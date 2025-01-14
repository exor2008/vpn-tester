import os
import struct
import time
from hashlib import blake2s

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import BLAKE2s, Hash
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dotenv import load_dotenv
from scapy.all import *
from scapy.contrib.wireguard import (
    Wireguard,
    WireguardInitiation,
    WireguardResponse,
    WireguardTransport,
)

load_dotenv()


def tai64n(timestamp: float) -> bytes:
    """TAI64N timestamp"""
    STRUCTURE = b">QI"
    OFFSET = (2**62) + 10
    seconds = int(timestamp)
    nanoseconds = int((timestamp - seconds) * 1000000000)
    seconds = seconds + OFFSET
    return struct.pack(STRUCTURE, seconds, nanoseconds)


def hash(input_data: bytes) -> bytes:
    """Hash using BLAKE2s."""
    digest = Hash(BLAKE2s(32))
    digest.update(input_data)
    return digest.finalize()


def mac(key: bytes, input_data: bytes) -> bytes:
    """Keyed MAC using BLAKE2s."""
    return blake2s(input_data, digest_size=16, key=key).digest()


def hmac_blake2s(key: bytes, input_data: bytes) -> bytes:
    """HMAC using BLAKE2s."""
    h = HMAC(key, BLAKE2s(32))
    h.update(input_data)
    return h.finalize()


def kdfn(key: bytes, input_data: bytes, n: int) -> List[bytes]:
    """
    Implements the KDF function to generate an n-tuple of 32-byte keys.
    """
    tau_0 = hmac_blake2s(key, input_data)

    # Generate τ1, τ2, ..., τn
    derived_keys = []
    prev_key = b""
    for i in range(1, n + 1):
        data = prev_key + i.to_bytes(1, "little")
        derived_key = hmac_blake2s(tau_0, data)
        derived_keys.append(derived_key)
        prev_key = derived_key

    return derived_keys


def aead(key: bytes, counter: int, plain_text: bytes, auth_text: bytes) -> bytes:
    """
    Encrypts the plain text using ChaCha20Poly1305 AEAD.
    """
    # Ensure the key is exactly 32 bytes
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes.")

    # Construct the nonce: 4 bytes of zeros + 8 bytes of the counter (little-endian)
    nonce = b"\x00" * 4 + counter.to_bytes(8, "little")

    # Initialize ChaCha20Poly1305 with the key
    chacha = ChaCha20Poly1305(key)

    # Encrypt the plaintext
    cipher_text = chacha.encrypt(nonce, plain_text, auth_text)
    return cipher_text


def dh(
    private_key: x25519.X25519PrivateKey, public_key: x25519.X25519PublicKey
) -> bytes:
    """Perform Curve25519 point multiplication."""
    return private_key.exchange(public_key)


if __name__ == "__main__":
    SERVER_IP = os.getenv("SERVER_IP")
    SERVER_PORT = int(os.getenv("SERVER_PORT") or "51820")
    CLIENT_PRIVATE_KEY = os.getenv("CLIENT_PRIVATE_KEY")
    assert CLIENT_PRIVATE_KEY
    PEER_PUBLIC_KEY = os.getenv("PEER_PUBLIC_KEY")
    assert PEER_PUBLIC_KEY

    CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".encode()
    IDENTEFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".encode()
    LABEL_MAC1 = "mac1----".encode()

    # Prepare keys
    # Client
    client_public_key_bytes = base64.b64decode(CLIENT_PRIVATE_KEY)
    client_private_key = x25519.X25519PrivateKey.from_private_bytes(
        client_public_key_bytes
    )
    client_public_key = client_private_key.public_key()

    # Peer
    peer_public_key_bytes = base64.b64decode(PEER_PUBLIC_KEY)
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)

    # Initial hashes
    c = hash(CONSTRUCTION)
    h = hash(c + IDENTEFIER)
    h = hash(h + peer_public_key_bytes)

    # Generate ephemeral key pair
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key_bytes = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    [c] = kdfn(c, ephemeral_public_key_bytes, 1)
    h = hash(h + ephemeral_public_key_bytes)

    c, k = kdfn(c, dh(ephemeral_private_key, peer_public_key), 2)

    encrypted_static = aead(k, 0, client_public_key_bytes, h)

    h = hash(h + encrypted_static)

    c, k = kdfn(c, dh(client_private_key, peer_public_key), 2)

    timestamp = aead(k, 0, tai64n(time.time()), h)
    encrypted_timestamp = tai64n(time.time())

    h = hash(h + timestamp)

    sender_index = os.urandom(4)  # 4-byte random sender index

    mac1 = mac(
        hash(LABEL_MAC1 + peer_public_key_bytes),
        sender_index
        + ephemeral_public_key_bytes
        + encrypted_static
        + encrypted_timestamp,
    )

    handshake_initiation = WireguardInitiation(
        sender_index=int.from_bytes(sender_index, "big"),
        unencrypted_ephemeral=ephemeral_public_key_bytes,
        encrypted_static=encrypted_static,
        encrypted_timestamp=encrypted_timestamp,
        mac1=mac1,
        mac2=b"\x00" * 16,
    )

    (initial,) = (
        Ether()
        / IP(dst=SERVER_IP)
        / UDP(dport=SERVER_PORT)
        / Wireguard()
        / handshake_initiation,
    )

    response = srp1(initial, timeout=5)
    hexdump(initial)

    if not response or not response.haslayer(WireguardResponse):
        print("Failed to receive handshake response!")
        exit(1)

    # exit(0)

    # # Step 2: Process the handshake response
    # wg_response = response[WireguardResponse]
    # receiver_index = wg_response.receiver_index
    # ephemeral_shared_secret = client_private_key.exchange(
    #     x25519.X25519PublicKey.from_public_bytes(wg_response.unencrypted_ephemeral)
    # )

    # # Derive session keys from the shared secret
    # session_key = derive_session_keys(ephemeral_shared_secret)

    # # Step 3: Send encrypted transport packets
    # for i in range(100):
    #     counter = os.urandom(12)  # 12-byte nonce
    #     plaintext = f"Packet {i}".encode("utf-8")
    #     encrypted_data = encrypt_payload(session_key, counter, plaintext)

    #     transport_packet = WireguardTransport(
    #         receiver_index=receiver_index,
    #         counter=i,
    #         encrypted_encapsulated_packet=encrypted_data,
    #     )
    #     send(Ether() / IP(dst=SERVER_IP) / UDP(dport=SERVER_PORT) / transport_packet)

    # print("Sent 100 encrypted packets!")

    # # Step 4: Listen for responses
    # def handle_response(packet):
    #     if packet.haslayer(WireguardTransport):
    #         transport = packet[WireguardTransport]
    #         decrypted_data = decrypt_payload(
    #             session_key,
    #             transport.counter.to_bytes(12, "big"),
    #             transport.encrypted_encapsulated_packet,
    #         )
    #         print(f"Received response: {decrypted_data}")

    # sniff(filter=f"udp and port {SERVER_PORT}", prn=handle_response, timeout=10)
