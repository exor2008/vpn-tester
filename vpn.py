import argparse
import os
from functools import partial
from random import randint

from scapy.all import *
from scapy.contrib.wireguard import (
    Wireguard,
    WireguardInitiation,
    WireguardResponse,
    WireguardTransport,
)


def main():
    parser = argparse.ArgumentParser(
        description="A tool for sending and sniffing UDP Wireguard packets."
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Available commands"
    )

    # 'send' command
    send_parser = subparsers.add_parser(
        "send", help="Send data to a specified address and port."
    )
    send_parser.add_argument(
        "packet",
        choices=["hi", "hr", "t"],
        help="""Type of packet to send:
        hi - handshake initiation
        hr - handshake response
        t - transport packet
        """,
    )
    send_parser.add_argument(
        "--address", required=True, help="Target address to send data."
    )
    send_parser.add_argument(
        "--port", type=int, required=True, help="Target port to send data."
    )
    send_parser.add_argument(
        "--mangle-zeros",
        action="store_true",
        help="Mangle Wireguard header's reserved zeros",
    )
    send_parser.add_argument(
        "--type",
        type=int,
        default=None,
        help="Substitute the message type in the Wireguard header",
    )
    send_parser.add_argument(
        "--sport",
        type=int,
        default=None,
        help="Source port from which to send the data.",
    )
    send_parser.add_argument(
        "-n", type=int, default=1, help="Number of packets to send."
    )
    send_parser.add_argument(
        "-r",
        type=int,
        default=1,
        help="Number of repeatitions of the same packets to send.",
    )
    send_parser.add_argument("-x", action="store_true", help="Hexdump")
    send_parser.add_argument("-s", action="store_true", help="Show packet")
    send_parser.add_argument(
        "--inter", type=float, default=0, help="Interval between 2 packets"
    )
    send_parser.add_argument(
        "--expand", action="store_true", help="Add 4 random bytes after UDP header"
    )

    # 'sniff' command
    sniff_parser = subparsers.add_parser(
        "sniff", help="Sniff data from a specified address and port."
    )
    sniff_parser.add_argument(
        "--address", required=True, help="Address to sniff packets from."
    )
    sniff_parser.add_argument(
        "--port", type=int, required=True, help="Port to sniff packets from."
    )
    sniff_parser.add_argument("-x", action="store_true", help="Hexdump")
    sniff_parser.add_argument("-s", action="store_true", help="Show packet")
    sniff_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Timeout for receiving a packages",
    )
    sniff_parser.add_argument(
        "-n",
        type=int,
        default=0,
        help="Count of packets to receive",
    )

    # 'serve' command
    serve_parser = subparsers.add_parser(
        "serve",
        help="Wireguard connection simulator. Receives a handshake init and response with a handshake response.",
    )
    serve_parser.add_argument("--address", required=True, help="Address to serve.")
    serve_parser.add_argument("--port", type=int, required=True, help="Port to serve.")
    serve_parser.add_argument(
        "-t", action="store_true", help="Send transport packets after the handshake"
    )
    serve_parser.add_argument(
        "-n", type=int, default=1, help="Number of transport packets to send."
    )
    serve_parser.add_argument(
        "--inter", type=float, default=0, help="Interval between 2 transport packets"
    )
    serve_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Timeout for receiving a packages",
    )
    serve_parser.add_argument(
        "--mangle-zeros",
        action="store_true",
        help="Mangle Wireguard header's reserved zeros",
    )
    serve_parser.add_argument(
        "--type",
        type=int,
        default=None,
        help="Substitute the message type in the Wireguard header",
    )
    serve_parser.add_argument(
        "--expand", action="store_true", help="Add 4 random bytes after UDP header"
    )

    # 'client' command
    client_parser = subparsers.add_parser(
        "client",
        help="Wireguard connection simulator. Send a handshake init and wait for a handshake response.",
    )
    client_parser.add_argument("--address", required=True, help="Address to serve.")
    client_parser.add_argument("--port", type=int, required=True, help="Port to serve.")
    client_parser.add_argument(
        "--sport",
        type=int,
        default=None,
        help="Source port from which to send the data.",
    )
    client_parser.add_argument(
        "-t", action="store_true", help="Send transport packets after the handshake"
    )
    client_parser.add_argument(
        "-n", type=int, default=1, help="Number of transport packets to send."
    )
    client_parser.add_argument(
        "--inter", type=float, default=0, help="Interval between 2 transport packets"
    )
    client_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Timeout for receiving a packages",
    )
    client_parser.add_argument(
        "--mangle-zeros",
        action="store_true",
        help="Mangle Wireguard header's reserved zeros",
    )
    client_parser.add_argument(
        "--type",
        type=int,
        default=None,
        help="Substitute the message type in the Wireguard header",
    )
    client_parser.add_argument(
        "--expand", action="store_true", help="Add 4 random bytes after UDP header"
    )

    args = parser.parse_args()

    if args.command == "send":
        send_command(args)
    elif args.command == "sniff":
        sniff_command(args)
    elif args.command == "serve":
        serve_command(args)
    elif args.command == "client":
        client_command(args)


def wg_header(
    msg_type: Optional[int] = None,
    mangle_zeros: Optional[bytes] = None,
) -> Wireguard:
    if msg_type and not mangle_zeros:
        wg = Wireguard(message_type=msg_type)
    elif not msg_type and mangle_zeros:
        wg = Wireguard(reserved_zero=randint(8388608, 16777215))
    elif msg_type and mangle_zeros:
        wg = Wireguard(message_type=msg_type, reserved_zero=randint(8388608, 16777215))
    else:
        wg = Wireguard()

    return wg


def wg_init_handshake_packet(
    address: str,
    port: int,
    n: int,
    inter: float,
    msg_type: Optional[int] = None,
    mangle_zeros: Optional[bytes] = None,
    sport: Optional[int] = None,
    expand: bool = False,
) -> List[scapy.layers.l2.Ether]:
    timestamps = [tai64n(time.time() + i * inter) for i in range(n)]

    udp = UDP(dport=port, sport=sport) if sport else UDP(dport=port)

    wg = wg_header(msg_type=msg_type, mangle_zeros=mangle_zeros)

    header = os.urandom(4) / wg if expand else wg

    return [
        Ether()
        / IP(dst=address)
        / udp
        / header
        / fuzz(WireguardInitiation(encrypted_timestamp=timestamp))
        for timestamp in timestamps
    ]


def wg_response_handshake_packet(
    address: str,
    port: int,
    n: int,
    msg_type: Optional[int] = None,
    mangle_zeros: Optional[bytes] = None,
    sport: Optional[int] = None,
    expand: bool = False,
) -> List[scapy.layers.l2.Ether]:
    udp = UDP(dport=port, sport=sport) if sport else UDP(dport=port)

    wg = wg_header(msg_type=msg_type, mangle_zeros=mangle_zeros)

    header = os.urandom(4) / wg if expand else wg

    return [
        Ether() / IP(dst=address) / udp / header / fuzz(WireguardResponse())
        for _ in range(n)
    ]


def wg_transport_packet(
    address: str,
    port: int,
    n: int,
    msg_type: Optional[int] = None,
    mangle_zeros: Optional[bytes] = None,
    sport: Optional[int] = None,
    expand: bool = False,
) -> List[scapy.layers.l2.Ether]:
    udp = UDP(dport=port, sport=sport) if sport else UDP(dport=port)

    wg = wg_header(msg_type=msg_type, mangle_zeros=mangle_zeros)

    header = os.urandom(4) / wg if expand else wg

    return [
        Ether()
        / IP(dst=address)
        / udp
        / header
        / fuzz(
            WireguardTransport(
                counter=counter,
                encrypted_encapsulated_packet=os.urandom(randint(1, 50)),
            )
        )
        for counter in range(n)
    ]


def tai64n(timestamp: float) -> bytes:
    """TAI64N timestamp"""
    STRUCTURE = b">QI"
    OFFSET = (2**62) + 10
    seconds = int(timestamp)
    nanoseconds = int((timestamp - seconds) * 1000000000)
    seconds = seconds + OFFSET
    return struct.pack(STRUCTURE, seconds, nanoseconds)


def send_command(args: argparse.Namespace):
    if args.packet == "hi":
        wg_packets = wg_init_handshake_packet(
            args.address,
            args.port,
            args.n,
            args.inter,
            msg_type=args.type,
            mangle_zeros=args.mangle_zeros,
            sport=args.sport,
            expand=args.expand,
        )
    elif args.packet == "hr":
        wg_packets = wg_response_handshake_packet(
            args.address,
            args.port,
            args.n,
            msg_type=args.type,
            mangle_zeros=args.mangle_zeros,
            sport=args.sport,
            expand=args.expand,
        )
    elif args.packet == "t":
        wg_packets = wg_transport_packet(
            args.address,
            args.port,
            args.n,
            msg_type=args.type,
            mangle_zeros=args.mangle_zeros,
            sport=args.sport,
            expand=args.expand,
        )

    packets = sendp(
        wg_packets, count=args.r, verbose=2, return_packets=True, inter=args.inter
    )

    if packets:
        for packet in packets:
            if args.x:
                hexdump(packet)
                print()
            elif args.s:
                packet.show()
            else:
                print(packet.summary())


def handle_response(args: argparse.Namespace, packet):
    if args.x:
        hexdump(packet)
        print()
    elif args.s:
        packet.show()
    else:
        print(packet.summary())


def sniff_command(args: argparse.Namespace):
    callback = partial(handle_response, args)

    sniff(
        filter=f"udp and host {args.address} and port {args.port}",
        prn=callback,
        timeout=args.timeout,
        count=args.n,
    )


def serve_callback(args: argparse.Namespace, packet):
    print("Handshake received, sending response...")
    sendp(
        wg_response_handshake_packet(
            packet[IP].src,
            packet[UDP].sport,
            1,
            sport=args.port,
            msg_type=args.type,
            mangle_zeros=args.mangle_zeros,
            expand=args.expand,
        )
    )

    if args.t:
        sniffer = AsyncSniffer(
            filter=f"udp and host {args.address} and port {args.port}",
            timeout=args.timeout,
            # count=args.n,
        )

        sniffer.start()
        time.sleep(1)
        sendp(
            wg_transport_packet(
                packet[IP].src,
                packet[UDP].sport,
                args.n,
                sport=args.port,
            ),
            inter=args.inter,
            # return_packets=True,
        )  # .summary()
        # print()

        print(
            f"Exchanging transport packets with {packet[IP].src}:{packet[UDP].sport}..."
        )

        sniffer.join()

        n = 0
        if sniffer.results:
            n = len(list(filter(lambda p: p[UDP].dport == args.port, sniffer.results)))
        print(f"Received {n} transport packets")
        # sniffer.results.summary()


def serve_command(args: argparse.Namespace):
    print(f"Serving {args.address}:{args.port}")

    callback = partial(serve_callback, args)
    sniff(
        filter=f"udp and host {args.address} and port {args.port}",
        prn=callback,
        timeout=args.timeout,
        count=1,
    )


def client_callback(args: argparse.Namespace, my_packet, packet):
    print("Received a packet")
    if WireguardResponse in packet:
        print("Handshake response received")

    if args.t:
        sniffer = AsyncSniffer(
            filter=f"udp and host {my_packet[IP].src} and port {my_packet[UDP].sport}",
            timeout=args.timeout,
            # count=args.n,
        )

        sniffer.start()
        time.sleep(1)

        sendp(
            wg_transport_packet(
                args.address,
                args.port,
                args.n,
                sport=args.sport,
            ),
            inter=args.inter,
            # return_packets=True,
        )  # .summary()
        # print()

        print(
            f"Exchanging transport packets with {my_packet[IP].src}:{my_packet[UDP].dport}..."
        )
        sniffer.join()

        n = 0
        if sniffer.results:
            n = len(
                list(
                    filter(
                        lambda p: p[UDP].dport == my_packet[UDP].sport, sniffer.results
                    )
                )
            )
        print(f"Received {n} transport packets")
        # sniffer.results.summary()


def client_command(args: argparse.Namespace):
    print(f"Sending handshake init to {args.address}:{args.port}")
    packets = sendp(
        wg_init_handshake_packet(
            args.address,
            args.port,
            1,
            0,
            msg_type=args.type,
            mangle_zeros=args.mangle_zeros,
            sport=args.sport,
            expand=args.expand,
        ),
        return_packets=True,
    )
    assert packets
    [packet] = packets

    callback = partial(client_callback, args, packet)
    print(f"Waiting for handshake response on {packet[IP].src}:{packet[UDP].sport}...")
    sniff(
        filter=f"udp and host {packet[IP].src} and port {packet[UDP].sport}",
        prn=callback,
        timeout=args.timeout,
        count=1,
    )


if __name__ == "__main__":
    main()
