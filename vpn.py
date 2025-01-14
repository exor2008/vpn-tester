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

    args = parser.parse_args()

    if args.command == "send":
        send_command(args)
    elif args.command == "sniff":
        handle_sniff(args)


def wg_init_handshake_packet(
    address: str, port: int, n: int, inter: float
) -> List[scapy.layers.l2.Ether]:
    timestamps = [tai64n(time.time() + i * inter) for i in range(n)]
    return [
        Ether()
        / IP(dst=address)
        / UDP(dport=port)
        / Wireguard()
        / fuzz(WireguardInitiation(encrypted_timestamp=timestamp))
        for timestamp in timestamps
    ]


def wg_response_handshake_packet(
    address: str, port: int, n: int
) -> List[scapy.layers.l2.Ether]:
    return [
        Ether()
        / IP(dst=address)
        / UDP(dport=port)
        / Wireguard()
        / fuzz(WireguardResponse())
        for _ in range(n)
    ]


def wg_transport_packet(address: str, port: int, n: int) -> List[scapy.layers.l2.Ether]:
    return [
        Ether()
        / IP(dst=address)
        / UDP(dport=port)
        / Wireguard()
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
    match args.packet:
        case "hi":
            wg_packets = wg_init_handshake_packet(
                args.address, args.port, args.n, args.inter
            )
        case "hr":
            wg_packets = wg_response_handshake_packet(args.address, args.port, args.n)
        case "t":
            wg_packets = wg_transport_packet(args.address, args.port, args.n)

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


def handle_sniff(args: argparse.Namespace):
    callback = partial(handle_response, args)

    sniff(
        filter=f"udp and host {args.address} and port {args.port}",
        prn=callback,
        timeout=args.timeout,
        count=args.n,
    )


if __name__ == "__main__":
    main()
