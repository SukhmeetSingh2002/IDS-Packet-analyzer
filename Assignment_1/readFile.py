import argparse
import json
from abc import ABC, abstractmethod
from typing import List

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether

from ip_packet_identifier.src.Packet import Packet
from ip_packet_identifier.src.ip_packet import IPPacket
from ip_packet_identifier.src.udp_packet import UDPPacket
from ip_packet_identifier.src.tcp_packet import TCPPacket
from ip_packet_identifier.src.icmp_packet import ICMPPacket


class Interface(ABC):
    """Abstract base class for CLI and GUI interfaces."""

    @abstractmethod
    def process_file(self, file_name: str) -> List[dict]:
        """Process a pcap file, extracting statistics.
        Arguments:
            file_name: The name of the pcap file to process.

        Returns:
            List of dictionaries, where each dictionary contains the statistics
        """
        pass

    @abstractmethod
    def display_stats(self, stats: List[dict]):
        """Display the statistics.
        Arguments:
            stats: List of dictionaries, where each dictionary contains the statistics
        """
        pass


class CLIInterface(Interface):
    """Command-line interface implementation."""

    def process_file(self, file_name: str) -> List[dict]:
        print('Opening {}...'.format(file_name))
        all_packets = []

        for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
            stats = {}

            pkt = Packet(Ether(pkt_data), pkt_metadata)
            ip_layer_scapy = pkt.get_next_layer(pkt.pkt_data)
            ip_layer = pkt.get_layer_in_hex(ip_layer_scapy)

            ip_packet = IPPacket(ip_layer)
            embedded_protocol = ip_packet.identify_protocol()
            embedded_protocol_name = None
            if embedded_protocol == 1:
                embedded_protocol = ICMPPacket(
                    pkt.get_layer_in_hex(pkt.get_next_layer(ip_layer_scapy)))
                embedded_protocol_name = "icmp"
            elif embedded_protocol == 6:
                embedded_protocol = TCPPacket(
                    pkt.get_layer_in_hex(pkt.get_next_layer(ip_layer_scapy)))
                embedded_protocol_name = "tcp"
            elif embedded_protocol == 17:
                embedded_protocol = UDPPacket(
                    pkt.get_layer_in_hex(pkt.get_next_layer(ip_layer_scapy)))
                embedded_protocol_name = "udp"
            else:
                embedded_protocol = None

            # ip layer stats
            stats.setdefault('ip', {})
            stats['ip']['embedded_protocol'] = embedded_protocol_name
            stats['ip']['ip_version'] = ip_packet.get_version()
            stats['ip']['header_length'] = ip_packet.get_header_size()
            stats['ip']['source_address'] = ip_packet.get_source_address()
            stats['ip']['destination_address'] = ip_packet.get_destination_address()
            stats['ip']['is_df_set'] = ip_packet.is_df_set()
            stats['ip']['is_mf_set'] = ip_packet.is_mf_set()
            stats['ip']['ttl'] = ip_packet.get_ttl()

            # embedded protocol stats
            if embedded_protocol is not None:
                if isinstance(embedded_protocol, TCPPacket):
                    stats.setdefault('tcp', {})
                    stats['tcp']['source_port'] = embedded_protocol.get_tcp_source_port()
                    stats['tcp']['destination_port'] = embedded_protocol.get_tcp_destination_port()
                    stats['tcp']['flags'] = embedded_protocol.get_tcp_flags_in_dict()
                elif isinstance(embedded_protocol, UDPPacket):
                    stats.setdefault('udp', {})
                    stats['udp']['source_port'] = embedded_protocol.get_udp_source_port()
                    stats['udp']['destination_port'] = embedded_protocol.get_udp_destination_port()
                elif isinstance(embedded_protocol, ICMPPacket):
                    stats.setdefault('icmp', {})
                    stats['icmp']['type'] = embedded_protocol.get_icmp_type()
                    stats['icmp']['code'] = embedded_protocol.get_icmp_code()
                    stats['icmp']['type_of_icmp_message'] = embedded_protocol.type_of_icmp_message()
                else:
                    pass
            else:
                pass

            all_packets.append(stats)

        return all_packets

    def display_stats(self, stats: List[dict]):
        print(f"Processed {len(stats)} packets.")
        print(json.dumps(stats, indent=4))


class GUIInterface(Interface):
    """Graphical user interface implementation using tkinter."""

    def process_file(self, file_name: str) -> List[dict]:
        print('Opening {}...'.format(file_name))
        all_packets = []

        # TODO: Implement GUI processing of pcap file

        return all_packets

    def display_stats(self, stats: List[dict]):
        # TODO: Implement GUI display of statistics
        pass


def main():
    parser = argparse.ArgumentParser(description='Process a pcap file, extracting statistics.')
    parser.add_argument('file_name', type=str, help='The name of the pcap file to process.')
    parser.add_argument('--gui', action='store_true', help='Use graphical user interface.')
    parser.add_argument('--cli', action='store_true', help='Use command-line interface.')
    args = parser.parse_args()

    if args.gui:
        interface = GUIInterface()
    else:
        interface = CLIInterface()

    stats = interface.process_file(args.file_name)
    interface.display_stats(stats)

    # write to a file
    print("Writing to stats.json...")
    with open('stats.json', 'w') as outfile:
        json.dump(stats, outfile, indent=4)


if __name__ == '__main__':
    main()