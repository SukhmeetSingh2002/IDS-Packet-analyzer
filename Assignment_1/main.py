from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP

import json


from ip_packet_identifier.src.Packet import Packet
from ip_packet_identifier.src.ip_packet import IPPacket
from ip_packet_identifier.src.udp_packet import UDPPacket
from ip_packet_identifier.src.tcp_packet import TCPPacket
from ip_packet_identifier.src.icmp_packet import ICMPPacket


filename = "packets.pcapng"


def process_file(file_name: str) -> list:
    """Process a pcap file, extracting statistics.
    Arguments:
        file_name: The name of the pcap file to process.

    Returns:
        List of dictionaries, where each dictionary contains the statistics
    """
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
                # stats['tcp']['sequence_number'] = embedded_protocol.get_tcp_sequence_number()
                # stats['tcp']['acknowledgement_number'] = embedded_protocol.get_tcp_acknowledgement_number()
                # stats['tcp']['data_offset'] = embedded_protocol.get_tcp_data_offset()
                # stats['tcp']['reserved'] = embedded_protocol.get_tcp_reserved()
                stats['tcp']['flags'] = embedded_protocol.get_tcp_flags_in_dict()
                # stats['tcp']['window'] = embedded_protocol.get_tcp_window()
                # stats['tcp']['checksum'] = embedded_protocol.get_tcp_checksum()
                # stats['tcp']['urgent_pointer'] = embedded_protocol.get_tcp_urgent_pointer()
                # stats['tcp']['options'] = embedded_protocol.get_tcp_options()
                # stats['tcp']['data'] = embedded_protocol.get_tcp_data()
            elif isinstance(embedded_protocol, UDPPacket):
                stats.setdefault('udp', {})
                stats['udp']['source_port'] = embedded_protocol.get_udp_source_port()
                stats['udp']['destination_port'] = embedded_protocol.get_udp_destination_port()
                # stats['udp']['length'] = embedded_protocol.get_udp_length()
                # stats['udp']['checksum'] = embedded_protocol.get_udp_checksum()
                # stats['udp']['data'] = embedded_protocol.get_udp_data()
            elif isinstance(embedded_protocol, ICMPPacket):
                stats.setdefault('icmp', {})
                stats['icmp']['type'] = embedded_protocol.get_icmp_type()
                stats['icmp']['code'] = embedded_protocol.get_icmp_code()
                stats['icmp']['type_of_icmp_message'] = embedded_protocol.type_of_icmp_message()
                # stats['icmp']['checksum'] = embedded_protocol.get_icmp_checksum()
                # stats['icmp']['data'] = embedded_protocol.get_icmp_data()
            else:
                pass
        else:
            pass

        all_packets.append(stats)

    return all_packets


if __name__ == '__main__':
    stats = process_file(filename)
    print(f"Processed {len(stats)} packets.")
    # print(json.dumps(stats, indent=4))

    # write to a file
    print("Writing to stats.json...")
    with open('stats.json', 'w') as outfile:
        json.dump(stats, outfile, indent=4)