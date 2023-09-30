from Interface import Interface

from scapy.utils import RawPcapReader
from typing import List
from ip_packet_identifier.src.pcap_processor import process_file


class GUIInterface(Interface):
    """Graphical user interface implementation using tkinter."""

    def process_file(self, file_name: str) -> List[dict]:
        print('Opening {}...'.format(file_name))
        all_packets = []

        for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
            stats = process_file(pkt_data, pkt_metadata)
            all_packets.append(stats)

        return all_packets
        

    def display_stats(self, stats: List[dict]):
        # TODO: Implement GUI display of statistics
        pass