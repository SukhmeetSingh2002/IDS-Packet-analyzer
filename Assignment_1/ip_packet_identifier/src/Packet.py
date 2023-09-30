from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP


class Packet:
    def __init__(self, pkt_data, pkt_metadata):
        self.pkt_data = pkt_data
        self.pkt_metadata = pkt_metadata

    def get_layer_name(self, layer):
        return layer.name

    def get_layer_in_hex(self, layer):
        return layer.raw_packet_cache.hex()

    def get_next_layer(self, layer):
        return layer.payload

    def get_next_layer_fields(self, layer):
        return layer.payload.fields
