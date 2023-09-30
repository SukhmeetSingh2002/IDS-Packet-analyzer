from ip_packet_identifier.src.Layer import Layer

class IPPacket(Layer):
    def __init__(self, packet):
        """Packet is a hex string."""
        super().__init__(packet)
    
    def identify_protocol(self):
        return int(self.packet[18:20], 16)
    
    def get_version(self):
        return self.packet[:1]
    
    def get_header_size(self):
        """Return header length in bytes."""
        return int(self.packet[1:2])*4
    
    def get_source_address(self):
        """Return source IP address.In decimal format.
        Example:
            >>> pkt = Packet(Ether(pkt_data), pkt_metadata)
            >>> ip_layer = IPPacket(pkt.get_layer_in_hex(pkt.get_ip_layer()))
            >>> ip_layer.get_source_address()
            '192.168.1.1'
        """
        ip = self.packet[24:32]
        return '.'.join(str(int(i, 16)) for i in [ip[:2], ip[2:4], ip[4:6], ip[6:8]])
    
    def get_destination_address(self):
        # return '.'.join(map(str, self.packet[16:20]))
        """Return destination IP address.In decimal format.
        Example:
            >>> pkt = Packet(Ether(pkt_data), pkt_metadata)
            >>> ip_layer = IPPacket(pkt.get_layer_in_hex(pkt.get_ip_layer()))
            >>> ip_layer.get_destination_address()
            '
        """
        ip = self.packet[32:40]
        return '.'.join(str(int(i, 16)) for i in [ip[:2], ip[2:4], ip[4:6], ip[6:8]])
    
    def get_flags(self):
        byte_containing_flags = self.packet[12:13]
        four_bits = bin(int(byte_containing_flags, 16))[2:].zfill(4)
        return four_bits[:3]

    def is_df_set(self):
        return bool(self.get_flags()[1] == '1')

    def is_mf_set(self):
        return bool(self.get_flags()[2] == '1')

    
    def get_ttl(self):
        return int(self.packet[16:18], 16)
    
