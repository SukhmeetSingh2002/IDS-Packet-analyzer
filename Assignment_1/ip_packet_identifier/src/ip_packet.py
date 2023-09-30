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
    
    def is_df_set(self):
        return bool(self.packet[20:21] == '1')
    
    def is_mf_set(self):
        return bool(self.packet[21:22] == '1')
    
    def get_ttl(self):
        return int(self.packet[22:24], 16)
    
    # def get_icmp_type(self):
    #     if self.identify_protocol() == 1:
    #         return self.packet[self.get_header_size():self.get_header_size()+2]
    
    # def get_tcp_source_port(self):
    #     if self.identify_protocol() == 6:
    #         return int.from_bytes(self.packet[self.get_header_size():self.get_header_size()+2], byteorder='big')
    
    # def get_tcp_destination_port(self):
    #     if self.identify_protocol() == 6:
    #         return int.from_bytes(self.packet[self.get_header_size()+2:self.get_header_size()+4], byteorder='big')
    
    # def get_tcp_header_length(self):
    #     if self.identify_protocol() == 6:
    #         return (self.packet[self.get_header_size()+12] >> 4) * 4
    
    # def get_tcp_flags(self):
    #     if self.identify_protocol() == 6:
    #         flags = {}
    #         tcp_header = self.packet[self.get_header_size():self.get_header_size()+self.get_tcp_header_length()]
    #         flags['URG'] = bool(tcp_header[13] & 32)
    #         flags['ACK'] = bool(tcp_header[13] & 16)
    #         flags['PSH'] = bool(tcp_header[13] & 8)
    #         flags['RST'] = bool(tcp_header[13] & 4)
    #         flags['SYN'] = bool(tcp_header[13] & 2)
    #         flags['FIN'] = bool(tcp_header[13] & 1)
    #         return flags
    
    # def get_udp_source_port(self):
    #     if self.identify_protocol() == 17:
    #         return int.from_bytes(self.packet[self.get_header_size():self.get_header_size()+2], byteorder='big')
    
    # def get_udp_destination_port(self):
    #     if self.identify_protocol() == 17:
    #         return int.from_bytes(self.packet[self.get_header_size()+2:self.get_header_size()+4], byteorder='big')