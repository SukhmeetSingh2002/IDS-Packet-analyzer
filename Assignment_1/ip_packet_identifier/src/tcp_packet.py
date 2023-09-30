from ip_packet_identifier.src.Layer import Layer

class TCPPacket(Layer):
    def __init__(self, packet):
        super().__init__(packet)
    
    def get_tcp_source_port(self):
        return int(self.packet[0:4], 16)
    
    def get_tcp_destination_port(self):
        return int(self.packet[4:8], 16)
    
    def get_tcp_sequence_number(self):
        return int(self.packet[8:16], 16)
    
    def get_tcp_acknowledgment_number(self):
        return int(self.packet[16:24], 16)
    
    def get_tcp_header_length(self):
        return int(self.packet[24:25], 16)
    
    def get_tcp_reserved(self):
        return int(self.packet[25:26], 16)
    
    def get_tcp_flags(self):
        return int(self.packet[26:28], 16)
    
    def get_tcp_window(self):
        return int(self.packet[28:32], 16)
    
    def get_tcp_checksum(self):
        return int(self.packet[32:36], 16)
    
    def get_tcp_urgent_pointer(self):
        return int(self.packet[36:40], 16)
    
    def get_tcp_options(self):
        return self.packet[40:]
    
    def get_tcp_flags_in_binary(self):
        return bin(int(self.packet[26:28], 16))[2:].zfill(8)
    
    def get_tcp_flags_in_hex(self):
        return self.packet[26:28]
    
    def get_tcp_flags_in_decimal(self):
        return int(self.packet[26:28], 16)
    
    def get_tcp_flags_in_dict(self):
        flags = self.get_tcp_flags_in_binary()
        
        flags_dict = {
            'URG': bool(int(flags[2])),
            'ACK': bool(int(flags[3])),
            'PSH': bool(int(flags[4])),
            'RST': bool(int(flags[5])),
            'SYN': bool(int(flags[6])),
            'FIN': bool(int(flags[7])),
        }

        return flags_dict
        
