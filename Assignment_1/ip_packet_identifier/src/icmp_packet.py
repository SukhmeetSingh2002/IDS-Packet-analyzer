from ip_packet_identifier.src.Layer import Layer

class ICMPPacket(Layer):
    def __init__(self, packet):
        super().__init__(packet)
    
    def get_icmp_type(self):
        """
        Returns the type of ICMP message (based on Type & Code field of ICMP header).
        """
        return self.packet[0:2]
    
    def get_icmp_code(self):
        """
        Returns the code of ICMP message (based on Type & Code field of ICMP header).
        """
        return self.packet[2:4]
    
    def type_of_icmp_message(self):
        """
        Returns the type of ICMP message (based on Type field of ICMP header).
        """
        _type = self.get_icmp_type()
        _code = self.get_icmp_code()
        if _type == '00':
            return 'Echo Reply'
        elif _type == '03':
            if _code == '00':
                return 'Destination Network Unreachable'
            elif _code == '01':
                return 'Destination Host Unreachable'
            elif _code == '02':
                return 'Destination Protocol Unreachable'
            elif _code == '03':
                return 'Destination Port Unreachable'
            elif _code == '04':
                return 'Fragmentation required, and DF flag set'
            elif _code == '05':
                return 'Source route failed'
            elif _code == '06':
                return 'Destination network unknown'
            elif _code == '07':
                return 'Destination host unknown'
            elif _code == '08':
                return 'Source host isolated'
            elif _code == '09':
                return 'Network administratively prohibited'
            elif _code == '10':
                return 'Host administratively prohibited'
            elif _code == '11':
                return 'Network unreachable for TOS'
            elif _code == '12':
                return 'Host unreachable for TOS'
            elif _code == '13':
                return 'Communication administratively prohibited'
            elif _code == '14':
                return 'Host Precedence Violation'
            elif _code == '15':
                return 'Precedence cutoff in effect'
        elif _type == '04':
            return 'Source Quench'
        elif _type == '05':
            if _code == '00':
                return 'Redirect Datagram for the Network'
            elif _code == '01':
                return 'Redirect Datagram for the Host'
            elif _code == '02':
                return 'Redirect Datagram for the TOS & Network'
            elif _code == '03':
                return 'Redirect Datagram for the TOS & Host'
        elif _type == '08':
            return 'Echo Request'
        elif _type == '09':
            return 'Router Advertisement'
        elif _type == '10':
            return 'Router Solicitation'
        elif _type == '11':
            return 'Time Exceeded for a Datagram'
        elif _type == '12':
            if _code == '00':
                return 'Pointer indicates the error'
            elif _code == '01':
                return 'Missing a Required Option'
            elif _code == '02':
                return 'Bad Length'
        elif _type == '13':
            if _code == '00':
                return 'Timestamp'
            elif _code == '01':
                return 'Timestamp Reply'
        elif _type == '14':
            if _code == '00':
                return 'Information Request'
            elif _code == '01':
                return 'Information Reply'
        else:
            return 'Unknown Type'
        