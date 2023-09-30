from ip_packet_identifier.src.Layer import Layer


class UDPPacket(Layer):
    """
    Represents a UDP packet.
    Inherits from IPPacket.
    """

    def __init__(self, packet):
        """
        Initializes a new instance of the UDPPacket class.
        :param packet: The UDP packet to parse.
        """
        super().__init__(packet)

    def get_udp_source_port(self):
        """
        Returns the source port number of the UDP packet.
        :return: The source port number.
        """
        return int(self.packet[0:2], 16)

    def get_udp_destination_port(self):
        """
        Returns the destination port number of the UDP packet.
        :return: The destination port number.
        """
        return int(self.packet[2:4], 16)
