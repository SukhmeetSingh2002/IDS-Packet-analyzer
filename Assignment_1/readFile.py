from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    count = 0
    interesting_packet_count = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1

        ether_pkt = Ether(pkt_data)
        print("Start")
        print("1 >> ", ether_pkt)
        print("2 >> ", ether_pkt.fields)
        print("3 >> ", ether_pkt.type)
        print("4 >> ", ether_pkt.dst)
        print("5 >> ", ether_pkt.src)
        print("6 >> ", ether_pkt.payload)
        print("7 >> ", ether_pkt.payload.raw_packet_cache)
        # print above bytes in hex
        print("7 >> ", ether_pkt.payload.raw_packet_cache.hex())
        print("7 >> ", ether_pkt.payload.raw_packet_cache_fields)
        print("\n7 >> ", ether_pkt.payload.fields)
        print("8 >> ", ether_pkt.payload.payload)
        print("9 >> ", ether_pkt.payload.payload.fields)
        print("10 >> ", ether_pkt.payload.payload.payload)
        print("11 >> ", ether_pkt.payload.payload.payload.fields)
        print("12 >> ", ether_pkt.payload.payload.payload.payload)
        print("13 >> ", ether_pkt.payload.payload.payload.payload.fields)
        print("14 >> ", ether_pkt.payload.payload.payload.payload.payload)
        # print layer of packet
        print("15 >> ", ether_pkt.getlayer(1))
        print()
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue

        interesting_packet_count += 1

    print('{} contains {} packets ({} interesting)'.
          format(file_name, count, interesting_packet_count))


process_pcap("test2.pcap")

# using oops concept for above code


class Packet:
    def __init__(self, pkt_data, pkt_metadata):
        self.pkt_data = pkt_data
        self.pkt_metadata = pkt_metadata

    def get_layer_name(self, layer):
        return layer.name

    def get_ip_layer(self):
        if 'type' not in self.pkt_data.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            return None

        if self.pkt_data.type != 0x0800:
            # disregard non-IPv4 packets
            return None

        ip_pkt = self.pkt_data[IP]
        return ip_pkt

    def get_icmp_layer(self):
        ip_pkt = self.get_ip_layer()
        if ip_pkt is None:
            return None

        if ip_pkt.proto != 1:
            # Ignore non-ICMP packet
            return None

        icmp_layer = ip_pkt[ICMP]
        return icmp_layer

    def get_transport_layer(self):
        ip_pkt = self.get_ip_layer()
        if ip_pkt is None:
            return None

        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            return None

        transport_layer = ip_pkt[TCP]
        return transport_layer

    def get_layer_in_hex(self, layer):
        return layer.raw_packet_cache.hex()

    def get_next_layer(self, layer):
        return layer.payload

    def get_next_layer_fields(self, layer):
        return layer.payload.fields


class Layer():
    def __init__(self, hex) -> None:
        self.hex = hex

    def get_layer(self):
        return self.hex
    


class IP_layer(Layer):
    def __init__(self, hex) -> None:
        super().__init__(hex)

    # def embedded_protocol(self):
    #     embedded_protocol = self.hex[18:20]
    #     if embedded_protocol == "06":
    #         return "TCP"
    #     elif embedded_protocol == "01":
    #         return "ICMP"
    #     elif embedded_protocol == "11":
    #         return "UDP"
    #     else:
    #         return embedded_protocol

    # def verion(self):
    #     return self.hex[:1]

    # def header_len(self):
    #     """Return header length in bytes.
    #     Example:
    #         >>> pkt = Packet(Ether(pkt_data), pkt_metadata)
    #         >>> ip_layer = IP_layer(pkt.get_layer_in_hex(pkt.get_ip_layer()))
    #         >>> ip_layer.header_len()
    #         20
    #     """
    #     return int(self.hex[1:2])*4

    # def src_ip(self):
    #     """Return source IP address.In decimal format.
    #     Example:
    #         >>> pkt = Packet(Ether(pkt_data), pkt_metadata)
    #         >>> ip_layer = IP_layer(pkt.get_layer_in_hex(pkt.get_ip_layer()))
    #         >>> ip_layer.src_ip()
    #         '192.168.1.1'
    #     """
    #     ip = self.hex[24:32]
    #     # convert hex to decimal
    #     return '.'.join(str(int(i, 16)) for i in [ip[:2], ip[2:4], ip[4:6], ip[6:8]])

    # def dst_ip(self):
    #     """
    #     Return destination IP address.In decimal format.
    #     Example:
    #         >>> pkt = Packet(Ether(pkt_data), pkt_metadata)
    #         >>> ip_layer = IP_layer(pkt.get_layer_in_hex(pkt.get_ip_layer()))
    #         >>> ip_layer.dst_ip()
    #         '8.8.8.8'
    #     """
    #     ip = self.hex[32:40]
    #     # convert hex to decimal
    #     return '.'.join(str(int(i, 16)) for i in [ip[:2], ip[2:4], ip[4:6], ip[6:8]])

    #  Determine if the Do Not Fragment(DF) and More Fragment(MF) bits are set or not
    # def check_flags(self, type):
    #     if type == "DF":
    #         return self.hex[20:21]
    #     elif type == "MF":
    #         return self.hex[21:22]
    #     else:
    #         return None

    # Time to Live (TTL)
    # def ttl(self):
    #     return self.hex[22:24]
    #     # return int(self.hex[22:24], 16)


class ICMP_layer(Layer):
    def __init__(self, hex) -> None:
        super().__init__(hex)


print("\n\n====================\n\n")

for (pkt_data, pkt_metadata,) in RawPcapReader("test2.pcap"):
    pkt = Packet(Ether(pkt_data), pkt_metadata)

    ip_layer = IP_layer(pkt.get_layer_in_hex(pkt.get_ip_layer()))
    icmp_layer = ICMP_layer(pkt.get_layer_in_hex(pkt.get_icmp_layer()))

    print(ip_layer.get_layer())
    print(ip_layer.embedded_protocol())
    print(ip_layer.verion())
    print(ip_layer.header_len())
    print(ip_layer.src_ip())
    print(ip_layer.dst_ip())
    print(ip_layer.check_flags("DF"))
    print(ip_layer.check_flags("MF"))
    print()
