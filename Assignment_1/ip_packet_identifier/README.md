# IP Packet Identifier

This project provides a Python implementation for identifying various attributes of an IP packet, including the embedded protocol (TCP, UDP, or ICMP), IP version number (IPv4 or IPv6), size of the IP header, source and destination IP addresses, Do Not Fragment (DF) and More Fragment (MF) bits, Time to Live (TTL) value, and various attributes specific to TCP, UDP, and ICMP protocols.

## File Structure

The project has the following file structure:

```
ip_packet_identifier
├── src
│   ├── __init__.py
│   ├── ip_packet.py
│   ├── tcp_packet.py
│   ├── udp_packet.py
│   └── icmp_packet.py
├── tests
│   ├── __init__.py
│   ├── test_ip_packet.py
│   ├── test_tcp_packet.py
│   ├── test_udp_packet.py
│   └── test_icmp_packet.py
├── README.md
└── requirements.txt
```

- `src/ip_packet.py`: This file exports a class `IPPacket` which provides methods for identifying various attributes of an IP packet.
- `src/tcp_packet.py`: This file exports a class `TCPPacket` which inherits from `IPPacket` and provides methods for identifying various attributes specific to TCP protocol.
- `src/udp_packet.py`: This file exports a class `UDPPacket` which inherits from `IPPacket` and provides methods for identifying various attributes specific to UDP protocol.
- `src/icmp_packet.py`: This file exports a class `ICMPPacket` which inherits from `IPPacket` and provides methods for identifying various attributes specific to ICMP protocol.
- `tests/test_ip_packet.py`: This file contains unit tests for the `IPPacket` class.
- `tests/test_tcp_packet.py`: This file contains unit tests for the `TCPPacket` class.
- `tests/test_udp_packet.py`: This file contains unit tests for the `UDPPacket` class.
- `tests/test_icmp_packet.py`: This file contains unit tests for the `ICMPPacket` class.
- `README.md`: This file contains the documentation for the project.
- `requirements.txt`: This file lists the dependencies required to run the project.

## Usage

To use the project, simply import the relevant classes from the `src` directory and create instances of the `IPPacket`, `TCPPacket`, `UDPPacket`, or `ICMPPacket` classes. Call the relevant methods on these instances to identify various attributes of the IP packet.

## Dependencies

The project has the following dependencies:

- Python 3.x
- pytest (for running unit tests)

To install the dependencies, run `pip install -r requirements.txt` in the project directory.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more information.