import argparse
import json
from abc import ABC, abstractmethod
from typing import List


from ip_packet_identifier.src.pcap_processor import process_file


from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import print_json


class Interface(ABC):
    """Abstract base class for CLI and GUI interfaces."""

    @abstractmethod
    def process_file(self, file_name: str) -> List[dict]:
        """Process a pcap file, extracting statistics.
        Arguments:
            file_name: The name of the pcap file to process.

        Returns:
            List of dictionaries, where each dictionary contains the statistics
        """
        pass

    @abstractmethod
    def display_stats(self, stats: List[dict]):
        """Display the statistics.
        Arguments:
            stats: List of dictionaries, where each dictionary contains the statistics
        """
        pass


class CLIInterface(Interface):
    """Command-line interface implementation."""

    def __init__(self):
        self.console = Console()

    def process_file(self, file_name: str) -> List[dict]:
        return process_file(file_name)

    def display_table(self, stats: List[dict]):
        table = Table(title="IP Packet Statistics")
        table.add_column("Packet #", justify="right", style="cyan")
        table.add_column("IP Version", style="magenta")
        table.add_column("Source Address", style="green")
        table.add_column("Destination Address", style="green")
        table.add_column("Protocol", style="yellow")
        table.add_column("Source Port", justify="right", style="blue")
        table.add_column("Destination Port", justify="right", style="blue")
        # table.add_column("Flags", style="red")
        table.add_column("ICMP Type", justify="right", style="red")
        table.add_column("ICMP Code", justify="right", style="red")

        for i, packet_stats in enumerate(stats):
            row = [
                str(i + 1),
                str(packet_stats["ip"]["ip_version"]),
                packet_stats["ip"]["source_address"],
                packet_stats["ip"]["destination_address"],
                str(packet_stats["ip"]["embedded_protocol"]),
                str(packet_stats.get("tcp", {}).get("source_port", "")),
                str(packet_stats.get("tcp", {}).get("destination_port", "")),
                # packet_stats.get("tcp", {}).get("flags", ""),
                packet_stats.get("icmp", {}).get("type", ""),
                packet_stats.get("icmp", {}).get("code", ""),
            ]
            table.add_row(*row)

        self.console.print(table)

    def display_json(self, stats: List[dict]):
        print_json(json.dumps(stats, indent=4))


    def display_stats(self, stats: List[dict]):
        # ask user if they want to display as table or json
        choice = Prompt.ask("Display as table or json?", choices=["t", "j"])
        if choice == "t":
            self.display_table(stats)
        else:
            self.display_json(stats)




class GUIInterface(Interface):
    """Graphical user interface implementation using tkinter."""

    def process_file(self, file_name: str) -> List[dict]:
        return process_file(file_name)

    def display_stats(self, stats: List[dict]):
        # TODO: Implement GUI display of statistics
        pass


def main():
    parser = argparse.ArgumentParser(description='Process a pcap file, extracting statistics.')
    parser.add_argument('file_name', type=str, help='The name of the pcap file to process.')
    parser.add_argument('--gui', action='store_true', help='Use graphical user interface.')
    parser.add_argument('--cli', action='store_true', help='Use command-line interface.')
    args = parser.parse_args()

    if args.gui:
        interface = GUIInterface()
    else:
        interface = CLIInterface()

    stats = interface.process_file(args.file_name)
    interface.display_stats(stats)

    # write to a file
    print("Writing to stats.json...")
    with open('stats.json', 'w') as outfile:
        json.dump(stats, outfile, indent=4)


if __name__ == '__main__':
    main()