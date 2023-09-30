import argparse
import json
from typing import List

from scapy.utils import RawPcapReader

from GUI_interface import GUIInterface
from Interface import Interface

from ip_packet_identifier.src.pcap_processor import process_file

try:
    from rich.console import Console
    from rich.table import Table
    from rich.prompt import Prompt
    from rich import print_json
    from rich.progress import Progress
    RICH_INSTALLED = True
except ImportError:
    RICH_INSTALLED = False
    print("rich not installed. Install it with `pip install rich` to get a better experience.")
    print("Falling back to normal output.")
    print("=================================", end="\n\n")





class CLIInterface(Interface):
    """Command-line interface implementation."""

    def __init__(self, use_rich: bool = True):
        self.use_rich = use_rich
        if not use_rich:
            return
        self.console = Console()


    def ask_for_file(self) -> str:
        if not self.use_rich:
            return input("Enter the name of the pcap file to process: ")
        
        return Prompt.ask("Enter the name of the pcap file to process.")
    

    def process_file(self, file_name: str) -> List[dict]:

        if file_name is None:
            self.ask_for_file()

        print('Opening {}...'.format(file_name))
        all_packets = []
        
        if not self.use_rich:
            for i, (pkt_data, pkt_metadata,) in enumerate(RawPcapReader(file_name)):
                stats = process_file(pkt_data, pkt_metadata)
                all_packets.append(stats)
                print("Processed packet {}".format(i + 1), end="\r")
            return all_packets
        

        with self.console.status("[bold green]Processing file...", spinner="point") as status:
            for i, (pkt_data, pkt_metadata,) in enumerate(RawPcapReader(file_name)):
                stats = process_file(pkt_data, pkt_metadata)
                all_packets.append(stats)
                status.update(f"Processed packet {i + 1}")


        return all_packets


    def display_table(self, stats: List[dict]):
        table = Table(title="IP Packet Statistics")
        table.add_column("Packet #", justify="right", style="cyan")
        table.add_column("IP Version", style="magenta")
        table.add_column("Source Address", style="green")
        table.add_column("Destination Address", style="green")
        table.add_column("Protocol", style="yellow")
        table.add_column("Source Port", justify="right", style="blue")
        table.add_column("Destination Port", justify="right", style="blue")
        table.add_column("UAPRSF", style="red")
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
                packet_stats.get("tcp", {}).get("flags_binary", ""),
                packet_stats.get("icmp", {}).get("type", ""),
                packet_stats.get("icmp", {}).get("code", ""),
            ]
            table.add_row(*row)

        self.console.print(table)

    def display_json(self, stats: List[dict]):
        if not self.use_rich:
            print(json.dumps(stats, indent=4))
        else:
            self.console.print_json(json.dumps(stats, indent=4))


    def display_stats(self, stats: List[dict]):

        if not self.use_rich:
            self.display_json(stats)
            return
        

        # ask user if they want to display as table or json
        choice = Prompt.ask("Display as table or json or neither?", choices=["T", "J", "N"], default="T")
        if choice == "T":
            self.display_table(stats)
        elif choice == "J":
            self.display_json(stats)
        else:
            self.console.print("Not displaying anything.")





def main():
    parser = argparse.ArgumentParser(description='Process a pcap file, extracting statistics.')
    parser.add_argument('-f','--file_name', type=str, help='The name of the pcap file to process.')
    parser.add_argument('--gui', action='store_true', help='Use graphical user interface.')
    parser.add_argument('--cli', action='store_true', help='Use command-line interface.')
    parser.add_argument('--no-prettify', action='store_true', help='Do not prettify output.')
    parser.add_argument('-o','--output', type=str, help='Output file name.')
    args = parser.parse_args()

    OUTPUT_FILE_NAME = args.output if args.output else 'stats.json'

    if args.gui:
        interface = GUIInterface()
    else:
        interface = CLIInterface(use_rich=RICH_INSTALLED)

    if args.no_prettify and not args.gui:
        print("Not prettifying output.")
        interface.use_rich = False
        

    stats = interface.process_file(args.file_name)
    interface.display_stats(stats)

    # write to a file
    print(f"Writing to {OUTPUT_FILE_NAME}...")
    with open(OUTPUT_FILE_NAME, 'w') as outfile:
        json.dump(stats, outfile, indent=4)


if __name__ == '__main__':
    main()