import argparse
import json
from abc import ABC, abstractmethod
from typing import List


from ip_packet_identifier.src.pcap_processor import process_file



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

    def process_file(self, file_name: str) -> List[dict]:
        return process_file(file_name)

    def display_stats(self, stats: List[dict]):
        print(f"Processed {len(stats)} packets.")
        print(json.dumps(stats, indent=4))


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