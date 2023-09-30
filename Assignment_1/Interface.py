from abc import ABC, abstractmethod
from typing import List

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