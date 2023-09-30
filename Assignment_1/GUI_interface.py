from tkinter import filedialog
from Interface import Interface

from scapy.utils import RawPcapReader
from typing import List
from ip_packet_identifier.src.pcap_processor import process_file

import customtkinter
import tkinter as tk
from tkinter import ttk


class GUIInterface(Interface):
    """Graphical user interface implementation using tkinter."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("IP Packet Identifier")
        self.file_name = None
        self.stats = None

        self.root.geometry("800x600")
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(3, weight=1)

        # Create widgets
        self.file_label = tk.Label(self.root, text="No file selected.")
        self.file_button = tk.Button(self.root, text="Select file", command=self.select_file)
        self.process_button = tk.Button(self.root, text="Process file", command=self.process_file)
        self.stats_tree = ttk.Treeview(self.root, columns=("Packet #", "IP Version", "Source Address", "Destination Address", "Protocol", "Source Port", "Destination Port", "Flags", "ICMP Type", "ICMP Code"))

        # Configure treeview columns
        self.stats_tree.heading("#0", text="Packet #")
        self.stats_tree.heading("#1", text="IP Version")
        self.stats_tree.heading("#2", text="Source Address")
        self.stats_tree.heading("#3", text="Destination Address")
        self.stats_tree.heading("#4", text="Protocol")
        self.stats_tree.heading("#5", text="Source Port")
        self.stats_tree.heading("#6", text="Destination Port")
        self.stats_tree.heading("#7", text="Flags")
        self.stats_tree.heading("#8", text="ICMP Type")
        self.stats_tree.heading("#9", text="ICMP Code")

        # Layout widgets
        self.file_label.pack()
        self.file_button.pack()
        self.process_button.pack()
        self.stats_tree.pack()

    def select_file(self):
        """Open a file dialog box to select a pcap file."""
        self.file_name = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap*"), ("All files", "*.*")])
        self.file_label.config(text=self.file_name)

    def my_process_file(self, file_name: str) -> List[dict]:
        print('Opening {}...'.format(file_name))
        all_packets = []

        for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
            stats = process_file(pkt_data, pkt_metadata)
            all_packets.append(stats)

        return all_packets

    def process_file(self, *args):
        """Process the selected pcap file and display the statistics."""
        if self.file_name is None:
            tk.messagebox.showerror("Error", "No file selected.")
            return

        stats = self.my_process_file(self.file_name)
        self.stats = stats
        self.display_stats(stats)

    def display_stats(self, stats: List[dict]):
        """Display the statistics in the GUI."""
        self.stats_tree.delete(*self.stats_tree.get_children())

        for i, packet_stats in enumerate(stats):
            row = [
                str(i + 1),
                packet_stats["ip"]["ip_version"],
                packet_stats["ip"]["source_address"],
                packet_stats["ip"]["destination_address"],
                packet_stats["ip"]["embedded_protocol"],
                packet_stats.get("tcp", {}).get("source_port", ""),
                packet_stats.get("tcp", {}).get("destination_port", ""),
                packet_stats.get("tcp", {}).get("flags", ""),
                packet_stats.get("icmp", {}).get("type", ""),
                packet_stats.get("icmp", {}).get("code", ""),
            ]
            self.stats_tree.insert("", "end", text=row[0], values=row[1:])

        # Resize columns to fit content
        for i in range(len(row)):
            self.stats_tree.column(i, width=tk.FIXED)
            self.stats_tree.heading(i, text=row[i])

    def run(self, *args):
        print("Running GUI interface...", args)
        self.root.mainloop()
        return self.stats


if __name__ == "__main__":
    gui = GUIInterface()
    gui.run()
    