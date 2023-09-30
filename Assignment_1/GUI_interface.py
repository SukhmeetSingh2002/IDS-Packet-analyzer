from tkinter import filedialog, messagebox
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
        self.heading_columns = ("Packet #", "IP Version", "Source Address", "Destination Address", "Protocol", "Source Port", "Destination Port", "Flags", "ICMP Type", "ICMP Code", "UDP Source Port", "UDP Destination Port")


        self.root.geometry("800x600")
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(3, weight=1)

        # Create widgets
        self.file_label = tk.Label(self.root, text="No file selected.")
        self.file_button = tk.Button(self.root, text="Select file", command=self.select_file)
        self.process_button = tk.Button(self.root, text="Process file", command=self.process_file)
        self.stats_tree = ttk.Treeview(self.root, columns=self.heading_columns)
        self.stats_scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.stats_tree.yview)
        # self.stats_tree.configure(yscrollcommand=self.stats_scrollbar.set)
        self.stats_hscrollbar = ttk.Scrollbar(self.root, orient="horizontal", command=self.stats_tree.xview)
        # self.stats_tree.configure(xscrollcommand=self.stats_hscrollbar.set)

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
        self.stats_tree.heading("#10", text="UDP Source Port")
        self.stats_tree.heading("#11", text="UDP Destination Port")
        
        # Configure treeview scrollbars
        self.stats_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.stats_hscrollbar.pack(side=tk.BOTTOM, fill=tk.X)

        self.stats_tree.configure(yscrollcommand=self.stats_scrollbar.set, xscrollcommand=self.stats_hscrollbar.set)
        # self.stats_scrollbar.configure(command=self.stats_tree.yview)
        # self.stats_hscrollbar.configure(command=self.stats_tree.xview)

        # Layout widgets
        self.file_label.pack()
        self.file_button.pack()
        self.process_button.pack()
        self.stats_tree.pack()
        self.stats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

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
            messagebox.showerror("Error", "No file selected.")
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
                packet_stats.get("tcp", {}).get("flags_binary", "")[2:],
                packet_stats.get("icmp", {}).get("type", ""),
                packet_stats.get("icmp", {}).get("code", ""),
                packet_stats.get("udp", {}).get("source_port", ""),
                packet_stats.get("udp", {}).get("destination_port", ""),
            ]
            self.stats_tree.insert("", "end", text=row[0], values=row[1:])

        # Resize columns to fit content
        for i in range(len(row)):
            self.stats_tree.column(i, width=100)
            # self.stats_tree.heading(i, text=self.heading_columns[i])

        # Allow sorting by column
        for i in range(len(row)):
            self.stats_tree.heading(i, command=lambda col=i: self.sortby(self.stats_tree, col, False))


    def sortby(self, tree, col, descending):
        """Sort tree contents when a column is clicked on."""
        data = [(tree.set(child, col), child) for child in tree.get_children('')]
        data.sort(reverse=descending)

        for i, item in enumerate(data):
            self.stats_tree.move(item[1], '', i)

        # Switch the heading so that it will sort in the opposite direction
        self.stats_tree.heading(col, command=lambda col=col: self.sortby(tree, col, not descending))


    def run(self, *args):
        print("Running GUI interface...", args)
        self.root.mainloop()
        return self.stats


if __name__ == "__main__":
    gui = GUIInterface()
    gui.run()
    