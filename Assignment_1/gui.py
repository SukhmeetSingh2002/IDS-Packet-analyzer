import customtkinter

class MyCheckboxFrame(customtkinter.CTkScrollableFrame):
    def __init__(self, master, title, values):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        self.values = values
        self.title = title
        self.checkboxes = []

        self.title = customtkinter.CTkLabel(self, text=self.title, fg_color="gray30", corner_radius=6)
        self.title.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="ew")

        for i, value in enumerate(self.values):
            checkbox = customtkinter.CTkCheckBox(self, text=value)
            checkbox.grid(row=i+1, column=0, padx=10, pady=(10, 0), sticky="w")
            self.checkboxes.append(checkbox)

    def get(self):
        checked_checkboxes = []
        for checkbox in self.checkboxes:
            if checkbox.get() == 1:
                checked_checkboxes.append(checkbox.cget("text"))
        return checked_checkboxes

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("my app")
        self.geometry("400x180")
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.checkbox_frame_1 = MyCheckboxFrame(self, values=["value 1", "value 2", "value 3"],title='asfd')
        self.checkbox_frame_1.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="nsew")
        self.checkbox_frame_2 = MyCheckboxFrame(self, values=["option 1", "option 2"],title='asfd')
        self.checkbox_frame_2.grid(row=0, column=1, padx=(0, 10), pady=(10, 0), sticky="nsew")

        self.button = customtkinter.CTkButton(self, text="my button", command=self.button_callback)
        self.button.grid(row=3, column=0, padx=10, pady=10, sticky="ew", columnspan=2)

    def button_callback(self):
        print("checkbox_frame_1:", self.checkbox_frame_1.get())
        print("checkbox_frame_2:", self.checkbox_frame_2.get())

app = App()
app.mainloop()

# gui code

import tkinter as tk
from ip_packet_identifier.src.ip_packet import IPPacket

class IPInfoUI:
    def __init__(self, master):
        self.master = master
        master.title("IP Packet Information")
        
        # Create the UI elements
        self.packet_data_label = tk.Label(master, text="Packet Data:")
        self.packet_data_entry = tk.Entry(master, width=50)
        self.packet_data_entry.focus()
        self.packet_data_entry.bind('<Return>', self.show_packet_info)
        
        self.protocol_label = tk.Label(master, text="Protocol:")
        self.protocol_value = tk.Label(master, text="")
        
        self.version_label = tk.Label(master, text="Version:")
        self.version_value = tk.Label(master, text="")
        
        self.header_size_label = tk.Label(master, text="Header Size:")
        self.header_size_value = tk.Label(master, text="")
        
        self.source_address_label = tk.Label(master, text="Source Address:")
        self.source_address_value = tk.Label(master, text="")
        
        self.destination_address_label = tk.Label(master, text="Destination Address:")
        self.destination_address_value = tk.Label(master, text="")
        
        self.df_label = tk.Label(master, text="DF:")
        self.df_value = tk.Label(master, text="")
        
        self.mf_label = tk.Label(master, text="MF:")
        self.mf_value = tk.Label(master, text="")
        
        self.ttl_label = tk.Label(master, text="TTL:")
        self.ttl_value = tk.Label(master, text="")
        
        self.icmp_type_label = tk.Label(master, text="ICMP Type:")
        self.icmp_type_value = tk.Label(master, text="")
        
        self.tcp_source_port_label = tk.Label(master, text="TCP Source Port:")
        self.tcp_source_port_value = tk.Label(master, text="")
        
        self.tcp_destination_port_label = tk.Label(master, text="TCP Destination Port:")
        self.tcp_destination_port_value = tk.Label(master, text="")
        
        # Layout the UI elements
        self.packet_data_label.grid(row=0, column=0, sticky="w")
        self.packet_data_entry.grid(row=0, column=1, columnspan=2, sticky="we")
        
        self.protocol_label.grid(row=1, column=0, sticky="w")
        self.protocol_value.grid(row=1, column=1, sticky="w")
        
        self.version_label.grid(row=2, column=0, sticky="w")
        self.version_value.grid(row=2, column=1, sticky="w")
        
        self.header_size_label.grid(row=3, column=0, sticky="w")
        self.header_size_value.grid(row=3, column=1, sticky="w")
        
        self.source_address_label.grid(row=4, column=0, sticky="w")
        self.source_address_value.grid(row=4, column=1, sticky="w")
        
        self.destination_address_label.grid(row=5, column=0, sticky="w")
        self.destination_address_value.grid(row=5, column=1, sticky="w")
        
        self.df_label.grid(row=6, column=0, sticky="w")
        self.df_value.grid(row=6, column=1, sticky="w")
        
        self.mf_label.grid(row=7, column=0, sticky="w")
        self.mf_value.grid(row=7, column=1, sticky="w")
        
        self.ttl_label.grid(row=8, column=0, sticky="w")
        self.ttl_value.grid(row=8, column=1, sticky="w")
        
        self.icmp_type_label.grid(row=9, column=0, sticky="w")
        self.icmp_type_value.grid(row=9, column=1, sticky="w")
        
        self.tcp_source_port_label.grid(row=10, column=0, sticky="w")
        self.tcp_source_port_value.grid(row=10, column=1, sticky="w")
        
        self.tcp_destination_port_label.grid(row=11, column=0, sticky="w")
        self.tcp_destination_port_value.grid(row=11, column=1, sticky="w")
        
    def show_packet_info(self, event):
        # Get the packet data from the entry field
        packet_data = bytes.fromhex(self.packet_data_entry.get())
        
        # Create an instance of the IPPacket class
        ip_pkt = IPPacket(packet_data)
        
        # Update the UI elements with the packet information
        self.protocol_value.config(text=ip_pkt.identify_protocol())
        self.version_value.config(text=ip_pkt.get_version())
        self.header_size_value.config(text=ip_pkt.get_header_size())
        self.source_address_value.config(text=ip_pkt.get_source_address())
        self.destination_address_value.config(text=ip_pkt.get_destination_address())
        self.df_value.config(text=ip_pkt.is_df_set())
        self.mf_value.config(text=ip_pkt.is_mf_set())
        self.ttl_value.config(text=ip_pkt.get_ttl())
        self.icmp_type_value.config(text=ip_pkt.get_icmp_type())
        self.tcp_source_port_value.config(text=ip_pkt.get_tcp_source_port())
        self.tcp_destination_port_value.config(text=ip_pkt.get_tcp_destination_port())

# Create the main window
root = tk.Tk()

# Create an instance of the IPInfoUI class
ip_info_ui = IPInfoUI(root)

# Run the main event loop
root.mainloop()