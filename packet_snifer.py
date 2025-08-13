import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import threading
import scapy.all as scapy

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        
        self.text_area = ScrolledText(root, width=80, height=20)
        self.text_area.pack(pady=10)
        
        self.start_btn = tk.Button(root, text="Start Sniffing", command=self.start_sniff)
        self.start_btn.pack(side=tk.LEFT, padx=10)
        
        self.stop_btn = tk.Button(root, text="Stop Sniffing", command=self.stop_sniff, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10)
        
        self.sniff_thread = None
        self.sniffing = False
        
    def packet_callback(self, packet):
        # Called for each captured packet
        self.text_area.insert(tk.END, packet.summary() + '\n')
        self.text_area.see(tk.END)
        
    def start_sniff(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.sniff_thread = threading.Thread(target=self.sniff_packets)
            self.sniff_thread.start()
    
    def sniff_packets(self):
        scapy.sniff(prn=self.packet_callback, stop_filter=lambda x: not self.sniffing)
        
    def stop_sniff(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
