import requests
from requests.auth import HTTPBasicAuth
import json
from scapy.layers.inet import IP
from scapy.all import *
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
import threading
from tkinter import messagebox

# API credentials and IP address to query
username = "w2CX25m6VwVzx1Wi"
password = "0O4nW44RZFgTgX6h"

# Function to query the API for threat information
def query_api(ip):
    response = requests.get(f'https://api.fraudguard.io/v2/ip/{ip}', verify=True, auth=HTTPBasicAuth(username, password))

    if response.status_code == 200:
        data = json.loads(response.text)
        risk_level = data.get("risk_level")
        threat = data.get("threat")

        return risk_level, threat
    else:
        print(f"Request failed with status code: {response.status_code}")
        return None, None

# Function to handle captured packets and check for consecutive safe packets
def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Query the API for threat information
        risk_level, threat = query_api(dst_ip)

        # Check if the threat value is available and convert it to an integer
        if threat is not None:
            risk_level = int(risk_level) if risk_level is not None else None
            # Check if the threat level is greater than 4
            if risk_level is not None and risk_level > 4:
                output_text.insert(tk.END, f"IP {dst_ip} is suspicious with Threat Level {threat}\n")
                reset_consecutive_safe_count()  # Reset the consecutive safe count
            else:
                threat = "No threat"  # Set threat to "No threat" if risk level <= 4
                output_text.insert(tk.END, f"IP {dst_ip} is safe. {threat}\n")
                increment_consecutive_safe_count()  # Increment the consecutive safe count

                if get_consecutive_safe_count() == 10:
                    send_alert("Your phone is safe !")

        # Print the risk level and threat
        output_text.insert(tk.END, f"Source IP: {src_ip}, Destination IP: {dst_ip}\n")
        output_text.insert(tk.END, f"Risk Level: {risk_level}\n")
        output_text.insert(tk.END, f"Threat: {threat}\n")
        output_text.insert(tk.END, "----------------\n")
        output_text.see(tk.END)  # Auto-scroll to the end

# Function to start packet sniffing
def start_sniffing():
    network_interface = selected_interface.get()
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

    def packet_handler_wrapper(packet):
        if not stop_sniffing_flag.is_set():
            packet_handler(packet)
        else:
            stop_sniffing()

    try:
        # Start packet sniffing in a separate thread
        sniff_thread = threading.Thread(target=lambda: sniff(iface="Wi-Fi", prn=packet_handler_wrapper))
        sniff_thread.daemon = True
        sniff_thread.start()
    except Exception as e:
        print(f"Error starting packet sniffing: {str(e)}")

# Function to stop packet sniffing
def stop_sniffing():
    stop_sniffing_flag.set()
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

# Function to reset the consecutive safe count
def reset_consecutive_safe_count():
    consecutive_safe_count.set(0)

# Function to increment the consecutive safe count
def increment_consecutive_safe_count():
    current_count = consecutive_safe_count.get()
    consecutive_safe_count.set(current_count + 1)

# Function to get the consecutive safe count
def get_consecutive_safe_count():
    return consecutive_safe_count.get()

# Function to send a pop-up alert
def send_alert(message):
    messagebox.showinfo("Alert", message)

# Create a GUI Window
window = tk.Tk()
window.title("Packet Sniffer GUI")
window.geometry("800x600")

# Labels with improved styling
label_interface = tk.Label(window, text="Suspecious IP detection:", font=("Helvetica", 14))
label_interface.pack()
label_output = tk.Label(window, text="Output:", font=("Helvetica", 14))
label_output.pack()

# Dropdown for network interface selection
network_interfaces = [iface[0] for iface in get_if_list()]
selected_interface = tk.StringVar(value=network_interfaces[0])
# interface_dropdown = ttk.Combobox(window, textvariable=selected_interface, values=network_interfaces, font=("Helvetica", 12))
# interface_dropdown.pack()

# Text widget for displaying output with improved styling
output_text = scrolledtext.ScrolledText(window, width=70, height=20, font=("Helvetica", 12))
output_text.pack()

# Start/Stop Buttons with improved styling
start_button = ttk.Button(window, text="Start Sniffing", command=start_sniffing, style="TButton")
start_button.pack()
stop_button = ttk.Button(window, text="Stop Sniffing", command=stop_sniffing, state=tk.DISABLED, style="TButton")
stop_button.pack()

# Initialize stop_sniffing_flag and consecutive_safe_count
stop_sniffing_flag = threading.Event()
consecutive_safe_count = tk.IntVar()

# Main Event Loop
window.mainloop()