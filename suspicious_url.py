# # # # import json
# # # # import requests

# # # # url = 'https://urlhaus.abuse.ch/api/'
# # # # api_key = "c1ac788c593c9d0df35d"

# # # # # URL to fetch the JSON data
# # # # json_data_url = 'https://urlhaus.abuse.ch/downloads/json_recent/'

# # # # # Fetch the JSON data from the URL
# # # # response = requests.get(json_data_url)

# # # # if response.status_code == 200:
# # # #     # Parse the JSON response
# # # #     json_data = response.json()

# # # #     # Sort the JSON data by dateadded and select the top 20 enwtries
# # # #     sorted_data = sorted(json_data.items(), key=lambda x: x[1][0]['dateadded'], reverse=True)
# # # #     top_20_data = dict(sorted_data[:20])

# # # #     # Now, top_20_data contains the top 20 entries based on dateadded
# # # #     print(json.dumps(json_data,indent=2))  # Print the top 20 data in JSON format

# # # #     headers = {
# # # #         "Content-Type": "application/json",
# # # #     }
# # # #     r = requests.post(url, json=top_20_data, timeout=15, headers=headers)
# # # # else:
# # # #     print(f"Failed to fetch JSON data. Status code: {response.status_code}")

# import subprocess
# import requests
# import re
# import json
# from scapy.layers.inet import IP
# from scapy.all import *
# from requests.auth import HTTPBasicAuth
# import threading

# username = "w2CX25m6VwVzx1Wi"
# password = "0O4nW44RZFgTgX6h"

# # URLhaus API information
# urlhaus_url = 'https://urlhaus.abuse.ch/api/'
# api_key = "c1ac788c593c9d0df35d"

# # URL to fetch the JSON data
# json_data_url = 'https://urlhaus.abuse.ch/downloads/json_recent/'

# # Function to query the API for threat information
# def query_api(ip):
#     response = requests.get(f'https://api.fraudguard.io/v2/ip/{ip}', verify=True, auth=HTTPBasicAuth(username, password))

#     if response.status_code == 200:
#         data = json.loads(response.text)
#         risk_level = data.get("risk_level")
#         threat = data.get("threat")

#         return risk_level, threat
#     else:
#         print(f"Request failed with status code: {response.status_code}")
#         return None, None

# # Function to handle captured packets
# def packet_handler(packet):
#     if IP in packet:
#         src_ip = packet[IP].src
#         dst_ip = packet[IP].dst

#         # Query the API for threat information
#         risk_level, threat = query_api(dst_ip)

#         # Check if the threat value is available and convert it to an integer
#         if threat is not None:
#             risk_level = int(risk_level)
#             # Check if the threat level is greater than 4
#             if risk_level > 4:
#                 print(f"IP {dst_ip} is suspicious with Threat Level {threat}")

#         # Check if the URL in the packet matches any URLs from the API
#         urls_in_packet = re.findall(r'(http[s]?://\S+)', str(packet))
#         for url in urls_in_packet:
#             if url in top_20_data.values():
#                 print(f"WARNING: Downloaded URL '{url}' matches a known threat in the API!")
#                 # Raise an exception or handle the error as needed
#                 raise Exception(f"Error: Downloaded URL '{url}' matches a known threat in the API!")

# # Sniff network traffic on the specified interface (Ethernet 3) in a separate thread
# def packet_capture_thread():
#     sniff(iface=network_interface, prn=packet_handler)

# # Start the packet capture thread
# network_interface = "Ethernet 3"
# capture_thread = threading.Thread(target=packet_capture_thread)
# capture_thread.daemon = True  # Allow the thread to exit when the main program exits
# capture_thread.start()

# # Continue running your existing code to fetch and process API data
# # Fetch the JSON data from the URL
# response = requests.get(json_data_url)

# if response.status_code == 200:
#     # Parse the JSON response
#     json_data = response.json()

#     # Sort the JSON data by dateadded and select the top 20 entries
#     sorted_data = sorted(json_data.items(), key=lambda x: x[1][0]['dateadded'], reverse=True)
#     top_20_data = dict(sorted_data[:20])

#     # # Now, top_20_data contains the top 20 entries based on dateadded
#     print(json.dumps(json_data, indent=2))  # Print the top 20 data in JSON format


#     headers = {
#         "Content-Type": "application/json",
#     }
#     r = requests.post(json_data_url, json=top_20_data, timeout=15, headers=headers)
# else:
#     print(f"Failed to fetch JSON data. Status code: {response.status_code}")

# # Add any other code that you want to run continuously here








# extracting urls from http requests ##########################################

# import dpkt
# import re

# # Function to extract URLs from HTTP GET requests in the captured packets
# def extract_urls(packet):
#     if 'HTTP' in packet and packet['HTTP'].startswith(b'GET '):
#         # Extract the URL from the HTTP GET request
#         match = re.search(br'GET (http[s]?://[^\s]+)', packet['HTTP'])
#         if match:
#             return match.group(1).decode('utf-8')

#     return None

# # Load your predefined database of URLs into a list (you can load it from a file or another source)
# predefined_urls = [
#     'http://200.59.72.72:33642/bin.sh',
#     'http://77.85.155.40:28268/.i',
#     'http://42.235.182.200:52526/Mozi.m',
#     # Add more URLs as needed
# ]

# # Open the PCAP file (replace with your file path)
# with open(r'C:\Users\Aarsh  Trivedi\OneDrive\Desktop\git\malware detection in mobile apps\wireshark_url_files\check_url.pcap', 'rb') as file:
#     pcap = dpkt.pcap.Reader(file)

#     # Iterate through captured packets
#     for timestamp, packet_data in pcap:
#         eth = dpkt.ethernet.Ethernet(packet_data)

#         # Check if it's an IP packet
#         if isinstance(eth.data, dpkt.ip.IP):
#             ip = eth.data

#             # Check if it's an HTTP GET request
#             if isinstance(ip.data, dpkt.tcp.TCP) and ip.data.dport == 80:
#                 url = extract_urls(ip.data.data)
#                 if url:
#                     print(f"Extracted URL: {url}")

#                     # Check if the extracted URL is in the predefined database
#                     if url in predefined_urls:
#                         print("URL is in the predefined database.")
#                     else:
#                         print("URL is not in the predefined database.")








# extrcating urls from the https requests #################################       NON FUNCTIONAL CODE

# import dpkt
# import re
# import ssl
# import socket

# # Function to extract URLs from HTTP GET requests in the captured packets
# def extract_urls(packet):
#     if b'GET ' in packet:
#         # Extract the URL from the HTTP GET request
#         match = re.search(b'GET (http[s]?://[^\r\n]+)', packet)
#         if match:
#             return match.group(1).decode('utf-8')

#     return None

# # Load your predefined database of URLs into a list (you can load it from a file or another source)
# predefined_urls = [
#     'http://200.59.72.72:33642/bin.sh',
#     'http://77.85.155.40:28268/.i',
#     'http://42.235.182.200:52526/Mozi.m',
#     # Add more URLs as needed
# ]

# # Open the PCAP file (replace with your file path)
# with open(r'C:\Users\Aarsh  Trivedi\OneDrive\Desktop\git\malware detection in mobile apps\wireshark_url_files\check_url.pcap', 'rb') as file:
#     pcap = dpkt.pcap.Reader(file)

#     # Iterate through captured packets
#     for timestamp, packet_data in pcap:
#         eth = dpkt.ethernet.Ethernet(packet_data)

#         # Check if it's an IP packet
#         if isinstance(eth.data, dpkt.ip.IP):
#             ip = eth.data

#             # Check if it's a TCP packet on port 443 (HTTPS)
#             if isinstance(ip.data, dpkt.tcp.TCP) and ip.data.dport == 443:
#                 # Check if the packet contains SSL/TLS data
#                 if b'\x16\x03' in ip.data.data:
#                     try:
#                         # Create an SSLContext and wrap the socket
#                         context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
#                         context.verify_mode = ssl.CERT_NONE
                        
#                         # Extract the server hostname from the SSL data
#                         match = re.search(b'Server Name: ([^\x00]+)', ip.data.data)
#                         if match:
#                             server_hostname = match.group(1).decode('utf-8')
#                         else:
#                             server_hostname = None
                        
#                         ssl_sock = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
#                                                       server_hostname=server_hostname)
#                         ssl_sock.sendall(ip.data.data)
                        
#                         # Extract data from the decrypted SSL/TLS packet
#                         decrypted_data = ssl_sock.recv(4096)  # Adjust buffer size as needed
                        
#                         url = extract_urls(decrypted_data)
#                         if url:
#                             print(f"Extracted HTTPS URL: {url}")

#                             # Check if the extracted URL is in the predefined database
#                             if url in predefined_urls:
#                                 print("URL is in the predefined database.")
#                             else:
#                                 print("URL is not in the predefined database.")
#                     except ssl.SSLError:
#                         # Handle SSL decryption errors
#                         pass
