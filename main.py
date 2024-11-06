from scapy.all import sniff

# List to store packet details
packet_details = []

def packet_callback(packet):
    # Store each packet's details as a dictionary
    packet_info = {}

    # Ethernet Layer
    if packet.haslayer("Ethernet"):
        packet_info["MAC Source"] = packet.src
        packet_info["MAC Destination"] = packet.dst
        packet_info["Ether Type"] = packet["Ethernet"].type
    
    # IP Layer
    if packet.haslayer("IP"):
        packet_info["IP Source"] = packet["IP"].src
        packet_info["IP Destination"] = packet["IP"].dst
        packet_info["Protocol"] = packet["IP"].proto
        packet_info["TTL"] = packet["IP"].ttl
        packet_info["Flags"] = packet["IP"].flags
        packet_info["Fragment Offset"] = packet["IP"].frag
    
    # TCP Layer
    if packet.haslayer("TCP"):
        packet_info["TCP Source Port"] = packet["TCP"].sport
        packet_info["TCP Destination Port"] = packet["TCP"].dport
        packet_info["Sequence Number"] = packet["TCP"].seq
        packet_info["Acknowledgment Number"] = packet["TCP"].ack
        packet_info["TCP Flags"] = packet["TCP"].flags
        packet_info["Window Size"] = packet["TCP"].window
    
    # UDP Layer
    if packet.haslayer("UDP"):
        packet_info["UDP Source Port"] = packet["UDP"].sport
        packet_info["UDP Destination Port"] = packet["UDP"].dport
        packet_info["Length"] = packet["UDP"].len
    
    # ICMP Layer
    if packet.haslayer("ICMP"):
        packet_info["ICMP Type"] = packet["ICMP"].type
        packet_info["ICMP Code"] = packet["ICMP"].code
        packet_info["ICMP Checksum"] = packet["ICMP"].chksum
    
    # DNS Layer
    if packet.haslayer("DNS"):
        packet_info["DNS Query"] = packet["DNS"].qd.qname if packet["DNS"].qd else "N/A"
        packet_info["Query Type"] = packet["DNS"].qd.qtype if packet["DNS"].qd else "N/A"
        packet_info["Answer Count"] = packet["DNS"].ancount
    
    # ARP Layer
    if packet.haslayer("ARP"):
        packet_info["ARP Operation"] = packet["ARP"].op
        packet_info["ARP Sender IP"] = packet["ARP"].psrc
        packet_info["ARP Sender MAC"] = packet["ARP"].hwsrc
        packet_info["ARP Target IP"] = packet["ARP"].pdst
        packet_info["ARP Target MAC"] = packet["ARP"].hwdst
    
    # Add packet info to the list
    packet_details.append(packet_info)

# Function to write the captured packets to a file
def save_packets_to_file(filename="packet_details.txt"):
    with open(filename, "w") as file:
        for i, packet in enumerate(packet_details, start=1):
            file.write(f"Packet {i}:\n")
            for key, value in packet.items():
                file.write(f"    {key}: {value}\n")
            file.write("\n")
    print(f"Packet details saved to {filename}")

# Capture packets and call save function after capturing
sniff(prn=packet_callback, count=10)
save_packets_to_file()
