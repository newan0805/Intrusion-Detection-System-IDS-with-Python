# Intrusion Detection System (IDS) with Python

This project is a simple Intrusion Detection System (IDS) written in Python, using the [Scapy](https://scapy.net/) library for packet sniffing and analysis. The IDS captures network packets, extracts detailed information from them, and saves the information to a file for further analysis.

## Features

- Captures Ethernet, IP, TCP, UDP, ICMP, DNS, and ARP packet information.
- Extracts key details from each packet, such as IP addresses, MAC addresses, ports, protocols, and more.
- Saves packet details to a text file (`packet_details.txt`) in a user-friendly format.

## Prerequisites

- Python 3.x installed on your machine.
- Scapy library installed (used for packet sniffing and analysis).

## Installation

1. **Clone the repository** (or download the files directly):

   ```bash
   git clone https://github.com/newan0805/Intrusion-Detection-System-IDS-with-Python
   cd Intrusion-Detection-System
   ```
2. **Install scapy** 
Run the following command to install Scapy:
```bash
pip install scapy
```

3. **Verify Scapy Installation:**
Ensure Scapy is installed correctly:
```bash
python -m pip show scapy
```

## Usage
1. Run the IDS:
To start capturing packets, run the main script:

```bash
python main.py
```
The script captures 10 packets by default and then saves the details to packet_details.txt.

2. Change Packet Count (Optional):
You can change the number of packets captured by modifying the count parameter in the sniff function in main.py:

```python
sniff(prn=packet_callback, count=10)
```

3. View Saved Packets:

After running the script, open the packet_details.txt file to see the captured packet information in a readable format.

## Output Example
Each packet is saved in packet_details.txt with details for Ethernet, IP, TCP, UDP, ICMP, DNS, and ARP layers, when available.

Example output:

``` yaml
Packet 1:
    MAC Source: 00:11:22:33:44:55
    MAC Destination: 66:77:88:99:aa:bb
    Ether Type: 2048
    IP Source: 192.168.1.2
    IP Destination: 192.168.1.3
    Protocol: 6
    TCP Source Port: 443
    TCP Destination Port: 12345
    Sequence Number: 123456789
    ...

Packet 2:
    MAC Source: ...
    MAC Destination: ...
    ...
```

## Troubleshooting
If you encounter ModuleNotFoundError: No module named 'scapy', ensure that Scapy is installed correctly and that your Python environment matches the one used to install Scapy.

## License
This project is licensed under the MIT License.


You can now copy and paste the markdown code above directly into your `README.md` file.
