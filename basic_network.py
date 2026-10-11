

from scapy.all import sniff, IP, TCP, UDP, ICMP

def analyze_packet(packet):
    if IP in packet:
        ip = packet[IP]

        print("\n--- Packet Captured ---")
        print("Source IP      :", ip.src)
        print("Destination IP :", ip.dst)
        print("Protocol       :", ip.proto)
        print("Packet Size    :", len(packet), "bytes")

        if TCP in packet:
            print("Type           : TCP")
            print("Source Port    :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif UDP in packet:
            print("Type           : UDP")
            print("Source Port    :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        elif ICMP in packet:
            print("Type           : ICMP")

print("Network Sniffer Started...")
print("Press Ctrl+C to stop.")

try:
    sniff(
        filter="ip",
        prn=analyze_packet,
        store=False,
        count=20
    )
except PermissionError:
    print("Please run with the required administrator/root permissions.")
except KeyboardInterrupt:
    print("Sniffer stopped.")
