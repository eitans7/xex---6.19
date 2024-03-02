from scapy.all import *

START_PORT = 20
END_PORT = 1024
TIMEOUT = 0.5


def scan_port(ip, port, timeout=TIMEOUT):
    # Prepare the packet
    pkt = IP(dst=ip)/TCP(dport=port, flags='S')
    # Send the packet
    resp = sr1(pkt, timeout=timeout, verbose=0)
    # Check if response is valid and contains SYN+ACK
    if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x12:
        return True
    else:
        return False


def main():
    # Get the target IP address from user
    target_ip = input("Enter the target IP address: ")
    open_ports = []

    # Scan ports in the range betwwen the start and end ports
    for port in range(START_PORT, END_PORT+1):
        print(f"Scanning port {port}")
        if scan_port(target_ip, port):
            print(f"Port {port} is OPEN!. :)")
            open_ports.append(port)
        else:
            print(f"Port {port} ClOsEd. :(")

    # Print all open ports
    if open_ports:
        print("Open ports:", ", ".join(str(port) for port in open_ports))
    else:
        print("No open ports found.")


if __name__ == "__main__":
    main()
