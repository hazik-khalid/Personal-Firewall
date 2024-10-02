import socket
import struct

# Helper function to format MAC addresses
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

# Helper function to format IP addresses
def get_ip(addr):
    return '.'.join(map(str, addr))

# Function to parse Ethernet header
def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(prototype)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

# Function to parse IPv4 header
def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src_ip = get_ip(src)
    target_ip = get_ip(target)
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, src_ip, target_ip, data

# Function to parse TCP header
def tcp_head(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

# Function to parse UDP header
def udp_head(raw_data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', raw_data[:8])
    data = raw_data[8:]
    return src_port, dest_port, size, data

# Function to parse ICMP header
def icmp_head(raw_data):
    icmp_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
    data = raw_data[4:]
    return icmp_type, code, checksum, data

# Format multi-line data output
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Main function to capture and parse packets
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        eth = ethernet_head(raw_data)

        print('\nEthernet Frame:')
        print(f'Destination: {eth[0]}, Source: {eth[1]}, Protocol: {eth[2]}')

        if eth[2] == 8:  # IPv4
            ipv4 = ipv4_head(eth[3])
            print(f'\t - IPv4 Packet:')
            print(f'\t\t - Version: {ipv4[0]}, Header Length: {ipv4[1]}, TTL: {ipv4[2]}')
            print(f'\t\t - Protocol: {ipv4[3]}, Source: {ipv4[4]}, Target: {ipv4[5]}')

            # TCP
            if ipv4[3] == 6:
                tcp = tcp_head(ipv4[6])
                print(f'\t - TCP Segment:')
                print(f'\t\t - Source Port: {tcp[0]}, Destination Port: {tcp[1]}')
                print(f'\t\t - Sequence: {tcp[2]}, Acknowledgment: {tcp[3]}')
                print(f'\t\t - Flags:')
                print(f'\t\t\t - URG: {tcp[4]}, ACK: {tcp[5]}, PSH: {tcp[6]}')
                print(f'\t\t\t - RST: {tcp[7]}, SYN: {tcp[8]}, FIN: {tcp[9]}')
                print(f'\t\t - TCP Data:')
                print(format_multi_line('\t\t\t', tcp[10]))

            # UDP
            elif ipv4[3] == 17:
                udp = udp_head(ipv4[6])
                print(f'\t - UDP Segment:')
                print(f'\t\t - Source Port: {udp[0]}, Destination Port: {udp[1]}, Length: {udp[2]}')

            # ICMP
            elif ipv4[3] == 1:
                icmp = icmp_head(ipv4[6])
                print(f'\t - ICMP Packet:')
                print(f'\t\t - Type: {icmp[0]}, Code: {icmp[1]}, Checksum: {icmp[2]}')
                print(f'\t\t - ICMP Data:')
                print(format_multi_line('\t\t\t', icmp[3]))

if __name__ == "__main__":
    main()
