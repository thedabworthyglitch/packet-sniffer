import socket
import struct
import binascii
import time
from prettytable import PrettyTable

def parse_ethernet_header(data):
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac_address(dest_mac), format_mac_address(src_mac), socket.htons(eth_proto), data[14:]

def format_mac_address(mac):
    return ':'.join(map('{:02x}'.format, mac))

def parse_ip_header(data):
    version_ihl, dscp_ecn, total_length, identification, flags_fragment_offset, \
    time_to_live, protocol, header_checksum, source_ip, dest_ip = struct.unpack('! B B H H H B B H 4s 4s', data[:20])
    return (version_ihl >> 4, (version_ihl & 0xF) * 4, dscp_ecn, total_length, identification,
            flags_fragment_offset, time_to_live, protocol, header_checksum,
            socket.inet_ntoa(source_ip), socket.inet_ntoa(dest_ip), data[(version_ihl & 0xF) * 4:])

def parse_tcp_header(data):
    source_port, dest_port, sequence, acknowledgement, offset_reserved_flags, window_size, checksum, \
    urgent_pointer = struct.unpack('! H H L L H H H H', data[:20])
    data_offset = (offset_reserved_flags >> 12) * 4
    return source_port, dest_port, sequence, acknowledgement, data_offset, \
           offset_reserved_flags & 0x1FF, window_size, checksum, urgent_pointer, data[data_offset:]

def print_packet_info(table, serial, timestamp, protocol, dest_port, source_port, length, information):
    table.add_row([serial, timestamp, protocol, dest_port, source_port, length, information])

def packet_sniffer(interface, packet_count):
    table = PrettyTable(["Serial", "Time", "Protocol", "Inbound Port", "Outbound Port", "Length", "Information"])
    table.align = 'l'

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((interface, 0))

    try:
        serial = 1
        while packet_count > 0:
            raw_data, _ = s.recvfrom(65535)

            dest_mac, src_mac, eth_proto, eth_data = parse_ethernet_header(raw_data)

            if eth_proto == 8:  # IPv4
                version, header_length, dscp_ecn, total_length, identification, flags_fragment_offset, \
                time_to_live, protocol, header_checksum, source_ip, dest_ip, ip_data = parse_ip_header(eth_data)

                if protocol == 6:  # TCP
                    source_port, dest_port, sequence, acknowledgement, data_offset, \
                    flags, window_size, checksum, urgent_pointer, tcp_data = parse_tcp_header(ip_data)

                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    packet_length = len(raw_data)
                    information = binascii.hexlify(tcp_data).decode('utf-8')

                    #debugging why is this not working i hate my life
                    print("=" * 50)
                    print("Timestamp:", timestamp)
                    print("Protocol: TCP")
                    print("Dest Port:", dest_port)
                    print("Source Port:", source_port)
                    print("Packet Length:", packet_length)
                    print("Information:", information)
                    print("=" * 50)

                    print_packet_info(table, serial, timestamp, "TCP", dest_port, source_port, packet_length, information)
                    serial += 1
                    packet_count -= 1
    except KeyboardInterrupt:
        print("\nSniffing stopped by the user.")

    print(table)

if __name__ == "__main__":
    interface = socket.gethostbyname(socket.gethostname())  #default net interface instead of ip lol
    packet_count = 10

    packet_sniffer(interface, packet_count)
