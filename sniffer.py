import socket
import struct
import textwrap
import time

interfaceip = '192.168.1.8'
#interfaceip = str(input('Enter the IP to your interface'))

def main():
    print(logo)
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((interfaceip, 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        serial_number = 0

        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

            serial_number += 1

            print('\nPacket Information:')
            print(f'Serial Number: {serial_number}')
            print(f'Timestamp: {timestamp}')
            print(f'Protocol number: {(proto)}')
            print(f'Protocol name: {get_protocol(proto)}')
            print(f'Packet Length: {len(raw_data)} bytes')
            print(f'Destination MAC: {dest_mac}')
            print(f'Source MAC: {src_mac}')
            print(f'Destination Host: {target}')
            print(f'Source Host: {src}')
            print(f'Destination Port: {get_destination_port(data)}')
            print(f'Source Port: {get_source_port(data)}')

    except PermissionError as e:
        print(f"PermissionError: {e}. Run with admin bruh.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # promiscuous mode bye bye

#        if 'conn' in locals():
#            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
#            conn.close()
        if 'conn' in locals():
            try:
                conn.ioctl(socket.SIO_RCVALL, 0)
            except OSError as e:
                if e.winerror == 10022:  # [WinError 10022] An invalid argument was supplied WHAT DOES THIS EVEN MEAN WINDOWS
                    pass  # ignore this specific error 🫵😹
                else:
                    print(f"Error disabling promiscuous mode: {e}")
            conn.close()
def ethernet_frame(data):
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(eth_proto), data[14:]

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def get_protocol(proto):
    protocol_map = {
        0: 'HOPOPT',1: 'ICMP',2:'IGMP',3:'GGP',4:'IPv4',5:'ST',6:'TCP',7:'CBT',8:'EGP',9:'IGP',10:'BBN-RCC-MON',11:'NVP-II',12:'PUP',13:'ARGUS (deprecated)',14:'EMCON',15:'XNET',16:'CHAOS',17:'UDP',18:'MUX',19:'DCN-MEAS',20:'HMP',21:'PRM',22:'XNS-IDP',23:'TRUNK-1',24:'TRUNK-2',25:'LEAF-1',26:'LEAF-2',27:'RDP',28:'IRTP',29:'ISO-TP4',30:'NETBLT',31:'MFE-NSP',32:'MERIT-INP',33:'DCCP',34:'3PC',35:'IDPR',36:'XTP',37:'DDP',38:'IDPR-CMTP',39:'TP++',40:'IL',41:'IPv6',42:'SDRP',43:'IPv6-Route',44:'IPv6-Frag',45:'IDRP',46:'RSVP',47:'GRE',48:'DSR',49:'BNA',50:'ESP',51:'AH',52:'I-NLSP',53:'SWIPE (deprecated)',54:'NARP',55:'Min-IPv4',56:'TLSP',57:'SKIP',58:'IPv6-ICMP',59:'IPv6-NoNxt',60:'IPv6-Opts',61:'any host internal protocol',62:'CFTP',63:'any local network',64:'SAT-EXPAK',65:'KRYPTOLAN',66:'RVD',67:'IPPC',68:'any distributed file system',69:'SAT-MON',70:'VISA',71:'IPCV',72:'CPNX',73:'CPHB',74:'WSN',75:'PVP',76:'BR-SAT-MON',77:'SUN-ND',78:'WB-MON',79:'WB-EXPAK',80:'ISO-IP',81:'VMTP',82:'SECURE-VMTP',83:'VINES',84:'IPTM',85:'NSFNET-IGP',86:'DGP',87:'TCF',88:'EIGRP',89:'OSPFIGP',90:'Sprite-RPC',91:'LARP',92:'MTP',93:'AX.25',94:'IPIP',95:'MICP (deprecated)',96:'SCC-SP',97:'ETHERIP',98:'ENCAP',99:'any private encryption scheme',100:'GMTP',101:'IFMP',102:'PNNI',103:'PIM',104:'ARIS',105:'SCPS',106:'QNX',107:'A/N',108:'IPComp',109:'SNP',110:'Compaq-Peer',111:'IPX-in-IP',112:'VRRP',113:'PGM',114:'any 0-hop protocol',115:'L2TP',116:'DDX',117:'IATP',118:'STP',119:'SRP',120:'UTI',121:'SMP',122:'SM (deprecated)',123:'PTP',124:'ISIS over IPv4',125:'FIRE',126:'CRTP',127:'CRUDP',128:'SSCOPMCE',129:'IPLT',130:'SPS',131:'PIPE',132:'SCTP',133:'FC',134:'RSVP-E2E-IGNORE',135:'Mobility Header',136:'UDPLite',137:'MPLS-in-IP',138:'manet',139:'HIP',140:'Shim6',141:'WESP',142:'ROHC',143:'Ethernet',144:'AGGFRAG',145:'NSH',253:'Used for experimentation and testing',254:'Used for experimentation and testing',255:'Reserved',
    }
    return protocol_map.get(proto, str(proto))

'''
def get_ports(packet):
    source_port = packet.sport
    destination_port = packet.dport
    return source_port, destination_port

def get_source_port(packet):
    return get_ports(packet)[0]

def get_destination_port(packet):
    return get_ports(packet)[1]

'''
'''def get_source_port(proto, data):
    if proto == 6:  # TCP
        return struct.unpack('! H', data[:2])[0]
    elif proto == 17:  # UDP
        return struct.unpack('! H', data[:2])[0]
    else:
        return None

def get_destination_port(proto, data):
    if proto == 6:  # TCP
        return struct.unpack('! H', data[2:4])[0]
    elif proto == 17:  # UDP
        return struct.unpack('! H', data[2:4])[0]
    else:
        return None
if __name__ == "__main__":
    main()
'''

def get_source_port(data):
    if True:  # TCP
        return struct.unpack('! H', data[:2])[0]


def get_destination_port(data):
    if True:  # TCP
        return struct.unpack('! H', data[2:4])[0]

logo = r'''
                                @@@@@@                                     @%@@@@@@\n
                            +@@@@@@@@@@*                                 @@@@@@@@@@@@@@\n
                      :@@@@@@@@@@@@@@@@                                   %@@@@@@@@@@@@@@@@\n
                    @@@@@@@@@@@@@@@@@@       -%@@@@@*          -@@@@@@%    @@@@@@   @@@@@@@@\n
                  @@@@@@@@@@@ @@@@@@@.      @@@@@@@@@@       +@@@@@@@@@@   @@@@@@@    @@@@@@@\n
                @@@@@@@@@@   @@@@@@@%     @@@@@@@@@@@@@     @@@@@@@@@@@@   @@@@@@      @@@@@@@\n
              @@@@@@@@@+    @@@@@@@      @@@@@@@@@@@@@@    @@@@@@@@@@@@@   @@@@@@       @@@@@@@\n
            @@@@@@@@@        @@@@@      @@@@@@@@ @@@@@@   @@@@@@@ @@@@@@@  @@@@@@        @@@@@@@\n
          @@@@@@@@@                     @@@@@@+  @@@@@@  @@@@@@@  @@@@@@@  @@@@@@        @@@@@@@\n
        .@@@@@@@@.                     @@@@@@@   @@@@@@  @@@@@@   @@@@@@@  @@@@@@        @@@@@@@\n
       @@@@@@@@          @            @@@@@@@@  @@@@@@@ @@@@@@@@  @@@@@@   @@@@@@         @@@@@@\n
      @@@@@@@@      @@@@@@@@@@@@      @@@@@@@   @@@@@@@ @@@@@@@   @@@@@@   @@@@@@         @@@@@@@\n
     @@@@@@@.       @@@@@@@@@@@@@@    @@@@@@@  @@@@@@@  @@@@@@@  @@@@@@@   @@@@@@         @@@@@@\n
     @@@@@@         @@@@@@@@@@@@@@@@  @@@@@@% :@@@@@@   @@@@@@@  @@@@@@@   @@@@@@        @@@@@@@\n
    @@@@@@@@               @@@@@@@@*  @@@@@@+ @@@@@@@   @@@@@@@ @@@@@@@    @@@@@@      @@@@@@@@.\n
     @@@@@@@           @@@@@@@@@@@@    @@@@@@@@@@@@@@    @@@@@@@@@@@@@@    @@@@@@@@@@@@@@@@@@@@\n
     *@@@@@@@@@@@@@@@@@@@@@@@@@@@      @@@@@@@@@@@@      @@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@\n
       @@@@@@@@@@@@@@@@@@@@@@@          @@@@@@@@@*        @@@@@@@@@       @@@@@@@@@@@@@@@@\n
        @@@@@@@@@@@@@@@@@@-               -@@*               *@@-          @@@@@@@@@+\n
            -@@@@@@@                         *    @@@@@@@@@  @@@@@@@   :*  @@@@   @@@@@@@\n
                      @       @@@  @@@@@@@@@@@@@  @@@@@@@@@ @@@@@@@@  @@@@@@@@@@-@@@@@@@@@@:\n
         -@@@@@@@    @@@*     @@@% @@@@@@@@@@@@@ @@@@@      @@@@      @@@@@@@@%  @@@@+  @@@@@\n
       @@@@@@@@@@@% @@@@@@    @@@%      @@@@     @@@@@      @@@@      @@@-       @@@@    @@@@\n
       @@@@@-        @@@@@@@  @@@*      @@@@      @@@@@@@@@ @@@@@@@@@+@@@@@@@@@  @@@@@  @@@@@-\n
       @@@@@@@@@@@   @@@@@@@@@@@@%      @@@@      @@@@      @@@@     +@@@@@@@@@  @@@@@@@@@@\n
            @@@@@@@@ @@@@  @@@@@@@      @@@@      @@@@     @@@@@     %@@@@       @@@@@@@@\n
                  @@@ @@@@    @@@@@     %@@@      @@@@@    @@@@@     @@@@@       @@@@+@@@@@\n
     @@@@@@@@@@@@@@@@ @@@@   @@@@@ @@@@@@@@@@@@@@@ @@@     @@@@       @@@@@@@@@  @@@@  @@@@@\n
    @@@@@@@@@@@@@@%   @@@          %@@@@@@@@@@@%*                      @@@@@@@@  @@@    @@@@@@\n
                                                                                          @@@@@\n'''

if __name__ == "__main__":
    main()