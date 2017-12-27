import os
from contextlib import contextmanager
from var import VAR


@contextmanager
def redirect_stderr(new_target):

    import sys
    old_target, sys.stderr = sys.stderr, new_target
    try:
        yield new_target
    finally:
        sys.stderr = old_target


with open(os.devnull, 'w') as errf:
    with redirect_stderr(errf):
        from scapy.all import *

#dictionary :protocal number->name
dict_pro = {0: 'HOPOPT', 1: 'ICMP', 2: 'IGMP', 3: 'GGP', 4: 'IP-in-IP', 5: 'ST', 6: 'TCP', 7: 'CBT', 8: 'EGP', 9: 'IGP', 10: 'BBN-RCC-MON', 11: 'NVP-II', 12: 'PUP', 13: 'ARGUS', 14: 'EMCON', 15: 'XNET', 16: 'CHAOS', 17: 'UDP', 18: 'MUX', 19: 'DCN-MEAS', 20: 'HMP', 21: 'PRM', 22: 'XNS-IDP', 23: 'TRUNK-1', 24: 'TRUNK-2', 25: 'LEAF-1', 26: 'LEAF-2', 27: 'RDP', 28: 'IRTP', 29: 'ISO-TP4', 30: 'NETBLT', 31: 'MFE-NSP', 32: 'MERIT-INP', 33: 'DCCP', 34: '3PC', 35: 'IDPR', 36: 'XTP', 37: 'DDP', 38: 'IDPR-CMTP', 39: 'TP++', 40: 'IL', 41: 'IPv6', 42: 'SDRP', 43: 'IPv6-Route', 44: 'IPv6-Frag', 45: 'IDRP', 46: 'RSVP', 47: 'GREs', 48: 'DSR', 49: 'BNA', 50: 'ESP', 51: 'AH', 52: 'I-NLSP', 53: 'SWIPE', 54: 'NARP', 55: 'MOBILE', 56: 'TLSP', 57: 'SKIP', 58: 'IPv6-ICMP', 59: 'IPv6-NoNxt', 60: 'IPv6-Opts', 62: 'CFTP', 64: 'SAT-EXPAK', 65: 'KRYPTOLAN', 66: 'RVD', 67: 'IPPC', 69: 'SAT-MON', 70: 'VISA', 71: 'IPCU', 72: 'CPNX', 73: 'CPHB',
            74: 'WSN', 75: 'PVP', 76: 'BR-SAT-MON', 77: 'SUN-ND', 78: 'WB-MON', 79: 'WB-EXPAK', 80: 'ISO-IP', 81: 'VMTP', 82: 'SECURE-VMTP', 83: 'VINES', 84: 'IPTM', 85: 'NSFNET-IGP', 86: 'DGP', 87: 'TCF', 88: 'EIGRP', 89: 'OSPF', 90: 'Sprite-RPC', 91: 'LARP', 92: 'MTP', 93: 'AX.25', 94: 'OS', 95: 'MICP', 96: 'SCC-SP', 97: 'ETHERIP', 98: 'ENCAP', 100: 'GMTP', 101: 'IFMP', 102: 'PNNI', 103: 'PIM', 104: 'ARIS', 105: 'SCPS', 106: 'QNX', 107: 'A/N', 108: 'IPComp', 109: 'SNP', 110: 'Compaq-Peer', 111: 'IPX-in-IP', 112: 'VRRP', 113: 'PGM', 115: 'L2TP', 116: 'DDX', 117: 'IATP', 118: 'STP', 119: 'SRP', 120: 'UTI', 121: 'SMP', 122: 'SM', 123: 'PTP', 124: 'IS-IS over IPv4', 125: 'FIRE', 126: 'CRTP', 127: 'CRUDP', 128: 'SSCOPMCE', 129: 'IPLT', 130: 'SPS', 131: 'PIPE', 132: 'SCTP', 133: 'FC', 134: 'RSVP-E2E-IGNORE', 135: 'Mobility Header', 136: 'UDPLite', 137: 'MPLS-in-IP', 138: 'manet', 139: 'HIP', 140: 'Shim6', 141: 'WESP', 142: 'ROHC'}

igmptypes = { 17 : "Group Membership Query",
              18 : "Version 1 - Membership Report",
              22 : "Version 2 - Membership Report",
              23 : "Leave Group"}
arpoptypes = {1:"who-has", 2:"is-at", 3:"RARP-req", 4:"RARP-rep", 5:"Dyn-RARP-req", 6:"Dyn-RAR-rep", 7:"Dyn-RARP-err", 8:"InARP-req", 9:"InARP-rep"}
class Packet_r():
    """Class for loading packet and further modifications.

    """

    def __init__(self, packet):
        """Add some new attributes to the packet.

        Args:
            packet: original scapy Packet Class
        """

        self.packet = packet
        self.tcp_order = True  # default every packer is in order
        try:
            self.ipsrc=packet[IP].src
            self.ipdst=packet[IP].dst
        except:
            pass
        try:
            self.sp=str(packet[TCP].sport)
            self.dp=str(packet[TCP].dport)
        except:
            pass
        try:
            self.sp=str(packet[UDP].sport)
            self.dp=str(packet[UDP].dport)
        except:
            pass
        self.pro=''
    def expand(self):
        """Expand get all payload.

        Yields:
        layername and fields.
        """

        x = self.packet
        yield x.name, x.fields
        while x.payload:
            x = x.payload
            yield x.name, x.fields

    def packet_to_layerlist(self):
        """Layerlist get formatted list contain every layer's detail

        Returns:
        list of packet information,like[(layername,{label1:content1,label2:conten2}),...]
        """
        return list(self.expand())

    def packet_to_all(self):
        """Combine every layer parsed in to a string for further searching.

        Returns:
        string of packet information frome layerlist.
        """

        s = ''
        for i in self.packet_to_layerlist():
            s = s + i[0] + ":\n"
            for key in i[1]:
                s = s + "\t%s: %s\n" % (key, i[1][key])
            s = s + '\n'
        try:
            s = s + packet.load + '\n'
        except:
            s = s + '\n'
        return s

    def packet_to_load_plain(self):
        """Convert every packet(including headers) to hex.

        Returns:
        string of packet's hex information.
        """
        try:
            return (bytes(self.packet).hex())
        except:
            return ("packet cannot be converted to hex")

    def packet_to_info(self):
        """Return every packet's brief information for QTableWidget

        Returns:
            list like [packet num, time, src ,dst, len, pro]
        list of packet information
        """

        try:
            pkt_src = self.packet.srcsummary()
            pkt_dst = self.packet.dstsummary()

        except:
            pkt_src = self.packet.src
            pkt_dst = self.packet.dst

            if (self.packet.getlayer(IP)):

                pkt_src = self.packet[IP].src
                pkt_dst = self.packet[IP].dst
            elif (self.packet.getlayer(IPv6)):

                pkt_src = self.packet[IPv6].src
                pkt_dst = self.packet[IPv6].dst
        try:
            if (self.packet.getlayer(IP)):
                pkt_pro = dict_pro[int(self.packet[IP].proto)]
                if (self.packet.getlayer(TCP)):
                    if (self.packet[TCP].sport==80 or self.packet[TCP].dport==80):
                        pkt_pro="HTTP"
                    elif (self.packet[TCP].sport==21 or self.packet[TCP].dport==21):
                        pkt_pro="FTP"
            else:
                if 'padding' in self.packet.lastlayer().name.lower():
                    if 'raw' in self.packet.lastlayer().underlayer.name.lower():
                        pkt_pro = self.packet.lastlayer().underlayer.underlayer.name
                    else:
                        pkt_pro = self.packet.lastlayer().underlayer.name
                elif 'raw' in self.packet.lastlayer().name.lower():
                    pkt_pro = self.packet.lastlayer().underlayer.name
                else:
                    pkt_pro = self.packet.lastlayer().name
            self.pro=pkt_pro
            info = [
                str(self.packet.num),
                self.packet.time, pkt_src, pkt_dst,
                str(len(self.packet)), pkt_pro
            ]

        except:
            info = [
                str(self.packet.num),
                self.packet.time, "unknown",
                "unknown", "unknown", "unknown"
            ]

        return info

    def packet_to_load_utf8(self):
        """Decode packet load to UTF-8

        Returns:
        string of decoded information
        """

        try:
            tmp = codecs.decode(bytes(self.packet.load).hex(), "hex")
        except:
            return "No load layer in this packet"
        try:
            if set(tmp.decode("utf-8")) == {"\x00"}:
                return ""
            else:
                return tmp.decode('utf-8')
        except:
            return "Cannot decoded by utf-8\n"

    def packet_to_load_gb(self, ignore=False):
        """Decode packet load to GB2312

        Returns:
        string of decoded information
        """
        try:
            tmp = codecs.decode(bytes(self.packet.load).hex(), "hex")
        except:
            return "No load layer in this packet"
        try:
            if set(tmp.decode("GB2312")) == {"\x00"}:
                return ""
            else:
                return tmp.decode('GB2312')
        except:
            if (ignore):
                return ""
            else:
                return "Cannot decoded by GB2312\n"

    def hexdump(self):
        """Return single packet's wireshark type raw hex

        Returns:
        string of raw hex
        """
        return hexdump(self.packet)

    def __getattr__(self, attr):
        """In this way, class Packet Inherit all attributes of original packet

        Args:
            attr: attribute of original scapy Packet Class.

        Returns:
            attribute of original scapy Packet Class.
        The type remains the same.
        """

        return getattr(self.packet, attr)

    def len(self):
        """return length of the packet(including header)

        Returns:
        int that stands for the total length of the packet.
        """

        return (len(self.packet))

    def getColor(self):
        """Define packet color according wireshark default color theme.

        Returns:
            (r,g,b)
        tuple that stands for the rgb of the packet
        """

        if (self.tcp_order):
            if (self.packet.haslayer(ARP)):
                return ((250, 240, 215), (18, 39, 46))
            elif (self.packet.haslayer(ICMP)):
                return ((252, 224, 255), (18, 39, 46))
            elif (self.packet.haslayer(TCP)):
                binary_flags = bin(int(self.packet[TCP].flags.split(' ')[0]))[
                    2:].rjust(7, '0')
                if (binary_flags[-3] == '1'):  # reset
                    return ((164, 0, 0), (255, 252, 156))
                elif (self.packet[TCP].sport == 80 or self.packet[TCP].dport == 80):  # http
                    return ((228, 255, 199), (18, 39, 46))
                elif (binary_flags[-2] == '1' or binary_flags[-1] == '1'):  # SYN/FIN
                    return ((160, 160, 160), (18, 39, 46))

                return ((231, 230, 255), (18, 39, 46))
            elif (self.packet.haslayer(UDP)):
                return ((218, 238, 255), (18, 39, 46))
            elif (self.packet.haslayer(IP)):
                if(self.packet[IP].proto in (2, 88, 89, 112)):
                    ### igmp,eigrp,ospf,vrrp
                    return ((255, 243, 214), (18, 39, 46))
                elif(self.packet[IP].proto==1):
                    ### ICMP fragments
                    return ((252, 224, 255), (18, 39, 46))
                else:
                    return ((255, 255, 255), (18, 39, 46))
            elif (self.packet.haslayer(IPv6)):
                index = 0
                try:  # ICMPv6 filter
                    while (self.packet[index].nh != 58):

                        index += 1
                except:
                    return ((255, 255, 255), (18, 39, 46))
                return ((252, 224, 255), (18, 39, 46))
            else:
                return ((255, 255, 255), (18, 39, 46))
        else:  # tcp out of order
            return ((18, 39, 46), (247, 135, 135))
