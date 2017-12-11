import os
from contextlib import contextmanager

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

class Packet_r():
    """Class for loading packet and further modifications"""
    def __init__(self, packet):
        self.packet = packet

    
    def expand(self):
        """expand get all payload"""
        x = self.packet
        yield x.name, x.fields
        while x.payload:
            x = x.payload
            yield x.name, x.fields
    

    def packet_to_layerlist(self):
        """layerlist get formatted list contain every layer's detail"""
        return list(self.expand())
    

    def packet_to_all(self):
        """combine every layer parsed in to a string for further searching"""
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
        """convert every packet(including headers) to hex"""
        try:
            return (bytes(self.packet).hex())
        except:
            return ("packet cannot be converted to hex")


    def packet_to_info(self):
        """return every packet's brief information for ListCtrl"""
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
            if 'padding' in self.packet.lastlayer().name.lower():
                if 'raw' in self.packet.lastlayer().underlayer.name.lower():
                    pkt_pro = self.packet.lastlayer().underlayer.underlayer.name
                else:
                    pkt_pro = self.packet.lastlayer().underlayer.name
            elif 'raw' in self.packet.lastlayer().name.lower():
                pkt_pro = self.packet.lastlayer().underlayer.name
            else:
                pkt_pro = self.packet.lastlayer().name

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
        """decode packet load to UTF-8"""
        try:
            tmp = codecs.decode(bytes(self.packet.load).hex(), "hex")
        except:
            return "No load layer in this packet"
        try:
            if set(tmp.decode("utf-8")) == {"\x00"}:
                return "null"
            else:
                return tmp.decode('utf-8')
        except:
            return "Cannot decoded by utf-8\n"


    def packet_to_load_gb(self):
        """decode packet load to GB2312 (particularly for Chinese)"""
        try:
            tmp = codecs.decode(bytes(self.packet.load).hex(), "hex")
        except:
            return "No load layer in this packet"
        try:
            if set(tmp.decode("GB2312")) == {"\x00"}:
                return "null"
            else:
                return tmp.decode('GB2312')
        except:
            return "Cannot decoded by GB2312\n"


    def hexdump(self):
        """return single packet's wireshark type raw hex"""
        return hexdump(self.packet)
    

    def __getattr__(self, attr):
        """In this way, class Packet Inherit all attributes of original packet"""
        return getattr(self.packet, attr)


    def len(self):
        """return length of the packet(including header)"""
        return (len(self.packet))
