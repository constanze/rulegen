import dpkt
import socket
from ipadress import IPv4Address, IPv4Network
from port import Port 
from portsmap import PortsMap 
from rule import Rule 
from ruleset import RuleSet
from ipsmap import IPsMap
from pflog import Pflog

class PcapParser():
    """
    PcapParser parses a pcap-file with dpkt.
    Every ip-paket is put into either the tcp or udp or icmp ruleset.
    Rulesets are sets, they contain every item only once.
    Concerning tcp: only full connections are kept (there must be a syn 
    and a fin paket).
    Non-ip-pakets are not concerned. 
    """
    def __init__(self, pcapFile, action, style, direction, maxNumPortsAny, \
                 connectionChecking, portscanChecking, printElements, \
                 innerNetworks=None, ddosDetection=True): 
        self.p = pcapFile
        self.direction = direction 
        self.action = action
        self.style = style
        self.interface = "None"
        self.tcpRuleSet = RuleSet()
        self.udpRuleSet = RuleSet()
        self.icmpRuleSet = RuleSet()
        self.tcpRuleList = []
        self.udpRuleList = []
        self.icmpRuleList = []
        self.MAX_NUM_PORTS_ANY = maxNumPortsAny
        self.connectionChecking = connectionChecking
        self.ddosDetection = ddosDetection
        self.saveElements = portscanChecking or printElements
        self.PFLOG_DUMP = 117
        self.innerNetworks = innerNetworks
    
    def parsePcapFile(self):
        """Parse a pcap file"""
        for ts, buf in self.p:
            self._packetHandler(buf, ts)
        if self.connectionChecking:
            self._checkTcpForConns()
        return self.tcpRuleSet, self.udpRuleSet, self.icmpRuleSet, \
               self.tcpRuleList, self.udpRuleList, self.icmpRuleList
        
    def _packetHandler(self, buf, ts):
        """Parse a pcap buffer"""
        try:
            if (self.p.datalink() == self.PFLOG_DUMP):
                #pkt = dpkt.pflog.Pflog(buf)
                pkt = Pflog(buf)
                self.interface = pkt.interfaceName
                self.direction = "in" if pkt.direction == 1 else "out"
                subpkt = pkt.data
                try:
                    subpkt = dpkt.ip.IP(subpkt)
                except:
                    #skip non IP packets
                    return
            else:
                pkt = dpkt.ethernet.Ethernet(buf)
                subpkt = pkt.data
                if not isinstance(subpkt, dpkt.ip.IP):
                    #skip non IP packets
                    return

            proto = subpkt.p
            shost = socket.inet_ntoa(subpkt.src)
            dhost = socket.inet_ntoa(subpkt.dst)
            shostInner = False
            dhostInner = False
            if self.innerNetworks != None:
                for n in self.innerNetworks:
                    slashSize = str(n).split("/")[1]
                    if IPv4Network(str(shost)+"/"+str(slashSize)) == n:
                       shostInner = True 
                    if IPv4Network(dhost+"/"+slashSize) == n:
                       dhostInner = True 
                if shostInner and dhostInner:
                    self.direction = "none-inner"
                elif shostInner and not dhostInner:
                    self.direction = "out"
                elif not shostInner and dhostInner:
                    self.direction = "in"
                else:
                    self.direction = "none-outer"

        except dpkt.Error:
            #skip non-ethernet packages
            return
        try:
            if proto == socket.IPPROTO_TCP:
                try:
                    tcp = subpkt.data
                    flag = tcp.flags
                    if self.connectionChecking:
                        rightFlag = ((flag == dpkt.tcp.TH_SYN) \
                                    or (flag & dpkt.tcp.TH_FIN != 0))
                    else:
                        rightFlag = (flag == dpkt.tcp.TH_SYN)
                                    
                    dport = tcp.dport
                    sport = tcp.sport
                    sIP = IPsMap(self.saveElements)
                    sIP.insert(IPv4Address(shost))
                    sPort = PortsMap(self.MAX_NUM_PORTS_ANY, self.saveElements)
                    sPort.insert(Port(sport, True))
                    dIP = IPsMap(self.saveElements)
                    dIP.insert(IPv4Address(dhost))
                    dPort = PortsMap(self.MAX_NUM_PORTS_ANY, self.saveElements)
                    dPort.insert(Port(dport, False))
                    if flag == dpkt.tcp.TH_SYN:
                        flag = "SYN"
                    else:
                        flag = "FIN"
                    r = Rule(self.direction, sIP, sPort, dIP, dPort, "tcp", \
                             self.interface, self.action, self.style, [ts, ], [flag, ])
                    if self.p.datalink() == self.PFLOG_DUMP or rightFlag:
                        self.tcpRuleSet.insert(r)
                    if self.ddosDetection:
                        self.tcpRuleList.append((IPv4Address(shost), ts))
                except AttributeError:
                    #skip broken packages
                    return
            elif proto == socket.IPPROTO_UDP:
                udp = subpkt.data
                dport = udp.dport
                sport = udp.sport
                sIP = IPsMap(self.saveElements)
                sIP.insert(IPv4Address(shost))
                sPort = PortsMap(self.MAX_NUM_PORTS_ANY, self.saveElements)
                sPort.insert(Port(sport, True))
                dIP = IPsMap(self.saveElements)
                dIP.insert(IPv4Address(dhost))
                dPort = PortsMap(self.MAX_NUM_PORTS_ANY, self.saveElements)
                dPort.insert(Port(dport, False))
                r = Rule(self.direction, sIP, sPort, dIP, dPort, "udp", \
                         self.interface, self.action, self.style, [ts, ])
                self.udpRuleSet.insert(r)
                if self.ddosDetection:
                   self.udpRuleList.append((IPv4Address(shost), ts))
            elif proto == socket.IPPROTO_ICMP:
                sIP = IPsMap(self.saveElements)
                sIP.insert(IPv4Address(shost))
                sPort = PortsMap(self.MAX_NUM_PORTS_ANY)
                sPort.insert(Port(-1, True))
                dIP = IPsMap(self.saveElements)
                dIP.insert(IPv4Address(dhost))
                dPort = PortsMap(self.MAX_NUM_PORTS_ANY)
                dPort.insert(Port(-1, False))
                r = Rule(self.direction, sIP, sPort, dIP, dPort, "icmp", \
                         self.interface, self.action, self.style, [ts, ])
                self.icmpRuleSet.insert(r)
                if self.ddosDetection:
                   self.icmpRuleList.append((IPv4Address(shost), ts))
        except dpkt.Error:
            return

    def _checkTcpForConns(self):
        """Checks tcp-set for connections.""" 
        print "Checking for Connections"
        tcpRuleSetConnsOnly = RuleSet()
        if self.p.linktype == self.PFLOG_DUMP:
            tcpRuleSetConnsOnly = self.tcpRuleSet
        else:
            for r in self.tcpRuleSet:
                connection = False
                for r2 in self.tcpRuleSet:
                    if (r == r2 and (r.flag[0]=="SYN") and (r2.flag[0]=="FIN")):
                        connection = True
                        break
                if connection:
                    tcpRuleSetConnsOnly.insert(r)

        self.tcpRuleSet = tcpRuleSetConnsOnly 
