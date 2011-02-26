from port import Port
from ruleset import RuleSet
from ipsmap import IPsMap
from ipadress import IPv4Address, IPv4Network

class InfectedHostsDetector():
    """
    InfectedHostsDetector takes found portscans and policy violations 
    and tries to find indected hosts.
    """
    
    def __init__(self, tcpPortscans, udpPortscans, policyViolations, suspPolVio):

        self.tcpPortscans = tcpPortscans
        self.udpPortscans = udpPortscans
        self.policyViolations = policyViolations
        self.portscans = RuleSet()
        self.doubleIPs = IPsMap()
        self.portscanIPs = IPsMap()
        self.violationIPs = IPsMap()
        self.clearedPolicyViolations = RuleSet()
        self.suspPolVio = suspPolVio.split(":")

    def detectInfectedHosts(self):
        for ps in self.tcpPortscans.portscanSet:
            if ps.direction == "out" or ps.direction == "none-inner":
                self.portscans.insert(ps)
        for ps in self.udpPortscans.portscanSet:
            if ps.direction == "out" or ps.direction == "none-inner":
                self.portscans.insert(ps)
        for pv in self.policyViolations:
            if pv.direction == "out" or pv.direction == "none-inner":
                if str(pv.dPorts.values()[0].portNumber) in self.suspPolVio:
                    self.clearedPolicyViolations.insert(pv)

        for portscan in self.portscans:
            for violation in self.clearedPolicyViolations:
                if portscan.sIPs == violation.sIPs:
                    self.doubleIPs.insert(portscan.sIPs)
        
        for doubleIP in self.doubleIPs:
            for policyVio in self.clearedPolicyViolations.values():
                if policyVio.sIPs == doubleIP:
                    try:
                        self.clearedPolicyViolations.remove(policyVio)        
                    except:
                        #already removed
                        pass

        for doubleIP in self.doubleIPs:
            for portscan in self.portscans.values():
                if portscan.sIPs == doubleIP:
                    try:
                        self.portscans.remove(portscan)        
                    except:
                        #already removed
                        pass
        
        for violation in self.clearedPolicyViolations:
                self.violationIPs.insert(violation.sIPs)
        for portscan in self.portscans:
                self.portscanIPs.insert(portscan.sIPs)

    def printInfectedHosts(self):
        for host in self.doubleIPs:
            print "%s might be infected! Warning signals include: portscans and policy violations" % str(host)
        for host in self.portscanIPs:
            print "%s might be infected! Warning signals include: portscans" % str(host)
        for host in self.violationIPs:
            print "%s might be infected! Warning signals include: policy violations" % str(host)
