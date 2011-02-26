from port import Port
from ruleset import RuleSet
from ipadress import IPv4Address, IPv4Network

class ViolationDetector():
    """
    ViolationDetector takes a ruleSet and tries to find policy violations.
    """
    
    def __init__(self, tcpRules, udpRules, icmpRules, innerServicesList, outerServicesList, \
                 forbiddenInnerServicesList, restrictedNetworks):

        self.tcpRules = tcpRules
        self.udpRules = udpRules
        self.icmpRules = icmpRules
        self.innerServicesList = self._parseServiceList(innerServicesList)
        self.outerServicesList = self._parseServiceList(outerServicesList)
        self.forbiddenInnerServicesList = self._parseServiceList(forbiddenInnerServicesList)
        self.restrictedNetworksList = self._parseNetworkList(restrictedNetworks)
        self.filteredRules = RuleSet()
        self.innerServicesFiltered = RuleSet()
        self.outerServicesFiltered = RuleSet()
        self.forbiddenInnerServicesFiltered = RuleSet()
        self.restrictedNetworksFiltered = RuleSet()

    def _parseNetworkList(self, networkList):
        if networkList != "None":
            networkList = networkList.split(",")
            tmpList = []
            for n in networkList:
                tmp = n.split("/")
                tmp[0] = IPv4Network(tmp[0]+"/"+tmp[1])
                tmp[1] = "any"
                tmp.append("any")
                tmpList.append(tmp)
            return tmpList
        return None

    def _parseServiceList(self, serviceList):
        if serviceList != "None":
            servicesList = serviceList.split(",")
            tmpList = []
            for s in servicesList:
                tmp = s.split(":")
                tmp[0] = ("any" if tmp[0]=="any" else IPv4Address(tmp[0]))
                tmp[1] = ("any" if tmp[1]=="any" else Port(int(tmp[1])))
                tmpList.append(tmp)
            return tmpList
        return None

    def printViolations(self):
        if len(self.innerServicesFiltered) > 0:
            print "Violations detected for services, which should only be accessed by ips from the inner networks:"
            print self.innerServicesFiltered
        if len(self.outerServicesFiltered) > 0:
            print "Violations detected for services, which should not be accessed by ips from the inner networks:"
            print self.outerServicesFiltered
        if len(self.forbiddenInnerServicesFiltered) > 0:
            print "Violations detected for services, which should not be used in the inner networks:"
            print self.forbiddenInnerServicesFiltered
        if len(self.restrictedNetworksFiltered) > 0:
            print "Violations detected for networks, which should have no incoming traffic:"
            print self.restrictedNetworksFiltered

    def detectViolations(self):
        if self.innerServicesList != None:
            self.innerServicesFiltered.extend(self._filterRules(self.tcpRules, self.innerServicesList, "tcp", ["in",]))
            self.innerServicesFiltered.extend(self._filterRules(self.udpRules, self.innerServicesList, "udp", ["in",]))
            self.innerServicesFiltered.extend(self._filterRules(self.icmpRules, self.innerServicesList, "icmp", ["in",]))
        if self.outerServicesList != None:
           self.outerServicesFiltered.extend(self._filterRules(self.tcpRules, self.outerServicesList, "tcp", ["out",]))
           self.outerServicesFiltered.extend(self._filterRules(self.udpRules, self.outerServicesList, "udp", ["out",]))
           self.outerServicesFiltered.extend(self._filterRules(self.icmpRules, self.outerServicesList, "icmp", ["out",]))
        if self.forbiddenInnerServicesList != None:
           self.forbiddenInnerServicesFiltered.extend(self._filterRules(self.tcpRules, self.forbiddenInnerServicesList, "tcp", ["none-inner", "in"]))
           self.forbiddenInnerServicesFiltered.extend(self._filterRules(self.udpRules, self.forbiddenInnerServicesList, "udp", ["none-inner", "in"]))
           self.forbiddenInnerServicesFiltered.extend(self._filterRules(self.icmpRules, self.forbiddenInnerServicesList, "icmp", ["none-inner", "in"]))
        if self.restrictedNetworksList != None:
           self.restrictedNetworksFiltered.extend(self._filterRules(self.tcpRules, self.restrictedNetworksList, "tcp", ["none-inner", "in"]))
           self.restrictedNetworksFiltered.extend(self._filterRules(self.udpRules, self.restrictedNetworksList, "udp", ["none-inner", "in"]))
           self.restrictedNetworksFiltered.extend(self._filterRules(self.icmpRules, self.restrictedNetworksList, "icmp", ["none-inner", "in"]))

        mergedViolations = RuleSet()
        mergedViolations.extend(self.innerServicesFiltered)
        mergedViolations.extend(self.outerServicesFiltered)
        mergedViolations.extend(self.forbiddenInnerServicesFiltered)
        mergedViolations.extend(self.restrictedNetworksFiltered)
        return mergedViolations    

    def _filterRules(self, rules, checkList, proto, direction):        
        filteredRules = RuleSet()
        for s in checkList:
            if s[2] == proto or s[2] == "any":
                for r in rules.values():
                    for d in direction:
                        if r.direction == d \
                           and (s[0] in r.dIPs or s[0] == "any") \
                           and (s[1] in r.dPorts or s[1] == "any"):
                            rules.remove(r)
                            filteredRules.insert(r)
        return filteredRules 
