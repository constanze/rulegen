from ruleset import RuleSet
from portscanRule import PortscanRule
from ruleGenerator import RuleGenerator

class PortscanDetector(RuleGenerator):
    """
    PortscanDetector takes a ruleSet and tries to find portscans.
    """
    
    def __init__(self, ruleSet, proto, style, numChecksP, numChecksIP, \
                 numAnyP, numAnyIP, distanceRange, slashSize, ipsPerSlash, \
                 numPortsPortscan, numIPsPortscan):

        RuleGenerator.__init__(self, ruleSet, proto, style, numChecksP, numChecksIP, \
                               numAnyP, numAnyIP, distanceRange, \
                               slashSize, ipsPerSlash)

        self.MAX_NUM_PORTS_PORTSCAN = numPortsPortscan
        self.MAX_NUM_IPS_PORTSCAN = numIPsPortscan
        self.MAX_DIST_RANGE_SCAN = 65535
        self.portscanSet = RuleSet()

    def detectPortscans(self):
        self.generateRules()
        self._checkForPortscans()
        self.portscanSet.checkTables(self.NUM_CHECKS_P, self.MAX_DIST_RANGE_SCAN,\
                                     self.NUM_ANY_P, self.NUM_CHECKS_IP, \
                                     self.NUM_EXP, self.NUM_ANY_IP, \
                                     self.SLASH_SIZE, self.MIN_IPS_PER_SLASH)

    def _checkForPortscans(self):
        ruleList = self.ruleSet.values()
        for r in ruleList:
            if (len(r.dPorts.elements) > self.MAX_NUM_PORTS_PORTSCAN) and \
               (len(r.sIPs) == 1) or \
               (len(r.dIPs.elements) > self.MAX_NUM_IPS_PORTSCAN and \
               len(r.sIPs) == 1) and (len(r.dPorts.elements) == 1)\
               and not r.direction == "out":
                psr = PortscanRule(r.direction, r.sIPs, r.sPorts, r.dIPs, \
                                   r.dPorts, r.proto, r.interface, "block", \
                                   self.style, r.timeStamp, r.flag)
                self.portscanSet.insert(psr)
    
    def removeRulesContainingPortscanners(self, ruleSet):
        for r in ruleSet.values():
            for pr in self.portscanSet.values():
                for e in pr.sIPs.elements.values():   
                    if r.sIPs.values()[0] == e \
                       or r.dIPs.values()[0] == e:
                       try:
                           ruleSet.remove(r)
                       except KeyError:
                           #Is already removed
                           pass
                       break

    def generateRules(self):
        self.generateTables()
        del self.sortingDict
        del self.tablesDict

    def printRules(self):
        l = len(self.portscanSet)
        if l > 0:
            if l == 1:
                print "%d rule which results from traffic which looks like a portscan\n" % l
            else:
                print "%d rules which result from traffic which looks like portscans\n" % l
            print self.portscanSet 

    def generateTables(self):
        slashSizeBackup = self.SLASH_SIZE
        self.SLASH_SIZE = 32
        if not self.proto == "icmp":
            # 2. sport is the varying part
            sPort = True
            self._portsVary(sPort)

            # 3. dport is the varying part
            sPort = False
            self._portsVary(sPort)

        # 4. dIP is the varying part
        sIP = False
        self._ipsVary(sIP)
        self.SLASH_SIZE = slashSizeBackup
