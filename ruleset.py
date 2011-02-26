import fileinput
from basemap import BaseMap
from ipsmap import IPsMap
from portsmap import PortsMap
from port import Port
from rule import Rule
from ipadress import IPv4Address, IPv4Network

class RuleSet(BaseMap):
    """A complete ruleset for pf, based on the analyzed traffic"""

    def __init__(self):
          BaseMap.__init__(self)
          self.classinfo = RuleSet

    def printWithElements(self):
            return self.separator.join(["%s" % r.printWithElements() for r in self])
 
    def checkIPTables(self, numChecks, numExpand, numAny, slashSize, minIPsForSlash=2):
        for rule in self:
            rule.checkIPTables(numChecks, numExpand, numAny, slashSize, minIPsForSlash)
 
    def checkTables(self, numChecksP, maxDistRange, numAnyP, numChecksIP, numExpand, \
                    numAny, slashSize, minIPsForSlash):
        for rule in self:
            rule.checkTables(numChecksP, maxDistRange, numAnyP, numChecksIP, numExpand, \
                             numAny, slashSize, minIPsForSlash)

    def initializeFromExistingRuleset(self, fileName, action, style):
        fileHandle = open(fileName)
        for line in fileinput.input(fileName):
            if style == "pf":
                self._existingRulesPfFormat(action, line, style)
            else:
               self._existingRulesNetfilterFormat(action, line, style)

    def _existingRulesPfFormat(self, action, line, style):
        if line.startswith(action):
            strings = line.split(" ")
            stringsStripped = []
            for s in strings:
                tmp = s.strip(",")
                stringsStripped.append(tmp.strip("\n"))
            strings = stringsStripped
            action = strings.pop(0)
            direction = strings.pop(0)
            if strings[0] == "on":
                del strings[0]
                interface = strings.pop(0)
            else:
                interface = "None"
            del strings[0]
            proto = strings.pop(0)
            del strings[0]
            sIPs = IPsMap()
            self._parseIPs(sIPs, strings) 
            sPorts = PortsMap(1000)
            self._parsePortsPf(sPorts, strings) 
            dIPs = IPsMap()
            self._parseIPs(dIPs, strings) 
            dPorts = PortsMap(1000)
            self._parsePortsPf(dPorts, strings) 

            r = Rule(direction, sIPs, sPorts, dIPs, dPorts, proto, interface, action, style)
            self.insert(r)

    def _existingRulesNetfilterFormat(self, action, line, style):
        if line.startswith("iptables"):
            strings = line.split(" ")
            stringsStripped = []
            for s in strings:
                tmp = s.split(",")
                for t in tmp:
                    stringsStripped.append(t.strip("\n"))
            strings = stringsStripped

            del strings[0]
            del strings[0]
            tmp = strings.pop(0)
            if tmp == "PREROUTING":
                direction = "in"
            elif tmp == "POSTROUTING":
                direction = "out"
            elif tmp == "outer":
                direction = "none-outer"
            else:
                direction = "none-inner"
            del strings[0]
            proto = strings.pop(0)
            del strings[0]
            del strings[0]
            if strings[0] == "-i":
                del strings[0]
                interface = strings.pop(0)
            else:
                interface = "None"
            del strings[0]
            sIPs = IPsMap()
            self._parseIPs(sIPs, strings) 
            sPorts = PortsMap(1000)
            self._parsePortsNetfilter(sPorts, strings) 
            dIPs = IPsMap()
            self._parseIPs(dIPs, strings) 
            dPorts = PortsMap(1000)
            self._parsePortsNetfilter(dPorts, strings) 
            action = "pass" if strings.pop(0) == "ACCEPT" else "block"

            r = Rule(direction, sIPs, sPorts, dIPs, dPorts, proto, interface, action, style)
            self.insert(r)

    def _parseIPs(self, ips, strings):
        if strings[0] == "{":
            del strings[0]
            while (strings[0] != "}"):
                if strings[0].count("/") != 0:
                    tmp = strings[0].split("/")
                    tmpNet = IPv4Network(strings[0])
                    ips.insert(tmpNet)
                    slashSizes.append(int(tmp[1]))
                else:
                    ips.insert(IPv4Address(strings[0]))
                del strings[0]
            del strings[0]
        else:
            if strings[0].count("/") != 0:
                tmp = strings[0].split("/")
                tmpNet = IPv4Network(strings[0])
                ips.insert(tmpNet)
            else:
                ips.insert(IPv4Address(strings[0]))
            del strings[0]

    def _parsePortsPf(self, ports, strings):
        if len(strings) != 0 and strings[0] == "port":
            del strings[0]
            if strings[0] == "{":
                del strings[0]
                while (strings[0] != "}"):
                    ports.insert(Port(int(strings[0])))
                    del strings[0]
                del strings[0]
            else:
                if strings[0] == "random":
                    tmp = Port(65535, True)
                    ports.insert(tmp)
                    ports.isRandomized = True
                else:
                    ports.insert(Port(int(strings[0])))
                del strings[0]
        else:
            ports.insert(Port(-1))
            ports.isAny = True
        if len(strings) != 0:
            del strings[0]

    def _parsePortsNetfilter(self, ports, strings):
        if len(strings) != 0 and strings[0].startswith("--"):
            del strings[0]
            if strings[0] == "random":
                tmp = Port(65535, True)
                ports.insert(tmp)
                ports.isRandomized = True
            else:
                ports.insert(Port(int(strings[0])))
            del strings[0]
            while (not strings[0].startswith("-")):
                ports.insert(Port(int(strings[0])))
                del strings[0]
        else:
            ports.insert(Port(-1))
            ports.isAny = True
        if len(strings) != 0:
            del strings[0]

