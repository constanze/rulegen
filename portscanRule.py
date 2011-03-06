from rule import Rule

class PortscanRule(Rule):
    """This class represents a pf-rule and additional information for a found portscan."""

    def __init__(self, d, sip, sp, dip, dp, p, i, action, style, ts=None, flag="None"):

        Rule.__init__(self, d, sip, sp, dip, dp, p, i, action, style, ts, flag)
        self.action = "block"
        self.numPortsScanned = len(self.dPorts.elements)
        sortedValues = self.dPorts.elements.values()
        sortedValues.sort()
        self.startPort = sortedValues[0]
        self.endPort = sortedValues[self.numPortsScanned-1]

    def __str__(self):
        self.timeStamp.sort()
        portstring1 = ""
        if self.numPortsScanned == 1: 
             portstring1 = "%d port was scanned: port %s\n" % (self.numPortsScanned, str(self.startPort))
        else:
             portstring1 = "%d ports were scanned in range: %s:%s\n" % (self.numPortsScanned, str(self.startPort), str(self.endPort))
        if self.style == "pf":
            portstring2 = self._pf_str()
        else:
            portstring2 = self._netfilter_str()
        portstring3 = ("\n%d IP(s) scanned: %d IP(s)" % (len(self.sIPs.elements), len(self.dIPs.elements)) +
        "\n%s scanned %s" % (str(self.sIPs.elements).replace("/32",""), \
        str(self.dIPs.elements).replace("/32", "")))
        return portstring1 + portstring2 + portstring3
