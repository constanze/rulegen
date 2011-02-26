import copy

class Rule:
    """This class represents a pf-rule."""

    def __init__(self, d, sip, sp, dip, dp, p, i, action, style="pf", ts=None, flag=["",]):

        self.sIPs = sip 
        self.sPorts = sp 
        self.dIPs = dip
        self.dPorts = dp
        self.direction = d
        self.proto = p
        self.interface = i
        self.timeStamp = ts
        self.flag = flag
        
        if (action != "pass" and action != "block"):
            raise ValueError("Action must be either block or pass.")
        self.action = action

        if (style != "pf" and style != "netfilter"):
            raise ValueError("Style must be either pf or netfilter, but it was: " + style)
        self.style = style

    def checkPortsForAny(self):
        self.sPorts.checkForAny(self.MAX_NUM_PORTS_FOR_ANY)
        self.dPorts.checkForAny(self.MAX_NUM_PORTS_FOR_ANY)

    def sort(self):
        self.sIPs.sort()
        self.sPorts.sort()
        self.dIPs.sort()
        self.dPorts.sort()

    def checkIPTables(self, numChecks, numExpand, numAny, \
                      slashSize, minIPsForSlash):
        """Calls methods to shorten IP tables."""

        self.sIPs.doChecks(numChecks, numExpand, numAny, slashSize, minIPsForSlash)
        self.dIPs.doChecks(numChecks, numExpand, numAny, slashSize, minIPsForSlash)

    def checkTables(self, numChecksP, maxDistRange, numAnyP, numChecksIP, numExpand, \
                    numAny, slashSize, minIPsForSlash):
        """Calls methods to shorten IP and port tables."""

        self.checkIPTables(numChecksIP, numExpand, numAny, slashSize, minIPsForSlash)
        self.sPorts.doChecks(numChecksP, maxDistRange, numAnyP)
        self.dPorts.doChecks(numChecksP, maxDistRange, numAnyP)

    def extendedEquals(self, other, slashSize):
        if self == other:
           return True
        if self.sPorts == other.sPorts and self.dPorts == other.dPorts:
            if self.sIPs == other.sIPs:
                self.dIPs.extend(other.dIPs)
                return True
            if self.dIPs == other.dIPs:
                self.sIPs.extend(other.sIPs)
                return True
            tmpsIPs = copy.deepcopy(self.sIPs)
            tmpdIPs = copy.deepcopy(self.dIPs)
            if not (tmpsIPs.ipInBoth(other.dIPs) or tmpdIPs.ipInBoth(other.sIPs)): 
                if tmpsIPs.checkForJoinedNetwork(other.sIPs, slashSize) \
                   and tmpdIPs.checkForJoinedNetwork(other.dIPs, slashSize):
                    self.sIPs = tmpsIPs
                    self.dIPs = tmpdIPs
                    return True
        return False
    
    def printWithElements(self):
        
        ruleString = (str(self) + 
               ("" if len(self.sIPs.elements) <= 1 or len(self.sIPs.elements) <= len(self.sIPs) else ("\nElements for source-ip: " + 
               str(self.sIPs.elements))) +
               ("" if self.proto=="icmp" or (len(self.sPorts.elements) <= 1 or len(self.sPorts.elements) <= len(self.sPorts)) else ("\nElements for source-port: " + 
               str(self.sPorts.elements))) +
               ("" if len(self.dIPs.elements) <= 1 or len(self.dIPs.elements) <= len(self.dIPs) else ("\nElements for destination-ip: " + 
               str(self.dIPs.elements))) +
               ("" if self.proto=="icmp" or (len(self.dPorts.elements) <= 1 or len(self.dPorts.elements) <= len(self.dPorts)) else ("\nElements for destination-port: " + 
               str(self.dPorts.elements)))
               )
                
        return ruleString

    def __hash__(self):
        flagH = ""
        for f in self.flag:
            flagH = flagH + f
        hashValue = self._pf_str() + flagH
        return hash(hashValue)

    def __eq__(self, other):
        if not self.direction == other.direction:
            return False
        if not self.proto == other.proto:
            return False
        if not self.sIPs == other.sIPs:
            return False
        if not self.dIPs == other.dIPs:
            return False
        if not self.sPorts == other.sPorts:
            return False
        if not self.dPorts == other.dPorts:
            return False
        if not self.action == other.action:
            return False
        return True
        
    def __ne__(self, other):
        return not self == other
        
    def __str__(self):
        if self.style == "pf": 
            return self._pf_str()
        else:
            return self._netfilter_str()

    def _pf_str(self):
        ruleString = (self.action + " " + 
               self.direction +
               ("" if self.interface == "None" else " on %s" % self.interface) + 
               " proto " + self.proto +
               " from " +
               str(self.sIPs) +
               ((" port %s" % str(self.sPorts)) if self.proto != "icmp" and not self.sPorts.isAny else "") +
               " to " +
               str(self.dIPs) +
               ((" port %s" % str(self.dPorts)) if self.proto != "icmp" and not self.dPorts.isAny else ""))
                
        return ruleString

    def _netfilter_str(self):
        rules = self._splitRule()
        ruleStrings = ""
        for rule in rules:
            if rule.direction == "in":
                direction = "PREROUTING"
            elif rule.direction == "out":
                direction = "POSTROUTING"
            elif rule.direction == "none-outer":
                direction = "none-outer"
            else:
                direction = "none-inner"
            ruleString = ("iptables -A " + 
                   direction +
                   " -p " + rule.proto +
                   " -m multiport" +
                   ("" if rule.interface == "None" else " -i %s" % rule.interface) + 
                   " -s " +
                   str(rule.sIPs) +
                   ((" --sports %s" % str(rule.sPorts).replace("{ ", "").replace(" }", "").replace(" ", "")) if rule.proto != "icmp" and not rule.sPorts.isAny else "") +
                   " -d " +
                   str(rule.dIPs) +
                   ((" --dports %s" % str(rule.dPorts).replace("{ ", "").replace(" }", "").replace(" ", "")) if rule.proto != "icmp" and not rule.dPorts.isAny else "") +
                   " -j " + ("ACCEPT" if rule.action == "pass" else "DROP"))
            ruleStrings = ruleStrings + ruleString + "\n"
        ruleStrings = ruleStrings.strip('\n')
        return ruleStrings

    def _splitRule(self):
        rules = []
        #rules.append(self)
        for sip in self.sIPs:
            if self.sIPs.isAny:
                sip = "any"
            for dip in self.dIPs:
                if self.dIPs.isAny:
                    dip = "any"
                rules.append(Rule(self.direction, sip, self.sPorts, dip, \
                             self.dPorts, self.proto, self.interface, self.action, self.style))
        return rules
