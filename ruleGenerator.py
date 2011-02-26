import copy
from ipsmap import IPsMap
from rule import Rule
from ruleset import RuleSet

class RuleGenerator():
    """
    RuleGenerator takes a ruleSet and tries to simplify it.
    """
    
    def __init__(self, ruleSet, proto, style, numChecksP, numChecksIP, \
                 numAnyP, numAnyIP, distanceRange, slashSize, ipsPerSlash):

        self.NUM_CHECKS_P =  numChecksP
        self.NUM_CHECKS_IP = numChecksIP
        self.NUM_ANY_P = numAnyP
        self.NUM_ANY_IP = numAnyIP
        self.MAX_DIST_RANGE = distanceRange
        self.SLASH_SIZE = slashSize
        self.MIN_IPS_PER_SLASH = ipsPerSlash
        self.NUM_EXP = 10

        self.proto = proto
        self.style = style
        self.sortingDict = {}
        self.tablesDict = {}
        self.ruleSet = ruleSet
        self.numberOfConns = len(ruleSet)

    def generateRules(self):
        """Generates pf rules with the following procedure:
           1. Assume one rule for every tupel
           2. Put varying parts in tables
           3. Parse tables, try to extrapolate
           4. Put tupels in rule-form"""

        self.generateTables()
        self.sortingDict.clear()
        self.tablesDict.clear()
        
        self.ruleSet.checkTables(self.NUM_CHECKS_P, self.MAX_DIST_RANGE,\
                                 self.NUM_ANY_P, self.NUM_CHECKS_IP, \
                                 self.NUM_EXP, self.NUM_ANY_IP, \
                                 self.SLASH_SIZE, self.MIN_IPS_PER_SLASH)
        self.generateTables()
        del self.sortingDict
        del self.tablesDict
        self.combineRulesWithAny()
        self.ruleSet.checkTables(self.NUM_CHECKS_P, self.MAX_DIST_RANGE,\
                                 self.NUM_ANY_P, self.NUM_CHECKS_IP, \
                                 self.NUM_EXP, self.NUM_ANY_IP, \
                                 self.SLASH_SIZE, self.MIN_IPS_PER_SLASH)

    def combineRulesWithAny(self):
        """Check for every rule, if there is another rule,
           it can be merged with using extendedEquals,
           which also checks if rules are equal, when their ips
           are made into size slashsize networks."""

        tmpRuleSet = self.ruleSet.values()
        
        for r1 in self.ruleSet:
           if (r1.sIPs.isAny or r1.dIPs.isAny or \
               r1.sPorts.isAny or r1.dPorts.isAny):
               for r2 in self.ruleSet:
                   if not r1 is r2 and r1.extendedEquals(r2, self.SLASH_SIZE):
                       tmpRuleSet.append(r1)
                       try:
                           tmpRuleSet.remove(r2)
                       except ValueError:
                           #print "Tried to remove already removed rule."
                           pass
        self.ruleSet.clear()
        self.ruleSet.extend(tmpRuleSet)
       
    def printRules(self, printElements=False):
        l = len(self.ruleSet)
        if self.style == "netfilter":
            l = 0
            for rule in self.ruleSet:
                l = l + (len(rule.sIPs)*len(rule.dIPs))
        if l <= 0:
            print "No connections for protocol %s" % self.proto
        else:
            if l == 1:
                print "%d rule for protocol %s from %d %s connection(s)" % \
                       (l, self.proto, self.numberOfConns, self.proto)
            else: 
                print "%d rules for protocol %s from %d %s connections" % \
                       (l, self.proto, self.numberOfConns, self.proto)
            if not printElements:
                print self.ruleSet 
            else:
                print self.ruleSet.printWithElements()
            print

    def generateTables(self):

        # 1. sIP is the varying part
        sIP = True
        self._ipsVary(sIP)
        
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
        
    def _portsVary(self, sPortVarying):
        """If key is not in sortingDict put key-value pairs in sortingDict and
           tablesDict,
           else merge value to existing value.
           sIPs/dIPs exist in key and value, because they could be the same ("any")
           as the one already in the hashmap and still contain different elements. 
           To provide a correct elements list they needs to be extended.
        """
        self.sortingDict.clear()
        self.tablesDict.clear()
        newR = RuleSet()
        for r in self.ruleSet:
            if sPortVarying:
                keys = (r.direction, r.sIPs, r.dIPs, r.dPorts, r.interface, r.action)
                value = (r.sPorts, r.timeStamp, r.flag, r.sIPs, r.dIPs)
            else:
               keys = (r.direction, r.sIPs, r.sPorts, r.dIPs, r.interface, r.action)
               value = (r.dPorts, r.timeStamp, r.flag, r.sIPs, r.dIPs)
            self._sortIntoDicts(keys, value)

        for key, value in self.tablesDict.iteritems():
            if sPortVarying:
                r = Rule(key[0], value[3], value[0], value[4], key[3], self.proto, key[4], key[5], self.style, value[1], value[2])
            else:
                r = Rule(key[0], value[3], key[2], value[4], value[0], self.proto, key[4], key[5], self.style,  value[1], value[2])
            newR.insert(r)

        self.ruleSet = newR
        del newR    

    def _sortIntoDicts(self, keys, value):

        if (keys) not in self.sortingDict:
            self.sortingDict[keys] = value
            self.tablesDict[keys] = value
        else:
            self.tablesDict[keys][0].extend(value[0])
            self.tablesDict[keys][3].extend(value[3])
            self.tablesDict[keys][4].extend(value[4])
            if self.proto == "tcp":
                self.tablesDict[keys][2].extend(value[2])

    def _ipsVary(self, sIP): 
        """Repeat _ipsVaryIteration until restSet is empty."""

        self.ruleSet, restSet = self._ipsVaryIteration(self.ruleSet, sIP)
        while len(restSet) != 0:
            newSet, restSet = self._ipsVaryIteration(restSet, sIP)
            self.ruleSet.extend(newSet)
        self.ruleSet.checkIPTables(self.NUM_CHECKS_IP, self.NUM_EXP,\
                                   self.NUM_ANY_IP, self.SLASH_SIZE)

    def _ipsVaryIteration(self, ruleSet, sIPvarying):
        """If sIP=True, the checks are made assuming sIP ist the varying part
           else, the check are made assuming dIP is the varying part.
           The checks work like this:
           1. The key for a rule are the ports.
           2. If the key (ports) is not in sortingDict, the rule is added to
              sortingDict and to tablesDict.
           3. If the key (ports) is already added, it is checked if the new rule
              is belonging to the rule already added.
              Belonging to is defined as that:
              3.1 If, by putting the rule together, they would have the same IP
                  on both sides (source/destination) they don't belong together.
              3.2 If the IPs don't belong into the same size slashSize networks,
                  the rules don't belong together.
            4. If the rule can be put together by making the existing IPs into
               size slashsize networks, the IPs are made into networks.
            5. If a rule has its key already in the dict, but can not be matched
               to the existing rule, it is put into the restSet.
            sPorts/dPorts exist in key and value, because they could be the same ("any")
            as the one already in the hashmap and still contain different elements. 
            To provide a correct elements list they needs to be extended.
            """
        self.sortingDict.clear()
        self.tablesDict.clear()
        newR = RuleSet()
        restSet = RuleSet()
        for r in ruleSet:
            if sIPvarying:
                value = [r.sIPs, r.dIPs, r.sPorts, r.dPorts, r.timeStamp, r.flag]
            else:
                value = [r.dIPs, r.sIPs, r.sPorts, r.dPorts, r.timeStamp, r.flag]

            key1 = copy.deepcopy(r.dPorts)
            key2 = copy.deepcopy(r.sPorts)
            keys = (r.direction, key1, r.interface, r.action, key2)
                 
            if keys not in self.sortingDict:
                self.sortingDict[keys] = value
                self.tablesDict[keys] = value
            else:
                tmpIPs1 = IPsMap()
                tmpIPs1.extend(value[0])
                tmpIPs1.extend(self.tablesDict[keys][0])
                tmpIPs2 = IPsMap()
                tmpIPs2.extend(value[1])
                tmpIPs2.extend(self.tablesDict[keys][1])

                sPortsRandom = value[2].isRandomized and\
                               self.tablesDict[keys][2].isRandomized \
                               or not value[2].isRandomized and not \
                               self.tablesDict[keys][2].isRandomized
        
                if not tmpIPs1.ipInBoth(tmpIPs2) and sPortsRandom \
                   and self.tablesDict[keys][1].checkForJoinedNetwork(value[1], self.SLASH_SIZE):
                        self.tablesDict[keys][0].extend(value[0])
                        self.tablesDict[keys][2].extend(value[2])
                        self.tablesDict[keys][3].extend(value[3])
                        if self.proto == "tcp":
                            self.tablesDict[keys][5].extend(value[5])
                else:
                    if sIPvarying:
                        restSet.insert(Rule(keys[0], value[0], value[2], \
                                            value[1], value[3], self.proto, keys[2], keys[3], self.style,  value[4], value[5]))
                    else:
                        restSet.insert(Rule(keys[0], value[1], value[2], \
                                            value[0], value[3], self.proto, keys[2], keys[3], self.style, value[4], value[5]))
        
        for key, value in self.tablesDict.iteritems():
            if sIPvarying:
                newR.insert(Rule(key[0], value[0], value[2], value[1], \
                                 value[3], self.proto, key[2], key[3], self.style, value[4], value[5]))
            else:
                newR.insert(Rule(key[0], value[1], value[2], value[0], \
                                 value[3], self.proto, key[2], key[3], self.style, value[4], value[5]))

        return newR, restSet
