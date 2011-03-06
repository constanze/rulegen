import sys
import os
import copy
import ConfigParser
from optparse import OptionParser 

from dpkt.pcap import Reader

from ipaddr import IPv4Network
from ruleset import RuleSet
from pcapParser import PcapParser
from ruleGenerator import RuleGenerator
from portscanDetector import PortscanDetector
from violationDetector import ViolationDetector
from DDoSDetector import DDoSDetector
from infectedHostsDetector import InfectedHostsDetector

def processFile(file, opts):
    """
    Process a pcap file.
    file is the pcap file to parse
    """

    fileHandle = open(file)
    p = Reader(fileHandle)

    newInnerNetworksList = None
    innerNetworksList = opts.innerNetworks.split(",")
    newInnerNetworksList = []
    for n in innerNetworksList:
        newInnerNetworksList.append(IPv4Network(n))
        
    print "Reading pcap file"
    print
    s = PcapParser(p, opts.action, opts.style, "in", opts.numAnyP, opts.checkConnections, \
                   opts.checkPortscans, opts.elements, newInnerNetworksList)
    tcpRules, udpRules, icmpRules, tcpList, udpList, icmpList = s.parsePcapFile()
    del p
    del s
        
    if opts.checkForDDoS:
        ddosDetection(opts, tcpList, udpList, icmpList)

    if opts.checkForViolations:
        violationsDetected = violationDetection(opts, tcpRules, udpRules, icmpRules)

    if opts.existRulesFile != "None":
        tcpRules, udpRules, icmpRules = filterWithExistingRules(opts.existRulesFile, opts.style, tcpRules, udpRules, icmpRules)

    if opts.checkPortscans:
        tcpPortscanDetect, udpPortscanDetect = portscanDetection(opts, tcpRules, udpRules, icmpRules)

    if opts.checkInfectedHosts:
        if not opts.checkForViolations or not opts.checkPortscans:
            print "Skipping infected host detection due to not existent portscan-check and/or policy violation-check"
        else:
            infectedHostsDetection(tcpPortscanDetect, udpPortscanDetect, violationsDetected, opts.suspPolVio)

    if opts.doTests:
        print "With tests"
        tcpRulesTest = copy.deepcopy(tcpRules)
        udpRulesTest = copy.deepcopy(udpRules)
        icmpRulesTest = copy.deepcopy(icmpRules)

    tcpRuleG, udpRuleG, icmpRuleG = generateRules(opts, tcpRules, udpRules, icmpRules)

    if opts.doTests:
        testRules(tcpRulesTest, tcpRuleG.ruleSet, True)
        del tcpRulesTest
        testRules(udpRulesTest, udpRuleG.ruleSet, True)
        del udpRulesTest
        testRules(icmpRulesTest, icmpRuleG.ruleSet, True)
        del icmpRulesTest

    if opts.checkPortscans:
        tcpPortscanDetect.printRules()
        udpPortscanDetect.printRules()

def portscanDetection(opts, tcpRules, udpRules, icmpRules):
    print "Detecting Portscans"
    tcpRulesPortscanCheck = copy.deepcopy(tcpRules)
    tcpPortscanDetect = PortscanDetector(tcpRulesPortscanCheck, "tcp", \
                                         opts.style, opts.numChecksP, \
                                         opts.numChecksIP, opts.numAnyP, opts.numAnyIP, \
                                         opts.distanceRange, opts.slashSize, opts.ipsPerSlash, \
                                         opts.numPortsPortscan, opts.numIPsPortscan)
    tcpPortscanDetect.detectPortscans()
    if len(tcpPortscanDetect.portscanSet) > 0:
        tcpPortscanDetect.removeRulesContainingPortscanners(tcpRules)
        tcpPortscanDetect.removeRulesContainingPortscanners(udpRules)
        tcpPortscanDetect.removeRulesContainingPortscanners(icmpRules)

    udpRulesPortscanCheck = copy.deepcopy(udpRules)
    udpPortscanDetect = PortscanDetector(udpRulesPortscanCheck, "udp", \
                                         opts.style, opts.numChecksP, \
                                         opts.numChecksIP, opts.numAnyP, opts.numAnyIP, \
                                         opts.distanceRange, opts.slashSize, opts.ipsPerSlash, \
                                         opts.numPortsPortscan, opts.numIPsPortscan)
    udpPortscanDetect.detectPortscans()
    if len(udpPortscanDetect.portscanSet) > 0:
        udpPortscanDetect.removeRulesContainingPortscanners(tcpRules)
        udpPortscanDetect.removeRulesContainingPortscanners(udpRules)
        udpPortscanDetect.removeRulesContainingPortscanners(icmpRules)
    return tcpPortscanDetect, udpPortscanDetect

def generateRules(opts, tcpRules, udpRules, icmpRules):
    print "Generating TCP-Ruleset"
    tcpRuleG = RuleGenerator(tcpRules, "tcp", opts.style, opts.numChecksP, opts.numChecksIP, \
                             opts.numAnyP, opts.numAnyIP, \
                             opts.distanceRange, opts.slashSize, opts.ipsPerSlash)
    if opts.verbose:
        print "Original ruleset:"
        tcpRuleG.printRules()

    tcpRuleG.generateRules()

    print "Generating UDP-Ruleset"
    udpRuleG = RuleGenerator(udpRules, "udp", opts.style, opts.numChecksP, opts.numChecksIP, \
                             opts.numAnyP, opts.numAnyIP, opts.distanceRange, \
                             opts.slashSize, opts.ipsPerSlash)
    if opts.verbose:
        print "Original ruleset:"
        udpRuleG.printRules()

    udpRuleG.generateRules()
    
    print "Generating ICMP-Ruleset"
    icmpRuleG = RuleGenerator(icmpRules, "icmp", opts.style, opts.numChecksP, opts.numChecksIP, \
                             opts.numAnyP, opts.numAnyIP, opts.distanceRange, \
                             opts.slashSize, opts.ipsPerSlash)
    if opts.verbose:
        print "Original ruleset:"
        icmpRuleG.printRules()

    icmpRuleG.generateRules()

    tcpRuleG.printRules(opts.elements)
    print
    udpRuleG.printRules(opts.elements)
    print
    icmpRuleG.printRules(opts.elements)
    print
    return tcpRuleG, udpRuleG, icmpRuleG

def filterWithExistingRules(existRulesFile, style, tcpRules, udpRules, icmpRules):
    existingRuleset = RuleSet()
    existingRuleset.initializeFromExistingRuleset(existRulesFile, "pass", style)
    print "Filtering Rules with existing ruleset"
    tcpRules = testRules(tcpRules, existingRuleset)
    udpRules = testRules(udpRules, existingRuleset)
    icmpRules = testRules(icmpRules, existingRuleset)
    return tcpRules, udpRules, icmpRules

def violationDetection(opts, tcpRules, udpRules, icmpRules):
    violationDetect = ViolationDetector(tcpRules, udpRules, icmpRules, \
                                        opts.innerServices, opts.outerServices, \
                                        opts.forbiddenInnerServices, opts.restrictedNetworks)
    violationsDetected = violationDetect.detectViolations()
    violationDetect.printViolations()
    return violationsDetected

def infectedHostsDetection(tcpPortscans, udpPortscans, violationsDetected, suspPolVio):
    print "Detecting infected hosts"
    infectedHostsDetector = InfectedHostsDetector(tcpPortscans, udpPortscans, violationsDetected, suspPolVio)
    infectedHostsDetector.detectInfectedHosts()
    infectedHostsDetector.printInfectedHosts()

def ddosDetection(opts, tcpList, udpList, icmpList):
    print "Checking for DDoS"
    ddosDetect = DDoSDetector(tcpList, udpList, icmpList, \
                              opts.pps, opts.matrixSize, \
                              opts.normalTrafficBorder, opts.wmaBorder)
    ddosDetect.checkForDDoS()
    ddosDetect.printDDoSResults()

def _testPorts(conn, rule):
    if (conn.sPorts.values()[0] in rule.sPorts.values() or rule.sPorts.isAny) and \
       (conn.dPorts.values()[0] in rule.dPorts.values() or rule.dPorts.isAny):
        return True
    else:
        return False

def _testIPs(conn, rule):
    sIPsTest = False
    dIPsTest = False
    if conn.sIPs.values()[0] in rule.sIPs.values() or rule.sIPs.isAny:
        sIPsTest = True
    if conn.dIPs.values()[0] in rule.dIPs.values() or rule.dIPs.isAny:
        dIPsTest = True
    if sIPsTest and dIPsTest:
        return True
                               
    for i in rule.sIPs.values():
        if len(str(i).split("/")) > 1:
            slashSize = int(str(i).split("/")[1])
            if IPv4Network("%s/%d" % (conn.sIPs.values()[0], slashSize)) in rule.sIPs.values():
                sIPsTest = True
                break              
    for i in rule.dIPs.values():
        if len(str(i).split("/")) > 1:
            slashSize = int(str(i).split("/")[1])
            if IPv4Network("%s/%d" % (conn.dIPs.values()[0], slashSize)) in rule.dIPs.values():
                dIPsTest = True
                break              

    if sIPsTest and dIPsTest:
        return True
    else:
        return False

def testRules(connections, rules, verbose=False):
    filtertConns = RuleSet()
    for c in connections:
        ruled = False
        for r in rules:
            if c.interface == r.interface and c.proto == r.proto:
                if _testPorts(c, r):
                    if _testIPs(c, r):
                        ruled = True
                        break
        if not ruled:
            if verbose:
                print "Was not matched"
                print c
            filtertConns.insert(c)   
    return filtertConns

def rulegen():
    """Set everything off and handle files/stdin etc"""
    # parse command line

    CONFIG_FILENAME = '/etc/rulegen/rulegen.cfg'

    config = ConfigParser.ConfigParser()
    config.read(CONFIG_FILENAME)

    parser = OptionParser()

    parser.add_option("--checkConnections", action="store_true", dest="checkConnections",
                      default=(False if config.get("Normal options", "checkConnections")=="False" else True),
                      help="turns on connection-checking, only complete connections will be considered")
    parser.add_option("--existingRuleset", dest="existRulesFile",
                      type="string",
                      default=config.get("Normal options", "existingRuleset"),
                      help="file containing an existing simple ruleset")
    parser.add_option("--printElements", action="store_true", dest="elements",
                      default=(False if config.get("Normal options", "printElements")=="False" else True),
                      help="turns on printing of ips/ports belonging to a network/any/range")
    parser.add_option("-t", "--doTests", action="store_true", dest="doTests",
                      default=(False if config.get("Normal options", "doTests")=="False" else True),
                      help="turns on the tests which check if every connection is matched by a rule")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                      default=(False if config.get("Normal options", "beVerbose")=="False" else True),
                      help="verbose output, i.e. print connections as well as resulting rules")

    parser.add_option("-a", "--action", dest="action",
                      default=config.get("Normal options", "actionType"),
                      help="which kind of rules should be generated: valid options are pass and block")
    parser.add_option("-s", "--style", dest="style",
                      default=config.get("Normal options", "style"),
                      help="which kind of firewall is used: valid options are pf and netfilter")
    parser.add_option("--numberOfPortsForChecks", dest="numChecksP",
                      type="int",
                      default=config.get("Normal options", "numberOfPortsForChecks"),
                      help="number of port in a portsmap which must be present before any checks on the portsmap are performed")
    parser.add_option("--numberOfIPsForChecks", dest="numChecksIP",
                      type="int",
                      default=config.get("Normal options", "numberOfIPsForChecks"),
                      help="number of ips in an ipsmap which must be present before any checks on the ipsmap are performed")
    parser.add_option("--distanceRange", dest="distanceRange",
                      type="int",
                      default=config.get("Normal options", "distanceRange"),
                      help="maximal distance between the largest and the smallest port in a portsmap for a range")
    parser.add_option("--numberOfPortsForAny", dest="numAnyP",
                      type="int",
                      default=config.get("Normal options", "numberOfPortsForAny"),
                      help="if the number of ports in a portsmap is greater than this, the portsmap is considered \"any\"")
    parser.add_option("--numberOfIPsForAny", dest="numAnyIP",
                      type="int",
                      default=config.get("Normal options", "numberOfIPsForAny"),
                      help="if the number of ips in a ipsmap is greater than this, the ipsmap is considered \"any\"")
    parser.add_option("--slashSize", dest="slashSize",
                      type="int",
                      default=config.get("Normal options", "slashSize"),
                      help="network slash-size which is used for rule aggregation")
    parser.add_option("--numberIPsPerSlash", dest="ipsPerSlash",
                      type="int",
                      default=config.get("Normal options", "ipsPerSlash"),
                      help="minimal number of ips which must belong to a /slashsize network for the ips to be converted into a network")

    parser.add_option("--checkForPortscans", action="store_true", dest="checkPortscans",
                      default=(False if config.get("Portscandetection options", "checkForPortscans")=="False" else True),
                      help="turns on portscan-checking")
    parser.add_option("--numberPortsPortscan", dest="numPortsPortscan",
                      type="int",
                      default=config.get("Portscandetection options", "numberPortsPortscan"),
                      help="minimal number of ports which must be present in a destination portsmap for the corresponding rule to be considered belonging to a port-scan")
    parser.add_option("--numberIPsPortscan", dest="numIPsPortscan",
                      type="int",
                      default=config.get("Portscandetection options", "numberIPsPortscan"),
                      help="minimal number of IPs which must be present in a destination ipsmap for the corresponding rule to be considered belonging to a port-scan")
    
    parser.add_option("--checkForViolations", action="store_true", dest="checkForViolations",
                      default=(False if config.get("Policy Violation options", "checkForViolations")=="False" else True),
                      help="turns on policy-violation-checking")
    parser.add_option("--innerNetworks", dest="innerNetworks",
                      default=config.get("Policy Violation options", "innerNetworks"),
                      help="inner networks, which are being protected by the firewall")
    parser.add_option("--innerServices", dest="innerServices",
                      default=config.get("Policy Violation options", "innerServices"),
                      help="Services which should only be accessed by ips in the innerNetworks")
    parser.add_option("--outerServices", dest="outerServices",
                      default=config.get("Policy Violation options", "outerServices"),
                      help="Services on the outer network which should not be accessed by ips in the inner Networks")
    parser.add_option("--forbiddenInnerServices", dest="forbiddenInnerServices",
                      default=config.get("Policy Violation options", "forbiddenInnerServices"),
                      help="Services which are forbidden in the inner Networks")
    parser.add_option("--restrictedNetworks", dest="restrictedNetworks",
                      default=config.get("Policy Violation options", "restrictedNetworks"),
                      help="Networks in the innerNetworks, which should only have outgoing traffic, no incoming")
    parser.add_option("--checkForDDoS", dest="checkForDDoS",
                      default=(False if config.get("DDoS", "checkForDDoS")=="False" else True),
                      help="Check for DDoS")
    parser.add_option("--packetsPerSecond", dest="pps",
                      type="int",
                      default=config.get("DDoS", "packetsPerSecond"),
                      help="rate of packets per second, which qualifies for a DDoS check")
    parser.add_option("--matrixSize", dest="matrixSize",
                      type="int",
                      default=config.get("DDoS", "matrixSize"),
                      help="Size of IP matrix")
    parser.add_option("--normalTrafficBorder", dest="normalTrafficBorder",
                      type="int",
                      default=config.get("DDoS", "normalTrafficBorder"),
                      help="number of ips, which would be normal for the given rate of packets per second")
    parser.add_option("--wmaBorder", dest="wmaBorder",
                      type="int",
                      default=config.get("DDoS", "wmaBorder"),
                      help="upper border for weighted moving average")
    parser.add_option("--infectedHostsDetection", dest="checkInfectedHosts",
                      default=(False if config.get("Infected Hosts", "checkInfectedHosts")=="False" else True),
                      help="Check for infected hosts")
    parser.add_option("--suspiciousPolicyViolations", dest="suspPolVio",
                      default=config.get("Infected Hosts", "suspiciousPolicyViolations"),
                      help="Policy violations which indicate an infected host")

    (opts, args) = parser.parse_args()

    if opts.existRulesFile != "None":
        if os.path.exists(opts.existRulesFile) and os.path.isfile(opts.existRulesFile):
            pass
        else:
            print "Files with existing rules not found. Exiting."
            sys.exit(2)
             
    if len(sys.argv)>1 and len(args) >= 1:
        for f in args:
            if os.path.exists(f) and os.path.isfile(f): 
                processFile(f, opts)
            else:
                print "File not found: %s" % f
                sys.exit(2)
    else:
        sys.exit(2) 

if __name__ == "__main__":
    rulegen()
