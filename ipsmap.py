from basemap import BaseMap
from ipadress import IPv4Address, IPv4Network

class IPsMap(BaseMap):
    """A map of IPs."""

    def __init__(self, checkForPortscans=False):
        BaseMap.__init__(self)
        self.classinfo = IPsMap
        self.separator = ", "
        self.isNetworks = False
        self.checkForPortscans = checkForPortscans
        if self.checkForPortscans:
            self.elements = BaseMap()
            self.elements.separator = ", "
        #List for problems, which need a sorted list
        #must be filled with current values() before used
        self.ipList = []

    def insert(self, item):
        if not self.isAny:
            BaseMap.insert(self, item)   
        if self.checkForPortscans and isinstance(item, IPv4Address):
            self.elements.insert(item)

    def extend(self, other):
        if not other.isAny:
            BaseMap.extend(self, other)
        else:
            self.clear()
            self.insert(IPv4Address("0.0.0.0"))
            self.isAny = True
        if self.checkForPortscans:
            self.elements.extend(other.elements.values())

    def ipInBoth(self, otherMap):
        for value1 in self:
            if isinstance(value1, IPv4Address):
                if value1 in otherMap:
                    return True
        return False

    def doChecks(self, numChecks, numExpand, numAny, slashSize, minIpsForSlash):
        self.ipList = self.values()
        self.ipList.sort()
        self.makeSlashNetwork(slashSize, minIpsForSlash)
        if len(self) >= numChecks:
            if len(self.ipList) > numAny:
                self.ipList = [IPv4Address("0.0.0.0"), ]
                self.isAny = True
        if self.isNetworks or self.isAny:
            self._mapToDict()
    
    def checkForJoinedNetwork(self, otherIPs, slashSize):
        """Checks if the ips from otherIPs would be
           in size slashSize networks made from the ips in self.
           If the ips from otherIPs fit into these networks,
           the ips in self are made into corresponding 
           slashSize networks."""
         
        self.ipList = self.values()
        length = len(self.ipList)
        if length > len(otherIPs):
            length = len(otherIPs)
        self.ipList.extend(otherIPs.values())
        self.ipList = list(set(self.ipList))
        self.ipList.sort() 
        self.makeSlashNetwork(slashSize, 2, length, True)
        if self.isNetworks:
            self._mapToDict()
            if self.checkForPortscans:
                self.elements.extend(otherIPs.elements.values())
        return self.isNetworks
    
    def checkForNetworks(self, border, numExpand):
        """Checks if by summarizing the address range of ips
           the number of networks is <= number of ips.
           If that is the case, ips are replaced with the networks
           from the summarized address range."""
        if len(self.ipList) >= border:
            network = summarize_address_range(self.ipList[0], \
                                              self.ipList[len(self.ipList)-1])
            network = collapse_address_list(network)
            if len(network) <= (len(self)/2):
                self.isNetworks = True
                self.ipList = network
    
    def makeSlashNetwork(self, slashSize, minIPsPerNet, maxFoundNetw=1000,\
                         joinedNetworksCheck=False):
        """If minIPsPerNet can be found for a slashSize networks,
           instead of the ips, the corresponding network is saved.
           MaxFoundNetworks and onlyOne are only relevant for check from 
           checkForJoinedNetwork. If there are more networks, than
           maxFoundNetwork, the ips which are checked are not in a 
           joined, but in separate networks."""
        foundNetworks = []
        ips = self.ipList
        
        while(len(ips) > 0):
            if joinedNetworksCheck and len(foundNetworks) > maxFoundNetw:
                self.isNetworks = False
                return
            startIp = ips[0]
            if not isinstance(startIp, IPv4Network):
                network = IPv4Network("%s/%d" % (startIp, slashSize))
                network = network.masked()
            else:
                network = startIp
                #If it is a network already, minIPsPerNet is not relevant
                minIPsPerNet = 2
            i = 0
            matchingIPsToCurrentNetwork = True
            while(matchingIPsToCurrentNetwork):
                if not isinstance(ips[i], IPv4Network):
            	    tmpNetwork = IPv4Network("%s/%d" % (ips[i], slashSize))
                else:
            	    tmpNetwork = ips[i]
                if len(ips) == 1: 
                    i = i + 1
                if tmpNetwork == network and len(ips) > 1 :
                    i = i + 1
                    if i >= len(ips):
                        self._writeIPs(ips, foundNetworks, network, i, minIPsPerNet)
                        matchingIPsToCurrentNetwork = False
                else:
                    self._writeIPs(ips, foundNetworks, network, i, minIPsPerNet)
                    matchingIPsToCurrentNetwork = False
        
        if joinedNetworksCheck and len(foundNetworks) > maxFoundNetw:
            self.isNetworks = False
        else:
            self.ipList = foundNetworks
            self.isNetworks = True 
       
    def _expandedNetworkSearch(self, border):
        """This method tries to find a network by
           expanding the range
           WARNING: This really takes some time,
                    be careful what you choose for
                    border!"""
        startIp = self.ipList[0]
        endIp = self.ipList[len(self.ipList)-1] + 1
        for i in range(border):
            for j in range(border):
                network = summarize_address_range(startIp, endIp)
                if len(network) == 1:
                    self.ipList = network
                    self.isNetworks = True
                endIp = endIp + 1
            endIp = self.ipList[len(self.ipList)-1]
            startIp = startIp - 1
           
    def _writeIPs(self, ips, foundNetworks, network, i, minIPsPerNet):
        if i >= minIPsPerNet:
            foundNetworks.append(network)
        else:
            for j in range(i):
                foundNetworks.append(ips[j])
        for j in range(i):
            ips.remove(ips[0])
        
    def _mapToDict(self):
        isAny = self.isAny
        self.clear()
        for item in self.ipList:
            self.insert(item) 
        del self.ipList
        self.isAny = isAny

    def __str__(self):
        out = "any" if self.isAny else BaseMap.__str__(self)
        if len(self) > 1 and not self.isAny:
            out = "{ " + out + " }"
        return out
