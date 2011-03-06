from basemap import BaseMap
from port import Port

class PortsMap(BaseMap):
    """A map of ports."""

    def __init__(self, npa, checkForPortscans=False):
        BaseMap.__init__(self)
        self.classinfo = PortsMap
        self.NUM_PORTS_ANY = npa
        self.separator = ", "
        self.isRange = False
        self.isRandomized = False
        self.checkForPortscans = checkForPortscans
        if self.checkForPortscans:
            self.elements = BaseMap()
            self.elements.separator = ", "
        
    def insert(self, item):
        if item.randomized and len(self) == 0:
            self.isRandomized = True
        if not self.isAny:
            BaseMap.insert(self, item)   
        if self.checkForPortscans and not item.portNumber == -1:
            self.elements.insert(item)

    def extend(self, other):
        if (len(self) + len(other)) < self.NUM_PORTS_ANY and not self.isAny\
           and not other.isAny:
            BaseMap.extend(self, other)
        else:
            self.clear()
            self.isAny = True
            self.insert(Port(-1, False))
        if self.checkForPortscans:
            self.elements.extend(other.elements.values())

    def doChecks(self, numChecks, distRange, numAny):
        l = len(self)
        if l >= numChecks:
            if l > numAny:
                self.clear()
                self.insert(Port(-1))
                self.isAny = True
            if not self.isAny and not self.isRange:
                self.checkForRange(distRange)
           
    def checkForRange(self, border):
        portMap = self.values()
        portMap.sort()
        if(portMap[len(portMap)-1] - portMap[0] <= border):
            self.isRange = True
            self.clear()
            self.insert(portMap[0])
            self.insert(portMap[len(portMap)-1])
            self.separator = ":"
 
    def __str__(self):
        if self.isAny:
            return ""
        out = BaseMap.__str__(self)
        if len(self) > 1  and not self.isRange:
            out = "{ " + out + " }"
        return out
