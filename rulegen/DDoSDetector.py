from ruleset import RuleSet

class DDoSDetector():
    """
    DDoSDetector takes a ruleSet and tries to find policy violations.
    """
    
    def __init__(self, tcpRules, udpRules, icmpRules, pps, matrixSize, normalTrafficBorder, wmaBorder):

        self.tcpRules = tcpRules
        self.udpRules = udpRules
        self.icmpRules = icmpRules
        self.filteredRules = RuleSet()
        self.matrixSize = matrixSize
        self.normalTrafficBorder = normalTrafficBorder
        self.wmaBorder = wmaBorder
        self.packetsPerSecond = pps
        self.matrix = None
        self.varianceList = None
        self.wma = None
        self.k = 0.0
        self.tcpWma = None
        self.tcp_k = 0.0
        self.udpWma = None
        self.udp_k = 0.0
        self.icmpWma = None
        self.icmp_k = 0.0

    def checkForDDoS(self):
        ddosLists = self._checkForPPS(self.tcpRules)
        if len(ddosLists) > 0:
            self.checkListsForDDoS(ddosLists)
            self.tcp_k = self.k
            self.tcpWma = self.wma
        ddosLists = self._checkForPPS(self.udpRules)
        if len(ddosLists) > 0:
            self.checkListsForDDoS(ddosLists)
            self.udp_k = self.k
            self.udpWma = self.wma
        ddosLists = self._checkForPPS(self.icmpRules)
        if len(ddosLists) > 0:
            self.checkListsForDDoS(ddosLists)
            self.icmp_k = self.k
            self.icmpWma = self.wma

    def checkListsForDDoS(self, ddosLists):
        self.varianceList = []
        i = 0
        for ddosList in ddosLists:
            self._computeMatrix(ddosList)
            self.varianceList.append(self._computeVariance())
            i = i + 1
        self._computeWMA()
        
    def printDDoSResults(self):
        if self.tcp_k < self.normalTrafficBorder and self.tcp_k < 0:
            print "There might be an tcp (D)DoS Attack."
            print str(self.packetsPerSecond) + \
                  " packets in one second from less than " + \
                  str(self.normalTrafficBorder) + " hosts."
        if self.tcpWma <= self.wmaBorder and self.tcpWma != None:
            print "There might be an tcp (D)DoS Attack. The weighted moving average is " + \
                  str(self.tcpWma) + ", which is below the given border " + \
                  str(self.wmaBorder) + "."
        if self.udp_k < self.normalTrafficBorder and self.udp_k < 0:
            print "There might be an udp (D)DoS Attack."
            print str(self.packetsPerSecond) + \
                  " packets in one second from less than " + \
                  str(self.normalTrafficBorder) + " hosts."
        if self.udpWma <= self.wmaBorder and self.udpWma != None:
            print "There might be an udp (D)DoS Attack. The weighted moving average is " + \
                  str(self.udpWma) + ", which is below the given border " + \
                  str(self.wmaBorder) + "."
        if self.icmp_k < self.normalTrafficBorder and self.icmp_k < 0:
            print "There might be an icmp (D)DoS Attack."
            print str(self.packetsPerSecond) + \
                  " packets in one second from less than " + \
                  str(self.normalTrafficBorder) + " hosts."
        if self.icmpWma <= self.wmaBorder and self.icmpWma != None:
            print "There might be an icmp (D)DoS Attack. The weighted moving average is " + \
                  str(self.icmpWma) + ", which is below the given border " + \
                  str(self.wmaBorder) + "."

    def _checkForPPS(self, ruleList):
        """Checks for packets per second"""
        i = 0
        ddosLists = []
        while i+self.packetsPerSecond < len(ruleList):
            ts1 = ruleList[i][1]
            if len(ruleList) >= self.packetsPerSecond+i:
                ts2 = ruleList[self.packetsPerSecond+i][1]
            if (ts2 - ts1) <= 1:
                ddosList = []
                for j in range(self.packetsPerSecond):
                    ddosList.append(ruleList[i+j])
                while (ts2-ts1 < 1) and (len(ruleList) > self.packetsPerSecond+i+1):
                    i = i + 1
                    tmp = ruleList[self.packetsPerSecond+i]
                    ts2 = tmp[1]
                    ddosList.append(tmp)
                ddosLists.append(ddosList)
                i = i + self.packetsPerSecond - 1
            i = i + 1
        return ddosLists

    def _computeMatrix(self, ruleList):
        self.matrix = []
        self.k = 0.0
        for i in range(self.matrixSize):
            self.matrix.insert(i, [])
            for j in range(self.matrixSize):
                self.matrix[i].insert(j, 0.0)
        for r in ruleList:
            ipParts = str(r[0]).split(".")
            i = (int(ipParts[0]) * int(ipParts[1])) % self.matrixSize
            j = (int(ipParts[2]) * int(ipParts[3])) % self.matrixSize

            tmp = self.matrix[i][j]
            if tmp == 0:
                self.k = self.k + 1.0
            self.matrix[i][j] = tmp + 1.0

    def _computeVariance(self):
        sum = 0.0
        for i in range(self.matrixSize):
            for j in range(self.matrixSize):
                sum = sum + self.matrix[i][j]

        mue = sum / self.k
        variance = 0.0
        for i in range(self.matrixSize):
            for j in range(self.matrixSize):
                if self.matrix[i][j] != 0:
                    tmp = (self.matrix[i][j] - mue) * (self.matrix[i][j] - mue)
                    variance = variance + tmp
        variance = variance / self.k
        return variance
    
    def _computeWMA(self):
        divisor = 0.0
        sum = 0.0
        for i in range(len(self.varianceList)):
            sum = sum + ((i+1.0) * self.varianceList[i])
            divisor = divisor + (i+1.0)
        self.wma = sum / divisor
