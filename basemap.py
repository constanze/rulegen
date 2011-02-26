class BaseMap:
    """BaseMap is a dictionary. 
       The keys are the hashes of the values."""
    
    def __init__(self):
        self.innerMap = {} 
        self.separator = "\n"
        self.classinfo = BaseMap
        self.hashValue = 0
        self.isAny = False

    def insert(self, item):

        if hash(item) not in self.innerMap.keys():
            self.innerMap[hash(item)] = item
            self.hashValue = self._computeHash()
        else:
            if item != self[hash(item)]:
                print "Collision:"
                print "Wanted to insert: %s" % item
                print "Collided with: %s " % self[hash(item)]

    def extend(self, otherMap):
        for item in otherMap:
            self.insert(item)

    def remove(self, item):
        self.innerMap.pop(hash(item))
        self.hashValue = self._computeHash()
        if len(self) == 0:
            self.isAny = False

    def sort(self):
        self.innerMap = sorted(self.innerMap)

    def keys(self):
        return self.innerMap.keys()

    def values(self):
        return self.innerMap.values()

    def clear(self):
        self.hashValue = 0
        self.isAny = False
        self.innerMap.clear()

    def __str__(self):
        baseMap = self.values()
        baseMap.sort()
        return self.separator.join(["%s" % item for item in baseMap]) 

    def __iter__(self):
        return self.innerMap.itervalues()

    def __len__(self):
        return len(self.innerMap)

    def __hash__(self):
        return self.hashValue

    def __eq__(self, other):
        if not isinstance(other, self.classinfo):
            return False
        if self.isAny or other.isAny:
            return True
        if len(self) != len(other):
            return False
        for key in self.innerMap.iterkeys():
            if not key in other.keys():
                return False
        return True

    def __ne__(self, other):
        return not self == other

    def __getitem__(self, key):
        return self.innerMap[key]

    def _computeHash(self):
        hashvalue = 0
        keys = self.innerMap.keys()
        for key in keys:
            hashvalue = hashvalue + key
        return hashvalue 
