class Port:
    """This class represents a port."""

    def __init__(self, nr, source=False):
        self.randomized = False
        if (nr < -1 or nr > 65535):
            raise ValueError("The port number must be an integer value \
                              between 0 and 65535 or -1 for any.")
        if source and nr >= 1024:
             nr = 65535
             self.randomized = True
        self.portNumber = nr

    def __str__(self):
        return str(self.portNumber) if not self.randomized else "random"

    def __eq__(self, other):
        if not isinstance(other, Port):
            return False
        if other.portNumber == -1 or self.portNumber == -1:
            return True
        if other.portNumber == self.portNumber:
            return True
        return False

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return self.portNumber
    
    def __cmp__(self, other):
        return self.portNumber - other.portNumber

    def __lt__(self, other):
        return self.portNumber < other.portNumber

    def __le__(self, other):
        return self.portNumber <= other.portNumber

    def __gt__(self, other):
        return self.portNumber > other.portNumber

    def __ge__(self, other):
        return self.portNumber >= other.portNumber

    def __sub__(self, other):
        return self.portNumber - other.portNumber

    def __add__(self, other):
        return self.portNumber + other.portNumber
