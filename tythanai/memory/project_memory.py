class ProjectMemory:
    """
    Lightweight project memory abstraction.
    """

    def __init__(self):
        self.memory = []

    def remember(self, item):
        self.memory.append(item)

    def recall(self):
        return self.memory