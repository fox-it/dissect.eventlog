class KeyValueCollection(dict):
    def __init__(self):
        super().__init__()
        self.idx = {}

    def __setitem__(self, key, value):
        if key in self.idx:
            self.idx[key] += 1
            key = f"{key}_{self.idx[key]}"
        else:
            self.idx[key] = 0

        dict.__setitem__(self, key, value)
