class KeyValueCollection(dict):
    """A dictionary subclass that handles setting duplicate keys by appending an index number to the duplicate key.

    Example:

        >>>  d = KeyValueCollection()
        >>>  d["foo"] = "bar"
        >>>  d["foo"] = "baz"  # Duplicate key
        >>>  d
        {'foo': 'bar', 'foo_1': 'baz'}
    """

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
