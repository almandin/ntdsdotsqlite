class BaseHandler:
    def __init__(self, sqlite_db, attributes, ese_db):
        self.sqlite_db = sqlite_db
        self.attributes = attributes
        self.ese_db = ese_db

    # Called each time a row is seen with the right objectCategory
    def handle(row):
        raise NotImplementedError()

    # Called after the NTDS is parsed
    def callback(self):
        pass
