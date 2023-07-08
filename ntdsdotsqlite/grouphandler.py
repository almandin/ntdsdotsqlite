from ntdsdotsqlite.utils import raw_to_sid
from ntdsdotsqlite.basehandler import BaseHandler
import json


class GroupHandler(BaseHandler):
    def __init__(self, links, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.links = links

    def handle(self, row):
        group = {
            "id": row.get("DNT_col"),
            "name": row.get(self.attributes["name"]),
            "cn": row.get(self.attributes["cn"]),
            "samaccountname": row.get(self.attributes["sAMAccountName"]),
            "SID": raw_to_sid(row.get(self.attributes["objectSid"])),
            "is_deleted": row.get(self.attributes["isDeleted"]) == 1,
            "description": row.get(self.attributes["description"])
        }
        stmt = """
            INSERT INTO groups VALUES (
            :id, :name, :cn, :samaccountname, :SID, NULL,
            :is_deleted, :description, ""
            )
        """
        self.sqlite_db.execute(stmt, group)

    def callback(self):
        # Set the domain column
        self.sqlite_db.execute("UPDATE groups SET domain=(SELECT id FROM domains LIMIT 1);")
        self.sqlite_db.commit()
        # Handle groups memberships with themselves
        for row in self.sqlite_db.execute("SELECT id FROM groups"):
            memberOf = []
            new_cur = self.sqlite_db.cursor()
            for link in self.links[row[0]]:
                res = new_cur.execute(f"SELECT id FROM groups WHERE id={link}")
                res = res.fetchone()
                if res is not None:
                    memberOf.append(link)
            new_cur.execute(
                "UPDATE groups SET memberOf=? WHERE id=?", (json.dumps(memberOf), row[0])
            )
        self.sqlite_db.commit()
