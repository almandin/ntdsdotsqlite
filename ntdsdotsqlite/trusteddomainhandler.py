from ntdsdotsqlite.utils import raw_to_guid, raw_to_sid
from ntdsdotsqlite.basehandler import BaseHandler
from ntdsdotsqlite.utils import TRUST_FLAGS
import json


class TrustedDomainHandler(BaseHandler):
    def handle(self, row):
        sid = row.get(self.attributes["objectSid"])
        sid = raw_to_sid(sid) if sid else None,
        dnt_id = row.get("DNT_col")
        guid = row.get(self.attributes["objectGUID"])
        guid = raw_to_guid(guid) if guid else None
        commonname = row.get(self.attributes["cn"])
        name = row.get(self.attributes["name"])
        trustattributes = row.get(self.attributes["trustAttributes"])
        trustdirection = (
            "disabled" if (direction := row.get(self.attributes["trustDirection"])) == 0 else
            "inbound" if direction == 1 else
            "outbound" if direction == 2 else
            "bidirectional" if direction == 3 else
            None
        )
        trustpartner = row.get(self.attributes["trustPartner"])
        trusttype = (
            "downlevel" if (ttype := row.get(self.attributes["trustType"])) == 1 else
            "uplevel" if ttype == 2 else
            "MIT" if ttype == 3 else
            "DCE" if ttype == 4 else
            None
        )
        attribute_flags = {
            f.name: True if trustattributes & f.value else False for f in TRUST_FLAGS
        }
        trust = {
            "id": dnt_id,
            "commonname": commonname,
            "name": name,
            "trustAttributes": trustattributes,
            "attributeFlags": json.dumps(attribute_flags),
            "trustDirection": trustdirection,
            "trustPartner": trustpartner,
            "trustType": trusttype
        }
        stmt = """
            INSERT INTO trusted_domains VALUES (
            :id, :commonname, :name, :trustAttributes, :trustDirection, :trustPartner, :trustType,
            :attributeFlags
            )
        """
        self.sqlite_db.execute(stmt, trust)

    def callback(self):
        pass
