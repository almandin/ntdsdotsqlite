from ntdsdotsqlite.utils import get_schema_object, raw_to_guid, raw_to_sid
from ntdsdotsqlite.utils import TRUST_FLAGS
import json


# yields dictionaries representing accounts (users or machines) based
# on the schema_guid (string) given in parameters.
def trust_generator(ese_db):
    dnt_cat, _ = get_schema_object(ese_db, "bf967ab8-0de6-11d0-a285-00aa003049e2")
    datatable = ese_db.table("datatable")

    trusts = filter(
        lambda row: row.get(ese_db.column_names["objectCategory"]) == dnt_cat,
        datatable.records()
    )
    for trust in trusts:
        sid = trust.get(ese_db.column_names["objectSid"])
        sid = raw_to_sid(sid) if sid else None,
        dnt_id = trust.get("DNT_col")
        guid = trust.get(ese_db.column_names["objectGUID"])
        guid = raw_to_guid(guid) if guid else None
        commonname = trust.get(ese_db.column_names["cn"])
        name = trust.get(ese_db.column_names["name"])
        trustattributes = trust.get(ese_db.column_names["trustAttributes"])
        trustdirection = (
            "disabled" if (direction := trust.get(ese_db.column_names["trustDirection"])) == 0 else
            "inbound" if direction == 1 else
            "outbound" if direction == 2 else
            "bidirectional" if direction == 3 else
            None
        )
        trustpartner = trust.get(ese_db.column_names["trustPartner"])
        trusttype = (
            "downlevel" if (ttype := trust.get(ese_db.column_names["trustType"])) == 1 else
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
        yield trust
