from ntdsdotsqlite.utils import get_schema_object, raw_to_guid, raw_to_sid
from ntdsdotsqlite.utils import escape_dn_chars


def get_domain_objects(ese_db):
    datatable = ese_db.table("datatable")
    # Locate the ID of the domainDNS schema object
    domainDNS_dnt, _ = get_schema_object(ese_db, "19195a5b-6da0-11d0-afd3-00c04fd930c9")
    if domainDNS_dnt is None:
        print("no domainDNS object ...")
        exit(1)
    domain_object = None
    for row in datatable.records():
        if (
            (object_category := row.get(ese_db.column_names["objectCategory"])) and
            object_category == domainDNS_dnt and
            row.get(ese_db.column_names["msDS-Behavior-Version"])
        ):
            domain_object = row
            # We only need the first object that represents the main domain
            break
    # go up in the tree to get the full domain name
    cur_object = domain_object
    parents = []
    while True:
        # If we got back to the root object (guid '00'*16, name='$ROOT_OBJECT$\u0000'), break
        parent_dnt = cur_object.get("PDNT_col")
        if parent_dnt == 2:
            break
        for row in datatable.records():
            if row.get("DNT_col") == parent_dnt:
                parents.append(row)
                cur_object = row
                break
    func_levels = {
        0: "2000", 2: "2003", 3: "2008", 4: "2008R2",
        5: "2012", 6: "2012R2", 7: "2016"
    }
    domain = {
        "id": domain_object.get("DNT_col"),
        "netbios_name": domain_object.get(ese_db.column_names["name"]),
        "name": ".".join([x.get(ese_db.column_names["name"]) for x in [domain_object, *parents]]),
        "parents": parents,
        "functional_level": (
            func_levels[domain_object.get(ese_db.column_names["msDS-Behavior-Version"])]
        ),
        "GUID": raw_to_guid(domain_object.get(ese_db.column_names["objectGUID"])),
        "gplink": domain_object.get(ese_db.column_names["gPLink"]),
        "SID": raw_to_sid(domain_object.get(ese_db.column_names["objectSid"])),
        "machineAccountQuota": domain_object.get(ese_db.column_names["ms-DS-MachineAccountQuota"]),
        # max password age in seconds
        "maxPwdAge": (
            domain_object.get(ese_db.column_names["maxPwdAge"]) * -1 / 10000000
        ),
        # lockout duration in seconds
        "lockoutDuration": (
            domain_object.get(ese_db.column_names["lockoutDuration"]) * -1 / 10000000
        ),
        "minPwdLength": domain_object.get(ese_db.column_names["minPwdLength"]),
        "pwdHistoryLength": domain_object.get(ese_db.column_names["pwdHistoryLength"]),
        # minimum password age in seconds
        "minPwdAge": (
            domain_object.get(ese_db.column_names["minPwdAge"]) * -1 / 10000000
        ),
        "dn": "DC=" + ",DC=".join(
            [
                escape_dn_chars(x.get(ese_db.column_names["name"]))
                for x in [domain_object, *parents]
            ]
        )
    }
    return domain
