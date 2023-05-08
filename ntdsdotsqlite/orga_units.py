from ntdsdotsqlite.domain import get_domain_objects
from ntdsdotsqlite.utils import get_schema_object
from ntdsdotsqlite.utils import escape_dn_chars


def ou_generator(ese_db):
    dnt_cat, _ = get_schema_object(ese_db, "bf967aa5-0de6-11d0-a285-00aa003049e2")
    datatable = ese_db.table("datatable")
    ous = filter(
        lambda row: (cat := row.get(ese_db.column_names["objectCategory"])) and cat == dnt_cat,
        datatable.records()
    )
    ous = {
        ou.get("DNT_col"): ou for ou in ous
    }

    domain = get_domain_objects(ese_db)
    domain_id = domain["id"]
    dn_suffix = domain["dn"]
    for ou_id, ou in ous.items():
        ou_object = {
            "id": ou_id,
            "description": ou.get(ese_db.column_names["description"]),
            "name": ou.get(ese_db.column_names["name"]),
            "parent": ou.get("PDNT_col"),
            "isDeleted": ou.get(ese_db.column_names["isDeleted"]) == 1
        }
        # get the full path of the OU
        dn_prefix = "OU=" + escape_dn_chars(ou_object["name"])
        cur_object = ou
        while True:
            parent_dnt = cur_object.get("PDNT_col")
            # if $ROOT_OBJECT" is reached or the current object is not an OU anymore
            if parent_dnt == domain_id:
                break
            parent = ous[parent_dnt]
            cur_object = parent
            name = parent.get(ese_db.column_names["name"])
            dn_prefix += "," + "OU=" + escape_dn_chars(name)
        ou_object["dn"] = f"{dn_prefix},{dn_suffix}"
        yield ou_object
