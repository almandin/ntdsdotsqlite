from ntdsdotsqlite.utils import get_schema_object
from ntdsdotsqlite.utils import escape_dn_chars


def containers_generator(ese_db, sqlite_db):
    dnt_cat, _ = get_schema_object(ese_db, "bf967a8b-0de6-11d0-a285-00aa003049e2")
    datatable = ese_db.table("datatable")
    containers = filter(
        lambda row: (cat := row.get(ese_db.column_names["objectCategory"])) and cat == dnt_cat,
        datatable.records()
    )
    containers = {
        row.get("DNT_col"): {
            "id": row.get("DNT_col"),
            "name": row.get(ese_db.column_names["name"]),
            "cn": row.get(ese_db.column_names["cn"]),
            "description": row.get(ese_db.column_names["description"]),
            "parent": row.get("PDNT_col"),
            "is_deleted": row.get(ese_db.column_names["isDeleted"]) == 1
        } for row in containers
    }
    cur = sqlite_db.cursor()
    res = cur.execute("SELECT id, dn FROM domains")
    domain_id, domain_DN = res.fetchone()
    for _, container in containers.items():
        cur_object = container
        parts = [f"CN={escape_dn_chars(cur_object['cn'])}"]
        while cur_object["parent"] != domain_id and cur_object["parent"] in containers.keys():
            cur_object = containers[cur_object["parent"]]
            parts.append(f"CN={escape_dn_chars(cur_object['cn'])}")
        container["dn"] = ",".join([*parts, domain_DN])

    yield from containers.values()
