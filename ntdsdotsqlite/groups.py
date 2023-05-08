from ntdsdotsqlite.utils import get_schema_object, raw_to_sid


def group_generator(ese_db):
    group_dnt, _ = get_schema_object(ese_db, "bf967a9c-0de6-11d0-a285-00aa003049e2")
    datatable = ese_db.table("datatable")
    groups = filter(
        lambda row: (cat := row.get(ese_db.column_names["objectCategory"])) and cat == group_dnt,
        datatable.records()
    )
    for group in groups:
        yield {
            "id": group.get("DNT_col"),
            "name": group.get(ese_db.column_names["name"]),
            "cn": group.get(ese_db.column_names["cn"]),
            "samaccountname": group.get(ese_db.column_names["sAMAccountName"]),
            "SID": raw_to_sid(group.get(ese_db.column_names["objectSid"])),
            "is_deleted": group.get(ese_db.column_names["isDeleted"]) == 1,
            "description": group.get(ese_db.column_names["description"])
        }
