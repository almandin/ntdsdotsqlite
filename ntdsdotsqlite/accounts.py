from ntdsdotsqlite.utils import get_schema_object, raw_to_guid, raw_to_sid
from ntdsdotsqlite.utils import hundredns_to_datetime, UAC_FLAGS
from ntdsdotsqlite.utils import escape_dn_chars
import json


# yields dictionaries representing accounts (users or machines) based
# on the schema_guid (string) given in parameters.
def account_generator(ese_db, schema_guid, sqlite_db, relations):
    dnt_cat, _ = get_schema_object(ese_db, schema_guid)
    datatable = ese_db.table("datatable")

    accounts = filter(
        lambda row: (cat := row.get(ese_db.column_names["objectCategory"])) and cat == dnt_cat,
        datatable.records()
    )
    for a in accounts:
        lastLogonTimestamp = a.get(ese_db.column_names["lastLogonTimestamp"])
        pwdlastset = a.get(ese_db.column_names["pwdLastSet"])
        if pwdlastset:
            pwdlastset = hundredns_to_datetime(pwdlastset)
        if lastLogonTimestamp:
            lastLogonTimestamp = hundredns_to_datetime(lastLogonTimestamp)
        admincount = a.get(ese_db.column_names["adminCount"])
        if admincount is None:
            admincount = 0
        spn = a.get(ese_db.column_names["servicePrincipalName"])
        accountExpires = a.get(ese_db.column_names["accountExpires"])
        if accountExpires:
            if accountExpires and accountExpires == 0 or accountExpires == 0x7FFFFFFFFFFFFFFF:
                accountExpires = 0
            else:
                accountExpires = hundredns_to_datetime(accountExpires)
        uac = a.get(ese_db.column_names["userAccountControl"])
        sid = a.get(ese_db.column_names["objectSid"])
        guid = a.get(ese_db.column_names["objectGUID"])
        account = {
            "id": a.get("DNT_col"), "description": a.get(ese_db.column_names["description"]),
            "UAC": uac,
            "SID": raw_to_sid(sid) if sid else None,
            "samaccountname": a.get(ese_db.column_names["sAMAccountName"]),
            # unix epoch or NULL if password never set
            "pwdLastSet": pwdlastset,
            "nthash": a.get(ese_db.column_names["unicodePwd"]),
            "commonname": a.get(ese_db.column_names["cn"]),
            "GUID": raw_to_guid(guid) if guid else None,
            "adminCount": admincount,
            "displayName": a.get(ese_db.column_names["displayName"]),
            "UPN": a.get(ese_db.column_names["userPrincipalName"]),
            "supplementalCredentials": a.get(ese_db.column_names["supplementalCredentials"]),
            # unix epoch
            "lastLogonTimestamp": lastLogonTimestamp,
            "lmPwdHistory": a.get(ese_db.column_names["lmPwdHistory"]),
            "ntPwdHistory": a.get(ese_db.column_names["ntPwdHistory"]),
            "accountExpires": accountExpires,
            "SPN": spn,
            "lmhash": a.get(ese_db.column_names["dBCSPwd"]),
            "parent": a.get("PDNT_col"),
            "isDeleted": a.get(ese_db.column_names["isDeleted"]) == 1
        }
        account["login"] = (
            account["UPN"].split("@")[0] if account["UPN"]
            else account["samaccountname"]
        )
        if (spn := account["SPN"]):
            if type(spn) is str:
                account["SPN"] = json.dumps([spn])
            elif type(spn) is list:
                account["SPN"] = json.dumps(spn)
            else:
                print(f"SPN type unknown : {spn} - {type(spn)}")
                print(account)
                exit(1)
        if uac:
            uac_flags = {
                k.name: True if uac & k.value else False for k in UAC_FLAGS
            }
            account["uac_flags"] = json.dumps(uac_flags)
            account["isDisabled"] = uac_flags["ACCOUNTDISABLE"]
        else:
            account["uac_flags"] = None
            account["isDisabled"] = None
        # Generate Distinguished Name
        cur = sqlite_db.cursor()
        parent_dnt = a.get("PDNT_col")
        res = cur.execute(f"SELECT dn FROM organizational_units WHERE id={parent_dnt}")
        res = res.fetchone()
        if res is None:
            res = cur.execute(f"SELECT dn FROM containers WHERE id={parent_dnt}")
            res = res.fetchone()
        if res:
            account["dn"] = "CN=" + escape_dn_chars(account["commonname"]) + "," + res[0]
        else:
            print(f"Warning: The DN for the account {account['commonname']} could not be computed")
            account["dn"] = None
        primaryGroup = a.get(ese_db.column_names["primaryGroupID"])
        if primaryGroup:
            res = cur.execute(f"SELECT id, SID from groups WHERE SID LIKE '%-{primaryGroup}'")
            res = res.fetchone()
            account["primaryGroup"] = res[0]
        else:
            account["primaryGroup"] = None
        # manage groups membership
        links_list = relations[account["id"]]
        account["links"] = json.dumps(links_list)
        account["memberOf"] = []
        for link in links_list:
            res = cur.execute(f"SELECT id FROM groups WHERE id={link}")
            res = res.fetchone()
            if res is not None:
                account["memberOf"].append(link)
        account["memberOf"] = json.dumps(account["memberOf"])
        yield account
