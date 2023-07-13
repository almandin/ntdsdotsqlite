from ntdsdotsqlite.decrypt import decrypt_hash, decrypt_history, decryptSupplementalInfo
from ntdsdotsqlite.utils import hundredns_to_datetime, UAC_FLAGS
from ntdsdotsqlite.utils import raw_to_guid, raw_to_sid
from ntdsdotsqlite.basehandler import BaseHandler
from ntdsdotsqlite.utils import escape_dn_chars
import json


class PersonHandler(BaseHandler):
    def __init__(self, links, sqlite_db, attributes, ese_db, dh):
        super().__init__(sqlite_db, attributes, ese_db)
        self.should_decrypt = dh.bootkey is not None
        self.peklist = dh.pek
        self.links = links
        self.could_not_decrypt_yet = list()

    def handle(self, row):
        lastLogonTimestamp = row.get(self.attributes["lastLogonTimestamp"])
        pwdlastset = row.get(self.attributes["pwdLastSet"])
        if pwdlastset:
            pwdlastset = hundredns_to_datetime(pwdlastset)
        if lastLogonTimestamp:
            lastLogonTimestamp = hundredns_to_datetime(lastLogonTimestamp)
        admincount = row.get(self.attributes["adminCount"])
        if admincount is None:
            admincount = 0
        spn = row.get(self.attributes["servicePrincipalName"])
        accountExpires = row.get(self.attributes["accountExpires"])
        if accountExpires:
            if accountExpires and accountExpires == 0 or accountExpires == 0x7FFFFFFFFFFFFFFF:
                accountExpires = 0
            else:
                accountExpires = hundredns_to_datetime(accountExpires)
        uac = row.get(self.attributes["userAccountControl"])
        sid = row.get(self.attributes["objectSid"])
        guid = row.get(self.attributes["objectGUID"])
        account = {
            "id": row.get("DNT_col"), "description": row.get(self.attributes["description"]),
            "UAC": uac,
            "SID": raw_to_sid(sid) if sid else None,
            "samaccountname": row.get(self.attributes["sAMAccountName"]),
            # unix epoch or NULL if password never set
            "pwdLastSet": pwdlastset,
            "encrypted_nthash": row.get(self.attributes["unicodePwd"]),
            "nthash": None,
            "commonname": row.get(self.attributes["cn"]),
            "GUID": raw_to_guid(guid) if guid else None,
            "adminCount": admincount,
            "displayName": row.get(self.attributes["displayName"]),
            "UPN": row.get(self.attributes["userPrincipalName"]),
            "encrypted_supplementalCredentials": (
                row.get(self.attributes["supplementalCredentials"])
            ),
            "supplementalCredentials": None,
            # unix epoch
            "lastLogonTimestamp": lastLogonTimestamp,
            "encrypted_lmPwdHistory": row.get(self.attributes["lmPwdHistory"]),
            "lmPwdHistory": None,
            "encrypted_ntPwdHistory": row.get(self.attributes["ntPwdHistory"]),
            "ntPwdHistory": None,
            "accountExpires": accountExpires,
            "SPN": spn,
            "encrypted_lmhash": row.get(self.attributes["dBCSPwd"]),
            "lmhash": None,
            "parent": row.get("PDNT_col"),
            "isDeleted": row.get(self.attributes["isDeleted"]) == 1,
            "primaryGroup": row.get(self.attributes["primaryGroupID"])
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
        if self.should_decrypt:
            try:
                account["nthash"] = decrypt_hash(self.peklist, account, "nt")
                account["lmhash"] = decrypt_hash(self.peklist, account, "lm")
                account["lmPwdHistory"] = json.dumps(decrypt_history(self.peklist, account, "lm"))
                account["ntPwdHistory"] = json.dumps(decrypt_history(self.peklist, account, "nt"))
                account["supplementalCredentials"] = json.dumps(
                    decryptSupplementalInfo(self.peklist, account)
                )
            except IndexError:
                self.could_not_decrypt_yet.append(account)
        stmt = """
            INSERT INTO user_accounts VALUES (
            :id, :encrypted_nthash, :nthash, :encrypted_lmhash, :lmhash, :UAC, :description,
            :lastLogonTimestamp, :pwdLastSet, :adminCount, :displayName, :GUID, :SID, :SPN,
            Null, :UPN, :login, :samaccountname, :commonname, :encrypted_supplementalCredentials,
            :supplementalCredentials, :encrypted_lmPwdHistory, :lmPwdHistory,
            :encrypted_ntPwdHistory, :ntPwdHistory, :accountExpires, :uac_flags, :parent, Null,
            :isDeleted, :primaryGroup, Null, :isDisabled
            )
        """
        self.sqlite_db.execute(stmt, account)

    def callback(self):
        ous = {
            oid: {"dn": dn, "domain": odid}
            for oid, dn, odid in self.sqlite_db.execute(
                "SELECT id, dn, domain FROM organizational_units"
            )
        }
        users = self.sqlite_db.execute(
            "SELECT id, commonname, parent_OU, primaryGroup FROM user_accounts"
        )
        containers = {
            cid: {"dn": cdn, "domain": cdid}
            for (cid, cdn, cdid) in self.sqlite_db.execute("SELECT id, dn, domain FROM containers")
        }
        domains = {
            did: ddn for (did, ddn) in self.sqlite_db.execute("SELECT id, dn FROM domain_dns")
        }
        group_ids = [x[0] for x in self.sqlite_db.execute("SELECT id FROM groups").fetchall()]
        for uid, cn, parent_OU, primaryGroup in users:
            # Compute DN
            if parent_OU in ous.keys():
                dn = f"CN={escape_dn_chars(cn)},{ous[parent_OU]['dn']}"
                domain_id = ous[parent_OU]["domain"]
            elif parent_OU in containers.keys():
                curdn = containers[parent_OU]['dn']
                dn = f"CN={escape_dn_chars(cn)},{curdn}"
                domain_id = containers[parent_OU]["domain"]
            elif parent_OU in domains.keys():
                dn = f"CN={escape_dn_chars(cn)},{domains[parent_OU]}"
                # Sets the domain ID to this "OU" ID since its the ID of the root domainDNS object
                # in which this user is.
                domain_id = parent_OU
            else:
                print(f"Warning: could not compute DN of user {cn}")
            links_list = self.links[uid]
            memberof = json.dumps([link for link in links_list if link in group_ids])
            self.sqlite_db.execute(
                "UPDATE user_accounts set domain=?, memberOf=?, primaryGroup=("
                f"SELECT id from groups WHERE SID LIKE '%-{primaryGroup}'"
                "), dn=? WHERE id=?",
                (domain_id, memberof, dn, uid)
            )
        # Decrypt users we could not decrypt previously
        for account in self.could_not_decrypt_yet:
            account["nthash"] = decrypt_hash(self.peklist, account, "nt")
            account["lmhash"] = decrypt_hash(self.peklist, account, "lm")
            account["lmPwdHistory"] = decrypt_history(self.peklist, account, "lm")
            account["ntPwdHistory"] = decrypt_history(self.peklist, account, "nt")
            account["supplementalCredentials"] = decryptSupplementalInfo(self.peklist, account)
            self.sqlite_db.execute(
                "UPDATE user_accounts set nthash=?, lmhash=?, ntPwdHistory=?, lmPwdHistory=?, "
                "supplementalCredentials=? WHERE id=?",
                (
                    account["nthash"], account["lmhash"], json.dumps(account["ntPwdHistory"]),
                    json.dumps(account["lmPwdHistory"]),
                    json.dumps(account["supplementalCredentials"]), account["id"]
                )
            )
