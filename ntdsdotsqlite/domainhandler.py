from ntdsdotsqlite.utils import raw_to_guid, raw_to_sid
from ntdsdotsqlite.basehandler import BaseHandler
from ntdsdotsqlite.utils import escape_dn_chars


class DomainHandler(BaseHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.objects = []

    def handle(self, row):
        func_levels = {
            0: "2000", 2: "2003", 3: "2008", 4: "2008R2",
            5: "2012", 6: "2012R2", 7: "2016"
        }
        sid = row.get(self.attributes["objectSid"])
        if sid is not None:
            # Store the main domain object
            self.id = row.get("DNT_col")
            self.start_parent = row.get("PDNT_col")
            self.nbtname = row.get(self.attributes["name"])
            domain = {
                "PDNT_col": row.get("PDNT_col"),
                "id": row.get("DNT_col"),
                "netbios_name": row.get(self.attributes["name"]),
                "name": None,
                "GUID": raw_to_guid(row.get(self.attributes["objectGUID"])),
                "gplink": row.get(self.attributes["gPLink"]),
                "SID": raw_to_sid(sid),
                "dn": None
            }
            if row.get(self.attributes["msDS-Behavior-Version"]) is not None:
                self.domain_nbtname = row.get(self.attributes["name"])
                domain |= {
                    "functional_level": (
                        func_levels[row.get(self.attributes["msDS-Behavior-Version"])]
                    ),
                    "machineAccountQuota": row.get(self.attributes["ms-DS-MachineAccountQuota"]),
                    # max password age in seconds
                    "maxPwdAge": (
                        row.get(self.attributes["maxPwdAge"]) * -1 / 10000000
                    ),
                    # lockout duration in seconds
                    "lockoutDuration": (
                        row.get(self.attributes["lockoutDuration"]) * -1 / 10000000
                    ),
                    "minPwdLength": row.get(self.attributes["minPwdLength"]),
                    "pwdHistoryLength": row.get(self.attributes["pwdHistoryLength"]),
                    # minimum password age in seconds
                    "minPwdAge": (
                        row.get(self.attributes["minPwdAge"]) * -1 / 10000000
                    )
                }
                stmt = (
                    "INSERT INTO domains VALUES(:id, :name, :netbios_name, :functional_level, "
                    ":GUID, :gplink, :SID, :machineAccountQuota, :maxPwdAge, :lockoutDuration, "
                    ":minPwdLength, :pwdHistoryLength, :minPwdAge, :dn)"
                )
                self.sqlite_db.execute(stmt, domain)
            # in any cases we add the domainDNS object
            stmt = (
                "INSERT INTO domain_dns "
                "VALUES(:id, :name, :netbios_name, :GUID, :gplink, :SID, :dn)"
            )
            self.sqlite_db.execute(stmt, domain)
            self.sqlite_db.commit()
            self.objects.append(domain)

    def callback(self):
        for object in self.objects:
            # Get the parents from id object to $ROOT_OBJECT$ and compute DN
            # and full name
            parents = []
            cur_object = object
            datatable = self.ese_db.table("datatable")
            while True:
                parent_dnt = cur_object.get("PDNT_col")
                if parent_dnt == 2:  # $ROOT_OBJECT$
                    break
                for row in datatable.records():
                    if row.get("DNT_col") == parent_dnt:
                        parents.append(row)
                        cur_object = row
                        break
            parent_names = [
                row.get(self.attributes["name"]) for row in parents
            ]
            names = [object["netbios_name"]] + parent_names
            dn = "DC=" + ",DC=".join([escape_dn_chars(name) for name in names])
            name = ".".join(names)
            self.sqlite_db.execute(
                "UPDATE domain_dns SET dn=?, name=? WHERE id=?",
                (dn, name, object["id"])
            )
            if self.domain_nbtname == object["netbios_name"]:
                self.sqlite_db.execute(
                    "UPDATE domains SET name=?, dn=?", (name, dn)
                )
                self.sqlite_db.commit()
        self.sqlite_db.commit()
