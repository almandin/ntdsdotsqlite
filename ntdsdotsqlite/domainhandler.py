from ntdsdotsqlite.utils import raw_to_guid, raw_to_sid
from ntdsdotsqlite.basehandler import BaseHandler
from ntdsdotsqlite.utils import escape_dn_chars
from ntdsdotsqlite.decrypt import (
    decryptAES, PEKLIST_ENC, PEKLIST_PLAIN, PEK_KEY
)
from Cryptodome.Cipher import ARC4
from struct import unpack
from hashlib import md5


class DomainHandler(BaseHandler):
    def __init__(self, sqlite_db, attributes, ese_db, bootkey):
        super().__init__(sqlite_db, attributes, ese_db)
        self.objects = []
        self.bootkey = bootkey
        self.pek = list()
        self.builtin_ids = set()

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
                self.main_domain = domain
                # extract pek if bootkey available
                if self.bootkey is not None:
                    peklist = row.get(self.attributes["pekList"])
                    encryptedPekList = PEKLIST_ENC(peklist)
                    if encryptedPekList['Header'][:4] == b'\x02\x00\x00\x00':
                        # Up to Windows 2012 R2 looks like header starts this way
                        md5h = md5()
                        md5h.update(self.bootkey)
                        for i in range(1000):
                            md5h.update(encryptedPekList['KeyMaterial'])
                        tmpKey = md5h.digest()
                        rc4 = ARC4.new(tmpKey)
                        decryptedPekList = PEKLIST_PLAIN(
                            rc4.encrypt(encryptedPekList['EncryptedPek'])
                        )
                        PEKLen = len(PEK_KEY())
                        for i in range(len(decryptedPekList['DecryptedPek']) // PEKLen):
                            cursor = i * PEKLen
                            pek = PEK_KEY(
                                decryptedPekList['DecryptedPek'][cursor:cursor+PEKLen]
                            )
                            self.pek.append(pek['Key'])

                    elif encryptedPekList['Header'][:4] == b'\x03\x00\x00\x00':
                        decryptedPekList = PEKLIST_PLAIN(
                            decryptAES(
                                self.bootkey, encryptedPekList['EncryptedPek'],
                                encryptedPekList['KeyMaterial']
                            )
                        )
                        pos, cur_index = 0, 0
                        while True:
                            pek_entry = decryptedPekList['DecryptedPek'][pos:pos+20]
                            if len(pek_entry) < 20:
                                break
                            index, pek = unpack('<L16s', pek_entry)
                            if index != cur_index:
                                break
                            self.pek.append(pek)
                            cur_index += 1
                            pos += 20

            # in any cases we add the domainDNS object
            stmt = (
                "INSERT INTO domain_dns "
                "VALUES(:id, :name, :netbios_name, :GUID, :gplink, :SID, :dn)"
            )
            self.sqlite_db.execute(stmt, domain)
            self.sqlite_db.commit()
            self.objects.append(domain)
        else:
            # Here, SID is None, meaning we are looking at a built-in root domain object like
            #   "ForestDnsZones" or "DomainDnsZones". We store their id to catch them in other
            #   classes (containers) which need them
            self.builtin_ids.add(row.get("DNT_col"))

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
