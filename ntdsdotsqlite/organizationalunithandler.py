from ntdsdotsqlite.basehandler import BaseHandler
from ntdsdotsqlite.utils import escape_dn_chars


class OrganizationalUnitHandler(BaseHandler):
    def handle(self, row):
        ou_object = {
            "id": row.get("DNT_col"),
            "description": row.get(self.attributes["description"]),
            "name": row.get(self.attributes["name"]),
            "parent": row.get("PDNT_col"),
            "isDeleted": row.get(self.attributes["isDeleted"]) == 1
        }
        stmt = """
            INSERT INTO organizational_units VALUES (
            :id, :name, :description, :parent, Null, :isDeleted
            )
        """
        self.sqlite_db.execute(stmt, ou_object)

    def callback(self):
        # Compute DNs
        roots = {domain_id: domain_DN for domain_id, domain_DN in self.sqlite_db.execute(
            "SELECT id, dn FROM domain_dns"
        ).fetchall()}
        ous = self.sqlite_db.execute("SELECT id, parent, name FROM organizational_units").fetchall()
        ous = {
            ou_id: {"id": ou_id, "name": name, "parent": parent}
            for ou_id, parent, name in ous
        }
        for ou_id, ou in ous.items():
            dn_prefix = "OU=" + escape_dn_chars(ou["name"])
            cur_object = ou
            while True:
                parent_dnt = cur_object["parent"]
                if parent_dnt in ous.keys():
                    parent = ous[parent_dnt]
                elif parent_dnt in roots.keys():
                    dn_prefix += ("," + roots[parent_dnt])
                    break
                else:
                    print(
                        f"Warning: could not compute DN of OU {cur_object['name']}."
                    )
                    break
                cur_object = parent
                name = parent["name"]
                dn_prefix += "," + "OU=" + escape_dn_chars(name)
            self.sqlite_db.execute(
                "UPDATE organizational_units SET dn=? WHERE id=?",
                (dn_prefix, ou_id)
            )
        self.sqlite_db.commit()
