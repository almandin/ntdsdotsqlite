from ntdsdotsqlite.basehandler import BaseHandler
from ntdsdotsqlite.utils import escape_dn_chars


class ContainerHandler(BaseHandler):
    def __init__(self, domainhandler, sqlite_db, attributes, ese_db):
        super().__init__(sqlite_db, attributes, ese_db)
        self.__domainhandler = domainhandler

    def handle(self, row):
        container = {
            "id": row.get("DNT_col"),
            "name": row.get(self.attributes["name"]),
            "cn": row.get(self.attributes["cn"]),
            "description": row.get(self.attributes["description"]),
            "parent": row.get("PDNT_col"),
            "is_deleted": row.get(self.attributes["isDeleted"]) == 1
        }
        stmt = """
            INSERT INTO containers VALUES (
            :id, :name, :description, :cn, :parent, Null, :is_deleted, Null
            )
        """
        self.sqlite_db.execute(stmt, container)

    def callback(self):
        # compute DNs
        roots = {domain_id: domain_DN for domain_id, domain_DN in self.sqlite_db.execute(
            "SELECT id, dn FROM domain_dns"
        ).fetchall()}
        containers = {
            c_id: {"id": c_id, "name": name, "parent": parent, "cn": cn, "domain": None}
            for c_id, name, parent, cn in self.sqlite_db.execute(
                "SELECT id, name, parent, commonname FROM containers"
            ).fetchall()
        }
        for container in containers.values():
            cur_object = container
            parts = [f"CN={escape_dn_chars(cur_object['cn'])}"]
            domain_id = None
            while True:
                if cur_object["parent"] in containers.keys():
                    cur_object = containers[cur_object["parent"]]
                    parts.append(f"CN={escape_dn_chars(cur_object['cn'])}")
                elif cur_object["parent"] in roots.keys():
                    parts.append(roots[cur_object["parent"]])
                    domain_id = cur_object["parent"]
                    break
                elif cur_object["parent"] in self.__domainhandler.builtin_ids:
                    domain_id = self.__domainhandler.main_domain["id"]
                    break
                else:
                    break
            container["dn"] = ",".join(parts)
            if ",DC=" not in container["dn"]:
                container["dn"] = ""
            self.sqlite_db.execute(
                "UPDATE containers SET dn=?, domain=? WHERE id=?",
                (container["dn"], domain_id, container["id"])
            )
        self.sqlite_db.commit()
