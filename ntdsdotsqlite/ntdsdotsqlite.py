from ntdsdotsqlite.organizationalunithandler import OrganizationalUnitHandler
from ntdsdotsqlite.trusteddomainhandler import TrustedDomainHandler
from ntdsdotsqlite.utils import create_database, compute_links
from ntdsdotsqlite.containerhandler import ContainerHandler
from ntdsdotsqlite.computerhandler import ComputerHandler
from ntdsdotsqlite.personhandler import PersonHandler
from ntdsdotsqlite.domainhandler import DomainHandler
from ntdsdotsqlite.grouphandler import GroupHandler
from ntdsdotsqlite.decrypt import getBootKey
from collections import OrderedDict
from dissect.esedb import EseDB
from tqdm import tqdm
import sqlite3
import re


def run(ese_path, outpath, system_path, quiet=False):
    create_database(outpath)
    sqlite_db = sqlite3.connect(outpath)
    fd = open(ese_path, "rb")
    ese_db = EseDB(fd)
    # Getting column names and base initialization stuff
    attribute_dnt = None
    class_dnt = None
    # attributes_raw : {131532: "ATTm131532"}
    attributes_raw = {}
    # attributes: {"displayName": "ATTm131532"}
    attributes = {}
    # classes: {"person": 1511}
    classes = {}
    link_relations = compute_links(ese_db)
    # catch the bootkey in the SYSTEM hive if any
    bootkey = getBootKey(system_path) if system_path else None
    # each class instance here are used to handle the addition of new objects in the sqlite
    # these classes should have a handle(row) method and a callback() method. They are instantiated
    # with the sqlite_db handle and the colnames dictionary. handle(row) is called live when a row
    # is caught with the class set in key of this dictionary, the callback method is called after
    # the ntds has been read entirely.
    # This dict can be ordered to choose in which order the callbacks will be called !
    dh = DomainHandler(sqlite_db, attributes, ese_db, bootkey)
    caught_classes = OrderedDict({
        "domainDNS": dh,
        "trustedDomain": TrustedDomainHandler(sqlite_db, attributes, ese_db),
        "group": GroupHandler(link_relations, sqlite_db, attributes, ese_db),
        "container": ContainerHandler(sqlite_db, attributes, ese_db),
        "organizationalUnit": OrganizationalUnitHandler(sqlite_db, attributes, ese_db),
        "person": PersonHandler(link_relations, sqlite_db, attributes, ese_db, dh),
        "computer": ComputerHandler(sqlite_db, attributes, ese_db, dh)
    })
    # "direct access" classes : {1511: SpecificHandler(...)}
    da_classes = {}
    attributeID_attr = "ATTc131102"
    schemaGuid_attr = "ATTk589972"
    lDAPDisplayName_attr = "ATTm131532"
    objectCategory_attr = "ATTb590606"
    attributeSchema_sguid = b"\x80\x7a\x96\xbf\xe6\x0d\xd0\x11\xa2\x85\x00\xaa\x00\x30\x49\xe2"
    classSchema_sguid = b"\x83\x7a\x96\xbf\xe6\x0d\xd0\x11\xa2\x85\x00\xaa\x00\x30\x49\xe2"
    d_reg = re.compile(r"(\d+$)")
    msysobjects = ese_db.table("MSysObjects")
    for row in msysobjects.records():
        if (name := row.Name).startswith('ATT'):
            res = d_reg.search(name)
            attributes_raw[name[res.start():]] = name
    datatable = ese_db.table("datatable")
    cnt = 0
    for row in datatable.records():
        cnt += 1
    datatable = ese_db.table("datatable")
    for row in datatable.records():
        sguid = row.get(schemaGuid_attr)
        if sguid is not None and sguid == attributeSchema_sguid:
            attribute_dnt = row.get("DNT_col")
        if sguid is not None and sguid == classSchema_sguid:
            class_dnt = row.get("DNT_col")
        if attribute_dnt is not None and class_dnt is not None:
            break
    tmp_rows = []

    store_tmp = True
    for row in (tqdm(datatable.records(), total=cnt) if not quiet else datatable.records()):
        obj_category = row.get(objectCategory_attr)
        # if the row is an attribute name :
        if obj_category == attribute_dnt:
            try:
                # match it with its value/raw name in msysobject and store it for later
                attributes[row.get(lDAPDisplayName_attr)] = (
                    attributes_raw[str(row.get(attributeID_attr))]
                )
            except KeyError:
                # Here an "AttributeSchema" object has been seen with an attributeID which is not
                # in the MSYSobjects table...
                pass
        # if the row is a class name :
        if obj_category == class_dnt:
            # store its DNT to use it later and match it against objectCategory attribute
            class_name = row.get(lDAPDisplayName_attr)
            dnt = row.get("DNT_col")
            classes[class_name] = dnt
            # if this class happens to be in the caught classes list, we keep a secondary
            # index for later use with O(1) instead of O(len(caught_classes.keys()))
            if class_name in caught_classes.keys():
                da_classes[dnt] = caught_classes[class_name]
                if len(da_classes.keys()) == len(caught_classes.keys()):
                    store_tmp = False
        # trigger the handle method of the associated handler if it exists
        try:
            da_classes[obj_category].handle(row)
        except KeyError:
            if store_tmp:
                tmp_rows.append(row)
    # manage the first "few" rows we saw when classes and attributes were not set up yet
    for row in filter(lambda r: r.get(attributes["objectCategory"]) in da_classes.keys(), tmp_rows):
        obj_category = row.get(objectCategory_attr)
        da_classes[obj_category].handle(row)
    sqlite_db.commit()
    # Trigger callbacks for all caught classes
    for _, obj in caught_classes.items():
        obj.callback()
        sqlite_db.commit()
    if sqlite_db:
        sqlite_db.close()
    fd.close()
