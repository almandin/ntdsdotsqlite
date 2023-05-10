from ntdsdotsqlite.utils import create_database, get_ESE_column_names
from ntdsdotsqlite.containers import containers_generator
from ntdsdotsqlite.accounts import account_generator
from ntdsdotsqlite.domain import get_domain_objects
from ntdsdotsqlite.orga_units import ou_generator
from ntdsdotsqlite.decrypt import decrypt_sqlite
from ntdsdotsqlite.groups import group_generator
from ntdsdotsqlite.links import compute_links
from dissect.esedb import EseDB
import sqlite3
import json


def run(ese_path, outpath, system_path):
    create_database(outpath)
    sqlite_db = sqlite3.connect(outpath)
    fd = open(ese_path, "rb")
    ese_db = EseDB(fd)
    cursor = sqlite_db.cursor()
    # Getting column names
    column_names = get_ESE_column_names(ese_db)
    ese_db.column_names = column_names
    # Compute links
    print("Retrieving and storing links information ...")
    link_relations = compute_links(ese_db)
    # Get the domain
    print("Retrieving the domain object ...")
    domain = get_domain_objects(ese_db)
    # Insert the domain record
    stmt = (
        "INSERT INTO domains VALUES(:id, :name, :netbios_name, :functional_level, :GUID, :gplink,"
        ":SID, :machineAccountQuota, :maxPwdAge, :lockoutDuration, :minPwdLength, :pwdHistoryLength"
        ", :minPwdAge, :dn)"
    )
    cursor.execute(stmt, domain)
    sqlite_db.commit()
    # Insert container objects
    print("Retrieving containers objects ...")
    stmt = """
        INSERT INTO containers VALUES (
        :id, :name, :description, :cn, :parent, :dn, :is_deleted
        )
    """
    cursor.executemany(stmt, containers_generator(ese_db, sqlite_db))
    sqlite_db.commit()
    # Insert ou objects records
    stmt = """
        INSERT INTO organizational_units VALUES (
        :id, :name, :description, :parent, :dn, :isDeleted
        )
    """
    print("Retrieving organizational units objects ...")
    cursor.executemany(stmt, ou_generator(ese_db))
    sqlite_db.commit()
    # Insert group objects
    print("Retrieving groups objects ...")
    stmt = f"""
        INSERT INTO groups VALUES (
        :id, :name, :cn, :samaccountname, :SID, {domain['id']},
        :is_deleted, :description, ""
        )
    """
    cursor.executemany(stmt, group_generator(ese_db))
    sqlite_db.commit()
    # # Handle groups memberships with themselves
    for row in cursor.execute("SELECT id FROM groups"):
        memberOf = []
        new_cur = sqlite_db.cursor()
        for link in link_relations[row[0]]:
            res = new_cur.execute(f"SELECT id FROM groups WHERE id={link}")
            res = res.fetchone()
            if res is not None:
                memberOf.append(link)
        new_cur.execute(
            "UPDATE groups SET memberOf=? WHERE id=?", (json.dumps(memberOf), row[0])
        )
    sqlite_db.commit()
    # Insert all user account records
    print("Retrieving user accounts objects ...")
    accounts_iter = account_generator(
        ese_db, "bf967aa7-0de6-11d0-a285-00aa003049e2",
        sqlite_db, link_relations
    )
    stmt = f"""
        INSERT INTO user_accounts VALUES (
        :id, :nthash, :lmhash, :UAC, :description, :lastLogonTimestamp,
        :pwdLastSet, :adminCount, :displayName, :GUID, :SID, :SPN,
        {domain['id']}, :UPN, :login, :samaccountname, :commonname,
        :supplementalCredentials, :lmPwdHistory, :ntPwdHistory, :accountExpires,
        :uac_flags, :parent, :dn, :isDeleted, :primaryGroup,
        :memberOf, :links, :isDisabled
        )
    """
    cursor.executemany(stmt, accounts_iter)
    sqlite_db.commit()
    # Insert all machine account records
    print("Retrieving machine accounts objects ...")
    machines_iter = account_generator(
        ese_db, "bf967a86-0de6-11d0-a285-00aa003049e2",
        sqlite_db, link_relations
    )
    stmt = f"""
        INSERT INTO machine_accounts VALUES (
        :id, :nthash, :lmhash, :UAC, :description, :lastLogonTimestamp,
        :pwdLastSet, :adminCount, :displayName, :GUID, :SID, :SPN,
        {domain['id']}, :UPN, :login, :samaccountname, :commonname,
        :supplementalCredentials, :lmPwdHistory, :ntPwdHistory, :accountExpires,
        :uac_flags, :parent, :dn, :isDeleted, :primaryGroup, :links,
        :isDisabled
        )
    """
    cursor.executemany(stmt, machines_iter)
    sqlite_db.commit()
    if system_path:
        print("Decrypting stuff with SYSTEM hive ...")
        decrypt_sqlite(sqlite_db, ese_path, system_path)
    if sqlite_db:
        sqlite_db.close()
    fd.close()
