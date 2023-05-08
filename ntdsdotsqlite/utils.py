from datetime import datetime, timedelta
from dissect.esedb import EseDB
from enum import IntFlag
from pathlib import Path
import binascii
import sqlite3
import re


# transforms a guid from raw hex byte returned by dissect to a correct GUID string
def raw_to_guid(raw):
    p1 = raw[:4][::-1].hex()
    p2 = raw[4:6][::-1].hex()
    p3 = raw[6:8][::-1].hex()
    p4 = raw[8:10].hex()
    p5 = raw[10:].hex()
    return f"{p1}-{p2}-{p3}-{p4}-{p5}"


def raw_to_sid(raw):
    rev = str(int(raw[0]))
    nb_dashes = int(raw[1])
    id_auth_value = int.from_bytes(raw[2:8], "big")
    subparts = []
    for i in range(nb_dashes):
        endianess = "big" if i == nb_dashes - 1 else "little"
        subparts.append(str(int.from_bytes(raw[8+(i*4):8+(i*4)+4], endianess)))
    return f"S-{rev}-{id_auth_value}-{'-'.join(subparts)}"


def hundredns_to_datetime(ns):
    return timedelta(seconds=ns / 10000000) + datetime(1601, 1, 1)


# Function to get attribute names from the ESE database. Gets real column names
# like "sAMAccountName" from attribute IDs like "ATTc131102". Way easier to work
# with !
# returns a 2-tuple of :
# (n, keys):
# with n beeing the number of rows in the datatable table, and
# keys the dictionary associating attribute ids and keys names:
#    {"ATTc131102": "AttributeID",  "ATTm13": "Description", ...}
def get_ESE_column_names(db_path):
    # from https://github.com/xmco/ntds_extract/tree/main/Part-2-La-Datatable
    def find_complete_record_name(complete_record_names, partial_record_name):
        for record_name in complete_record_names:
            if str(partial_record_name) == ''.join(re.findall(r'\d+', record_name)):
                return record_name

    with open(db_path, "rb") as fh:
        db = EseDB(fh)
        datatable_col_names = []
        output = {}
        attributeID = 'ATTc131102'
        lDAPDisplayName = 'ATTm131532'
        datatable = db.table("datatable")
        msysobjects = db.table("MSysObjects")
        for record in msysobjects.records():  # Look for attribute ID (column) in the datatable
            if record.Name.startswith('ATT'):
                datatable_col_names.append(record.Name)
        n = 0
        # Then, look the LDAP value corresponding to the attribute ID
        for record in datatable.records():
            n += 1
            complete_record_name = find_complete_record_name(
                datatable_col_names, record.get(attributeID)
            )
            if complete_record_name:
                output[record.get(lDAPDisplayName)] = complete_record_name
        return n, output


# Writes an initial sqlite database, with the chosen sql representation of an NTDS db.
def create_database(sqlite_path):
    # overwrite database if already existing
    f = open(sqlite_path, "w")
    f.close()
    db = sqlite3.connect(sqlite_path)
    script = open(Path(__file__).parent / "model.sql", "r").read()
    cursor = db.cursor()
    cursor.executescript(script)
    if db:
        db.close()


def ESE_cursor_next(db, table):
    cursor = db.openTable(table)
    while (row := db.getNextRow(cursor)):
        yield {
            db.column_names[k].decode("utf-8") if k in db.column_names.keys() else k: v
            for k, v in row.items() if v
        }


def get_schema_object(ese_db, schemaGuid):
    slices = [
        slice(0, 8), slice(9, 13), slice(14, 18), slice(19, 23),
        slice(24, 36)
    ]
    sguid = binascii.unhexlify(schemaGuid[slices[0]])[::-1].hex()
    sguid += binascii.unhexlify(schemaGuid[slices[1]])[::-1].hex()
    sguid += binascii.unhexlify(schemaGuid[slices[2]])[::-1].hex()
    sguid += schemaGuid[slices[3]] + schemaGuid[slices[4]]

    datatable = ese_db.table("datatable")
    for row in datatable.records():
        if (
            (guid := row.get(ese_db.column_names["schemaIDGUID"])) and
            guid.hex() == sguid
        ):
            return row.get("DNT_col"), row
    return None, None


class UAC_FLAGS(IntFlag):
    SCRIPT = 0x0001
    ACCOUNTDISABLE = 0x0002
    HOMEDIR_REQUIRED = 0x0008
    LOCKOUT = 0x0010
    PASSWD_NOTREQD = 0x0020
    PASSWD_CANT_CHANGE = 0x0040
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
    TEMP_DUPLICATE_ACCOUNT = 0x0100
    NORMAL_ACCOUNT = 0x0200
    INTERDOMAIN_TRUST_ACCOUNT = 0x0800
    WORKSTATION_TRUST_ACCOUNT = 0x1000
    SERVER_TRUST_ACCOUNT = 0x2000
    DONT_EXPIRE_PASSWORD = 0x10000
    MNS_LOGON_ACCOUNT = 0x20000
    SMARTCARD_REQUIRED = 0x40000
    TRUSTED_FOR_DELEGATION = 0x80000
    NOT_DELEGATED = 0x100000
    USE_DES_KEY_ONLY = 0x200000
    DONT_REQ_PREAUTH = 0x400000
    PASSWORD_EXPIRED = 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    PARTIAL_SECRETS_ACCOUNT = 0x04000000


def escape_dn_chars(s):
    """
    From python-ldap/Lib/ldap/dn.py
    Escape all DN special characters found in s
    with a back-slash (see RFC 4514, section 2.4)
    """
    if s:
        s = s.replace('\\', '\\\\')
        s = s.replace(',', '\\,')
        s = s.replace('+', '\\+')
        s = s.replace('"', '\\"')
        s = s.replace('<', '\\<')
        s = s.replace('>', '\\>')
        s = s.replace(';', '\\;')
        s = s.replace('=', '\\=')
        s = s.replace('\000', '\\\000')
        if s[-1] == ' ':
            s = ''.join((s[:-1], '\\ '))
        if s[0] == '#' or s[0] == ' ':
            s = ''.join(('\\', s))
    return s
