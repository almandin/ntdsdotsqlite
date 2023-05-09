from datetime import datetime, timedelta
from enum import IntFlag
from pathlib import Path
import binascii
import sqlite3


# transforms a guid from raw hex byte returned by dissect to a correct GUID string
def raw_to_guid(raw):
    p1 = raw[:4][::-1].hex()
    p2 = raw[4:6][::-1].hex()
    p3 = raw[6:8][::-1].hex()
    p4 = raw[8:10].hex()
    p5 = raw[10:].hex()
    return f"{p1}-{p2}-{p3}-{p4}-{p5}"


# Transforms raw bytes returned by dessect to a correct SID string
def raw_to_sid(raw):
    rev = str(int(raw[0]))
    nb_dashes = int(raw[1])
    id_auth_value = int.from_bytes(raw[2:8], "big")
    subparts = []
    for i in range(nb_dashes):
        endianess = "big" if i == nb_dashes - 1 else "little"
        subparts.append(str(int.from_bytes(raw[8+(i*4):8+(i*4)+4], endianess)))
    return f"S-{rev}-{id_auth_value}-{'-'.join(subparts)}"


# Translates microsoft duration/datetime format (intervals of 100ns) to python datetime object
def hundredns_to_datetime(ns):
    return timedelta(seconds=ns / 10000000) + datetime(1601, 1, 1)


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


# Returns the object in the database representing a schema object of the chosen schema GUID.
# Its main use is to get its DNT that will be used by all subsequent objects as an objectCategory.
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


# Extracted from python-ldap/Lib/ldap/dn.py, in order to remove one dependency
# that would need to be compiled otherwise.
def escape_dn_chars(s):
    """
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
