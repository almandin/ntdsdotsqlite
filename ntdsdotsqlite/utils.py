from datetime import datetime, timedelta
from collections import defaultdict
from enum import IntFlag
from pathlib import Path
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


class TRUST_FLAGS(IntFlag):
    NON_TRANSITIVE = 0x1
    UPLEVEL_ONLY = 0x2
    QUARANTINED_DOMAIN = 0x4
    FOREST_TRANSITIVE = 0x8
    CROSS_ORGANIZATION = 0x10
    WITHIN_FOREST = 0x20
    TREAT_AS_EXTERNAL = 0x40
    USES_RC4_ENCRYPTION = 0x80
    CROSS_ORGANIZATION_NO_TGT_DELEGATION = 0x200
    PIM_TRUST = 0x400


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


def compute_links(ese_db):
    links = ese_db.table("link_table")
    relations = defaultdict(list)
    for link in links.records():
        flink = link.get("link_DNT")
        blink = link.get("backlink_DNT")
        relations[blink].append(flink)
    return relations
