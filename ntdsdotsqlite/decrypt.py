from ntdsdotsqlite import secretsdump
import json


def decrypt_sqlite(sqlite_db, ntds_path, system_hive_path):
    local_operations = secretsdump.LocalOperations(system_hive_path)

    dumper = secretsdump.NTDSHashes(ntds_path, local_operations.getBootKey())
    cur = sqlite_db.cursor()
    cur.execute("ALTER TABLE user_accounts RENAME COLUMN nthash TO _encrypted_nthash")
    cur.execute("ALTER TABLE user_accounts RENAME COLUMN lmhash TO _encrypted_lmhash")
    cur.execute("ALTER TABLE user_accounts RENAME COLUMN lmPwdHistory TO _encrypted_lmPwdHistory")
    cur.execute("ALTER TABLE user_accounts RENAME COLUMN ntPwdHistory TO _encrypted_ntPwdHistory")
    cur.execute(
        "ALTER TABLE user_accounts RENAME COLUMN supplementalCredentials TO "
        "_encrypted_supplementalCredentials"
    )
    cur.execute("ALTER TABLE machine_accounts RENAME COLUMN nthash TO _encrypted_nthash")
    cur.execute("ALTER TABLE machine_accounts RENAME COLUMN lmhash TO _encrypted_lmhash")
    cur.execute(
        "ALTER TABLE machine_accounts RENAME COLUMN lmPwdHistory TO _encrypted_lmPwdHistory"
    )
    cur.execute(
        "ALTER TABLE machine_accounts RENAME COLUMN ntPwdHistory TO _encrypted_ntPwdHistory"
    )
    cur.execute(
        "ALTER TABLE machine_accounts RENAME COLUMN supplementalCredentials TO "
        "_encrypted_supplementalCredentials"
    )
    sqlite_db.commit()
    cur.execute("ALTER TABLE user_accounts ADD COLUMN nthash TEXT")
    cur.execute("ALTER TABLE user_accounts ADD COLUMN lmhash TEXT")
    cur.execute("ALTER TABLE user_accounts ADD COLUMN lmPwdHistory TEXT")
    cur.execute("ALTER TABLE user_accounts ADD COLUMN ntPwdHistory TEXT")
    cur.execute("ALTER TABLE user_accounts ADD COLUMN supplementalCredentials JSON")
    cur.execute("ALTER TABLE machine_accounts ADD COLUMN nthash TEXT")
    cur.execute("ALTER TABLE machine_accounts ADD COLUMN lmhash TEXT")
    cur.execute("ALTER TABLE machine_accounts ADD COLUMN lmPwdHistory TEXT")
    cur.execute("ALTER TABLE machine_accounts ADD COLUMN ntPwdHistory TEXT")
    cur.execute("ALTER TABLE machine_accounts ADD COLUMN supplementalCredentials JSON")
    sqlite_db.commit()
    for result in dumper.dump():
        # result :
        # {
        #   'username': 'TESTCOMPUTER$',
        #   'guid': 'd6ec4c6e-ecc2-4774-a068-9732b6bc4a58',
        #   'lmhash': 'aad3b435b51404eeaad3b435b51404ee',
        #   'nthash': 'c1653d2f7b46f97ea64453820add3f8a',
        #   'lmhistory': ['95e9dfa765098631fadb7a01acca7c7a', '8cdcaa8af553362e6631ab6c2ebbb9fd'],
        #   'nthistory': ['c1653d2f7b46f97ea64453820add3f8a', '7334e9d326b556d863040fa9d186426c'],
        #   'supplemental_credentials': [
        #       (
        #           'aes256-cts-hmac-sha1-96',
        #           '9e14bb28a510db728ce168fe3271a31dce8438cd623ad67f161f87f8053c70c3'
        #       ),
        #       ('aes128-cts-hmac-sha1-96', '071d2a973d5acb8ebd60eff7af5d1fdb'),
        #       ('des-cbc-md5', '04b3e0c12f8620fb')
        #   ]
        # }
        result["supplemental_credentials"] = json.dumps(result["supplemental_credentials"])
        result["lmhistory"] = json.dumps(result["lmhistory"])
        result["nthistory"] = json.dumps(result["nthistory"])
        cur.execute(
            "UPDATE user_accounts SET nthash = :nthash, "
            "lmhash = :lmhash, "
            "supplementalCredentials = :supplemental_credentials, "
            "lmPwdHistory = :lmhistory, "
            "ntPwdHistory = :nthistory "
            "WHERE GUID = :guid",
            result
        )
        # If no row has been updated, it was a machine account
        if cur.rowcount == 0:
            cur.execute(
                "UPDATE machine_accounts SET nthash = :nthash, "
                "lmhash = :lmhash, "
                "supplementalCredentials = :supplemental_credentials, "
                "lmPwdHistory = :lmhistory, "
                "ntPwdHistory = :nthistory "
                "WHERE GUID = :guid",
                result
            )
    sqlite_db.commit()
    dumper.finish()
