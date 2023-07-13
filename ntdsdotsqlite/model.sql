CREATE TABLE domains (
    id INTEGER PRIMARY KEY,
    name TEXT,
    netbiosname TEXT,
    functionallevel TEXT,
    GUID TEXT,
    gplink TEXT,
    SID TEXT,
    machineAccountQuota INTEGER,
    maxPwdAge INTEGER,
    lockoutDuration INTEGER,
    minPwdLength INTEGER,
    pwdHistoryLength INTEGER,
    minPwdAge INTEGER,
    dn TEXT
);

CREATE TABLE domain_dns (
    id INTEGER PRIMARY KEY,
    name TEXT,
    netbiosname TEXT,
    GUID TEXT,
    gplink TEXT,
    SID TEXT,
    dn TEXT
);

CREATE TABLE user_accounts (
    id INTEGER PRIMARY KEY,
    encrypted_nthash BLOB,
    nthash TEXT,
    encrypted_lmhash BLOB,
    lmhash TEXT,
    UAC INTEGER,
    description TEXT,
    lastLogonTimestamp INTEGER,
    pwdlastset INTEGER,
    admincount INTEGER,
    displayName TEXT,
    GUID TEXT,
    SID TEXT,
    SPN JSON,
    domain INTEGER,
    UPN TEXT,
    login TEXT,
    samaccountname TEXT,
    commonname TEXT,
    encrypted_supplementalCredentials BLOB,
    supplementalCredentials JSON,
    encrypted_lmPwdHistory BLOB,
    lmPwdHistory JSON,
    encrypted_ntPwdHistory BLOB,
    ntPwdHistory JSON,
    accountExpires INTEGER,
    UAC_flags JSON,
    parent_OU INTEGER,
    dn TEXT,
    isDeleted BOOLEAN,
    primaryGroup INTEGER,
    memberOf JSON,
    isDisabled BOOLEAN,
    FOREIGN KEY (id) REFERENCES domains (domain),
    FOREIGN KEY (id) REFERENCES organizational_units (parent_OU),
    FOREIGN KEY (id) REFERENCES groups (primaryGroup)
);

CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    name TEXT,
    commonname TEXT,
    samaccountname TEXT,
    SID TEXT,
    domain INTEGER,
    isDeleted BOOLEAN,
    description TEXT,
    memberOf JSON,
    FOREIGN KEY (id) REFERENCES domains (domain)
);

CREATE TABLE machine_accounts (
    id INTEGER PRIMARY KEY,
    encrypted_nthash BLOB,
    nthash TEXT,
    encrypted_lmhash BLOB,
    lmhash TEXT,
    UAC INTEGER,
    description TEXT,
    lastLogonTimestamp INTEGER,
    pwdlastset INTEGER,
    admincount INTEGER,
    displayName TEXT,
    GUID TEXT,
    SID TEXT,
    SPN JSON,
    domain INTEGER,
    UPN TEXT,
    login TEXT,
    samaccountname TEXT,
    commonname TEXT,
    encrypted_supplementalCredentials BLOB,
    supplementalCredentials JSON,
    encrypted_lmPwdHistory BLOB,
    lmPwdHistory JSON,
    encrypted_ntPwdHistory BLOB,
    ntPwdHistory JSON,
    accountExpires TEXT,
    UAC_flags JSON,
    parent_OU INTEGER,
    dn TEXT,
    isDeleted BOOLEAN,
    primaryGroup INTEGER,
    isDisabled BOOLEAN,
    FOREIGN KEY (id) REFERENCES domains (domain),
    FOREIGN KEY (id) REFERENCES organizational_units (parent_OU),
    FOREIGN KEY (id) REFERENCES groups (primaryGroup)
);

CREATE TABLE organizational_units (
    id INTEGER PRIMARY KEY,
    name TEXT,
    description TEXT,
    parent INTEGER,
    dn TEXT,
    isDeleted BOOLEAN,
    domain INTEGER,
    FOREIGN KEY (id) REFERENCES organizational_units (parent),
    FOREIGN KEY (id) REFERENCES domain_dns (domain)
);

CREATE TABLE containers (
    id INTEGER PRIMARY KEY,
    name TEXT,
    description TEXT,
    commonname TEXT,
    parent INTEGER,
    dn TEXT,
    isDeleted BOOLEAN,
    domain INTEGER,
    FOREIGN KEY (id) REFERENCES domain_dns (domain)
);

CREATE TABLE trusted_domains (
    id INTEGER PRIMARY KEY,
    commonname TEXT,
    name TEXT,
    trustAttributes INTEGER,
    trustDirection TEXT,
    trustPartner TEXT,
    trustType TEXT,
    attributeFlags JSON
 );