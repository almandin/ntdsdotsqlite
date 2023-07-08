# SQL Model

# Generalities

Every record in the database has a unique identifier (`id` column). These identifiers are unique database wide, not because they are generated but because they are directly extracted from the NTDS database.

A few choices of data representation are made to make them more easily accessible. For example, dates and duration are represented in seconds or Unix Epoch timestamps, instead of the Microsoft standard representation (number of intervals of 100 nanoseconds elapsed since 1601 😠).

All of the columns can be `NULL` when no data was availabe or to represent the absence of something (example: Null for password last set attribute meaning the password was never set).

If a SYSTEM hive is provided, data will be decrypted. The encrypted version of the associated columns are kept under columns with the `_encrypted_` prefix in their name. These columns are not present if no decryptions has occured.

## Table `domains`

This table only has one record representing the domain object (object class `Domain-DNS`), it has the following columns:

- `id` (INTEGER): The identifier of the object in the NTDS database (Example: 2042).
- `name` (TEXT): The full name of the domain (Example: 'windomain.local').
- `netbiosname` (TEXT): The NBT Name of the domain (Example: 'WINDOMAIN')
- `functionallevel` (TEXT): The functional level of the domain, on of the following values: `2000`, `2003`, `2008`, `2008R2`, `2012`, `2012R2` or `2016`.
- `GUID` (TEXT): The GUID of the domain (Ex. '822850bc-e868-4e83-bbb1-9f8fcde73355').
- `gplink` (TEXT): The GPLink attribute of the domain.
- `SID` (TEXT): The SID of the domain (Ex. 'S-1-5-21-2834339972-2568791593-173547513').
- `machineAccountQuota` (INTEGER): The machine-account-quota attribute of the domain (Ex. 10).
- `maxPwdAge` (INTEGER): The maxPwdAge attribute of the domain, **in seconds** (Ex. 3628800).
- `lockoutDuration` (INTEGER): The lockout-duration attribute of the domain **in seconds** (Ex. 60).
- `minPwdLength` (INTEGER): The minimum password length of the domain object (Ex. 7).
- `pwdHistoryLength` (INTEGER): The password history length of the domain objects (Ex. 24).
- `minPwdAge` (INTEGER): The minPwdAge attribute of the domain **in seconds** (Ex. 86400).
- `dn` (TEXT): The distinguished name of the domain (Ex. 'DC=windomain,DC=local')

## Table `domain_dns`

This table contains all `domainDNS` records, not only the one representing the main domain. It has information in common with the `domain` table, but it contains every DNS zone, not only the main.

- `id` (INTEGER): The identifier of the object in the NTDS database (Ex. 2042).
- - `name` (TEXT): The full name of the domain zone (Example: 'windomain.local').
- `netbiosname` (TEXT): The NBT Name of the domain zone (Example: 'WINDOMAIN')
- `GUID` (TEXT): The GUID of the domain zone (Ex. '822850bc-e868-4e83-bbb1-9f8fcde73355').
- `gplink` (TEXT): The GPLink attribute of the domain zone.
- `SID` (TEXT): The SID of the domain zone (Ex. 'S-1-5-21-2834339972-2568791593-173547513').
- `dn` (TEXT): The distinguished name of the domain zone (Ex. 'DC=windomain,DC=local')

## Table `user_accounts`

This table stores user accounts (object class `Person`). It has the following columns:

- `id` (INTEGER): The identifier of the object in the NTDS databse (Ex. 2042).
- `nthash` (BLOB or TEXT): The NT Hash (NTLM hash) of the account as a string if the SYSTEM hive is provided or the encrypted BLOB representing it (Ex. '31d6cfe0d16ae931b73c59d7e0c089c0' or binary data...).
- `lmhash` (BLOB or TEXT): The LM hash of the account as a string if the SYSTEM hive is provided or the encrypted BLOB representing it (Ex. 'aad3b435b51404eeaad3b435b51404ee' or binary data...).)
- `UAC` (INTEGER): The user account control value as an integer (Ex. 4260352).
- `description` (TEXT): The description of the account (Ex. 'Built-in account for guest access to the computer/domain').
- `lastLogonTimestamp` (INTEGER): Timestamp **as a datetime representation** of the last time the account was used.
- `pwdlastset` (INTEGER): Timestamp **as a datetime representation** of the last time the password was set for this account.
- `admincount` (INTEGER): The admin-count attribute of the object (Example: 0). 
- `displayName` (TEXT): The display name of the account. 
- `GUID` (TEXT): The GUID of the object (Ex. 'b5c2765f-024a-47a7-b0d4-18b8783d54ed')
- `SID` (TEXT): The SID of the account (Ex. 'S-1-5-21-2834339972-2568791593-173547513-502')
- `SPN` (JSON): The list of service principal names of the account. This list is represented as a valid JSON list (Ex. `["https/HREWLPT1000004", "kafka/TSTWAPPS1000000"]`)
- `domain` (INTEGER): A foreign key to the associated domain object.
- `UPN` (TEXT): The user principal name of the account (Ex. 'FOO_BAR@windomain.local').
- `login` (TEXT): The login of the account. It is either the left part of the UPN if it has one, or the samaccountname (Ex. 'FOO_BAR').
- `samaccountname` (TEXT): The Sam Account Name of the account (Ex. 'FOO_BAR').
- `commonname` (TEXT): The common name of the account (Ex. 'FOO_BAR').
- `supplementalCredentials` (BLOB or JSON): Either an encrypted BLOB or a decrypted JSON list representing additional credentials stored in the object. These are mainly kerberos keys, or plaintext credentials when the flag `store password with reversible encryption` is set. It is a list of 2-tuples containing the type of key it represents, and the associated value.
    - Example: `[["aes256-cts-hmac-sha1-96", "2fbb870186116974c53a0a8ed472bdd78c277305e7174f540ce3239340a8f33f"], ["aes128-cts-hmac-sha1-96", "a62b241a5e02eef50503ce5efd7728f1"], ["des-cbc-md5", "badfa8e9cd0ee5ba"], ["cleartext", "hunter2"]]`.
- `lmPwdHistory` (BLOB or JSON): Either an encrypted blob or a JSON list representing the history of LM hashes of the account.
    - Example: `["db6aaf42a0a9aa7818ab94e45e093787", "9216c6bb1c679145c44870b8ace24e98"]`
- `ntPwdHistory` (BLOB or JSON): Either an encrypted blob or a JSON list representing the history of NT hashes of the account.
    - Example: `["4e9f909d3a0fe9b1a7c726f882573635", "32ebda198689b00ca142d270f7759f0d"]`
- `accountExpires` (INTEGER): The date at which the account expires **as a datetime object representation**.
- `UAC_flags` (JSON): A JSON object containing the value of each user account control flag.
    - Example: `{"SCRIPT": false, "ACCOUNTDISABLE": false, "HOMEDIR_REQUIRED": false, "LOCKOUT": false, "PASSWD_NOTREQD": false, "PASSWD_CANT_CHANGE": false, "ENCRYPTED_TEXT_PWD_ALLOWED": false, "TEMP_DUPLICATE_ACCOUNT": false, "NORMAL_ACCOUNT": true, "INTERDOMAIN_TRUST_ACCOUNT": false, "WORKSTATION_TRUST_ACCOUNT": false, "SERVER_TRUST_ACCOUNT": false, "DONT_EXPIRE_PASSWORD": true, "MNS_LOGON_ACCOUNT": false, "SMARTCARD_REQUIRED": false, "TRUSTED_FOR_DELEGATION": false, "NOT_DELEGATED": false, "USE_DES_KEY_ONLY": false, "DONT_REQ_PREAUTH": true, "PASSWORD_EXPIRED": false, "TRUSTED_TO_AUTH_FOR_DELEGATION": false, "PARTIAL_SECRETS_ACCOUNT": false}`
- `parent_OU` (INTEGER): The organizational unit this account is in, as a INTEGER foreign key to the `organizational_units` table.
- `dn` (TEXT): The distinguished name of the account. Example: 'CN=john,CN=Users,DC=windomain,DC=local'.
- `isDeleted` (BOOLEAN): A boolean to indicate if this object has been deleted and is in the recycle bin.
- `primaryGroup` (INTEGER): The primary group of this account as an INTEGER foreign key to the `groups` table.
- `memberOf` (JSON): A JSON list of group identifiers in the `groups` table this account is member of. Ex. [4033, 4088, 4089, 4091, 4094]
- `isDisabled` (BOOLEAN): A shortcut to know wether the account is disabled or not (based on the user account control).

## Table `machine_accounts`

This table stores machine accounts information (object class `Computer`).

The columns are the exact same as the `user_accounts` table, it is just used to set them appart more easily when using the database.

## Table `groups`

This table store groups information (object class `Group`). It has the following columns:

- `id` (INTEGER): The identifier of the group object in the NTDS database (Ex. 2042).
- `name` (TEXT): The name of the group (Ex. 'Remote Desktop Users').
- `commonname` (TEXT): The common name of the group (Ex. 'Remote Desktop Users').
- `samaccountname` (TEXT): The Sam Account Name of the group (Ex. 'Remote Desktop Users').
- `SID` (TEXT): The security identifier of the group. Ex. 'S-1-5-21-2834339972-2568791593-173547513-512'.
- `domain` (INTEGER): The related domain object as a foreign key in the `domains` table.
- `isDeleted` (BOOLEAN): A boolean to tell wether this object has been deleted and is in the recycle bin.
- `description` (TEXT): The description of the group object.
- `memberOf` (JSON): A list of other groups identifiers describing group membership. Ex: `[5133, 5213]`.

## Table `organizational_units`

A table storing organizational units information (object class `Organization-Unit`). It has the following columns:

- `id` (INTEGER): The object identifier in the NTDS database.
- `name` (TEXT): The name of the OU.
- `description` (TEXT): The description of the OU.
- `commonname` (TEXT): The common name of the OU.
- `parent` (INTEGER): The identifier of the OU in which this one is in.
- `dn` (TEXT): The distinguished name of the OU (Ex. 'OU=ServiceAccounts,OU=BDE,OU=Tier 1,DC=windomain,DC=local').
- `isDeleted` (BOOLEAN): A boolean to tell wether this object has been removed and is in the recycle bin.

## Table `trusted_domains`

A table to store information about trusted domains (object class `Trusted-Domain`). It has the following columns:

- `id` (INTEGER): The object identifier in the NTDS database.
- `commonname` (TEXT): The common name of the related other domain.
- `name` (TEXT): The "name" of the related other domain (not sure how it should be different from the common name 🤷).
- `trustAttributes` (INTEGER): The value of the Trust-Attributes attribute.
- `trustDirection` (TEXT): The direction of the trust relation, either `disabled` if the trust relation is disabled, `inbound`, `outbound` or `bidirectional`.
- `trustPartner` (TEXT): The full domain name of the related trust domain (just like cn and name but trustPartner is supposed to hold the entire domain name).
- `trustType` (TEXT): The type of the trust, either `downlevel`, `uplevel`, `MIT` or `DCE` (See the [Microsoft Documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/36565693-b5e4-4f37-b0a8-c1b12138e18e) for more details).
- `attributeFlags` (JSON): A dictionary of attribute flags held in the the `trustAttributes` integer, but parsed to be easily accessed (contains information about transitivity for example).

## Table ???

The process of adding object classes and attributes is quite straightforward if these are not complex references to other intricate stuff. If you need something else which is not retrieved yet, open an issue or a PR ! There is basically one python file for each object class parsed. Objects are retrieved based on their class name directly ! The full list is available in the Microsoft documentation [here](https://learn.microsoft.com/en-us/windows/win32/adschema/classes).