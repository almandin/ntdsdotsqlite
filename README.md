# NTDS.Sqlite

This software can be used either directly as a CLI utility or as a library to get an SQLite database from an NTDS.DIT one. Encrypted bits can be decrypted if the associated system hive is provided altogether.

# Installation

`python -m pip install ntdsdotsqlite`

# Usage

`ntdsdotsqlite NTDS.DIT --system SYSTEM -o NTDS.sqlite`

```
usage: NTDS.sqlite [-h] [--system SYSTEM] -o OUTFILE NTDS

This tool helps dumping NTDS.DIT file to an SQLite database

positional arguments:
  NTDS                  The NTDS.DIT file

optional arguments:
  -h, --help            show this help message and exit
  --system SYSTEM       The SYSTEM hive to decrypt hashes. If not provided, hashes will be encrypted inside the sqlite database.
  -o OUTFILE, --outfile OUTFILE
                        The sqlite database. Example : NTDS.sqlite
```

# SQL model

The SQL model is described in the `sql_model.md` file in this repository. Basicaly, not all objects are extracted (at all), but the following are retrieved as of today : domain object, user accounts, machine accounts, groups, organizational units and containers. I thought these would be the most useful. If you need more object classes to be extracted or additional attributes, feel free to open an issue or a pull request !

# Performances

Performances can be a bit low for huge NTDS files. The whole NTDS is not stored in memory to prevent memory exhaustion when working on huge files (NTDS databases can grow to several gigabytes).
