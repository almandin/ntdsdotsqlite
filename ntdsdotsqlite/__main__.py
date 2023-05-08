from pathlib import Path
import argparse


from ntdsdotsqlite.ntdsdotsqlite import run

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="NTDS.sqlite",
        description=(
            "This tool helps dumping NTDS.DIT file to an SQLite database"
        )
    )
    parser.add_argument("NTDS", help="The NTDS.DIT file", type=Path)
    parser.add_argument(
        "--system", required=False,
        help=(
            "The SYSTEM hive to decrypt hashes. If not provided, hashes will "
            "be encrypted inside the sqlite database."
        )
    )
    parser.add_argument(
        "-o", "--outfile", required=True,
        help="The sqlite database. Example : NTDS.sqlite"
    )
    args = parser.parse_args()
    run(args.NTDS, args.outfile, args.system)
