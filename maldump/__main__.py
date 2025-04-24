#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import ctypes
import getpass
import io
import logging
import os
import sys
import tarfile
from pathlib import Path
from typing import TYPE_CHECKING

from colorama import Fore, Style, init

from maldump.av_manager import AVManager

if TYPE_CHECKING:
    from maldump.structures import Quarantine

__version__ = "0.5.0"
logger = logging.getLogger(__name__)


def main() -> None:
    init()
    args = parse_cli()
    init_logging(args.log_level)

    # Admin privileges are required for optimal function (windows only)
    if sys.platform == "win32" and not ctypes.windll.shell32.IsUserAnAdmin():
        logger.critical(
            "The program executed on Windows machine without proper privileges"
        )
        print("Please try again with admin privileges")
        sys.exit(1)

    # Save the destination directory
    dest: Path = args.dest.resolve()

    # Switch to root partition
    os.chdir(args.root_dir)

    logger.debug(
        'Working in directory "%s", files would be stored into "%s"', os.getcwd(), dest
    )

    # Get a list of all supported or all installed avs
    avs = AVManager.detect() if args.detect_avs else AVManager.retrieve()

    logger.debug("Detected AVs: %s", [av.name for av in avs])

    if args.quar:
        export_files(avs, dest)
    elif args.meta:
        export_meta(avs, dest)
    elif args.all:
        export_files(avs, dest)
        export_meta(avs, dest)
    else:
        list_files(avs)


def export_files(
    avs: list[Quarantine], dest: Path, out_file: str = "quarantine.tar"
) -> None:
    total = 0
    for av in avs:
        entries = av.export()
        if (len(entries)) > 0:
            tar_path = dest.joinpath(out_file)
            tar = tarfile.open(tar_path, total and "a" or "w")
            total += len(entries)
            for entry in entries:
                tarinfo = tarfile.TarInfo(av.name + "/" + entry.md5)
                tarinfo.size = len(entry.malfile)
                tar.addfile(tarinfo, io.BytesIO(entry.malfile))
            tar.close()
    if total > 0:
        print(f"Exported {total} object(s) into '{out_file}'")
    else:
        print("No quarantined files found!")


def export_meta(
    avs: list[Quarantine], dest: Path, meta_file: str = "quarantine.csv"
) -> None:
    entries = []
    for av in avs:
        for e in av.export():
            d = vars(e)
            d.update(antivirus=av.name)
            entries.append(d)
    if len(entries) > 0:
        csv_path = dest.joinpath(meta_file)
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            fields = [
                "timestamp",
                "antivirus",
                "threat",
                "path",
                "size",
                "md5",
                "sha1",
                "sha256",
            ]
            writer = csv.DictWriter(f, fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(entries)
        print(f"Written {len(entries)} row(s) into file '{meta_file}'")
    else:
        print(
            f"The file '{meta_file}' wasn't created as there is nothing in quarantine"
        )


def list_files(avs: list[Quarantine]) -> None:
    quarantined_file_exists = False
    for i, av in enumerate(avs):
        entries = av.export()
        if len(entries) > 0:
            quarantined_file_exists = True
            if i != 0:
                print()
            print(Fore.YELLOW + "---", av.name, "---" + Style.RESET_ALL)
            for e in entries:
                print(e.path)
    if not quarantined_file_exists:
        print("No quarantined files found!")


def parse_cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="maldump",
        formatter_class=argparse.RawTextHelpFormatter,
        description="Multi-quarantine extractor",
        epilog=(
            "Supported quarantines:\n"
            + "\n".join(sorted(["  * " + av.name for av in AVManager.avs]))
        ),
    )

    parser.add_argument(
        "root_dir",
        type=Path,
        help=r"root directory where OS is installed (example C:\)",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="list quarantined file(s) to stdout (default action)",
    )
    parser.add_argument(
        "-q",
        "--quar",
        action="store_true",
        help="dump quarantined file(s) to archive 'quarantine.tar'",
    )
    parser.add_argument(
        "-m",
        "--meta",
        action="store_true",
        help="dump metadata to CSV file 'quarantine.csv'",
    )
    parser.add_argument(
        "-a", "--all", action="store_true", help="equivalent of running both -q and -m"
    )
    parser.add_argument(
        "-c",
        "--detect-avs",
        action="store_false",
        help="try only avs which were detected in the system",
    )
    parser.add_argument(
        "-t",
        "--log-level",
        choices=["critical", "fatal", "error", "warn", "warning", "info", "debug"],
        default="warning",
        help="log level",
    )
    parser.add_argument(
        "-v", "--version", action="version", version="%(prog)s " + __version__
    )
    parser.add_argument(
        "-d",
        "--dest",
        type=Path,
        help="destination of (quarantine.tar/quaratine.csv)",
        default=os.getcwd(),
    )

    return parser.parse_args()


def init_logging(log_level: str) -> None:
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError("Invalid log level: " + log_level)  # noqa: TRY004
    logging.basicConfig(
        handlers=[
            # logging.FileHandler("syslog.log", mode="w", encoding="utf-8"),
            logging.StreamHandler(sys.stderr)
        ],
        level=numeric_level,
        format="%(asctime)s:%(levelname)s:%(name)s:%(module)s:%(message)s",
    )
    logger.debug("Logging started, logger initialized successfully")
    logger.info("Logging as user %s", getpass.getuser())


if __name__ == "__main__":
    main()
