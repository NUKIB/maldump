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
    root_dir = args.root_dir
    quar_entires: list[QuarEntry] = []


    if not args.velociraptor:
        quar_entires.extend(run_in_one_root(
            root_dir, 
            args.detect_avs,
        ))
    else:
        for directory in os.listdir(root_dir):
            new_root_dir = os.path.join(root_dir, directory, 'uploads', 'auto', 'C%3A')
            if not os.path.isdir(new_root_dir):
                continue

            quar_entires.extend(run_in_one_root(
                new_root_dir, 
                args.detect_avs
            ))

    if args.quar or args.all:
        export_files(quar_entires, dest)

    if args.meta or args.all:
        export_meta(quar_entires, dest)
    
    list_files(quar_entires)

    

def run_in_one_root(root_dir, detect_avs) -> list[QuarEntry]:
    # Switch to root partition
    os.chdir(root_dir)

    logger.debug(
        'Working in directory "%s"', os.getcwd()
    )

    # Get a list of all supported or all installed avs
    avs = AVManager.detect() if detect_avs else AVManager.retrieve()

    logger.debug("Detected AVs: %s", [av.name for av in avs])

    quar_entires: list[QuarEntry] = []
    for av in avs:
        quar_entires.extend(av.export())

    return quar_entires


def export_files(
    quar_entries: list[QuarEntry], dest: Path, out_file: str = "quarantine.tar"
) -> None:
    total = 0
    if (len(quar_entries)) > 0:
        tar_path = dest.joinpath(out_file)
        tar = tarfile.open(tar_path, total and "a" or "w")
        total += len(quar_entries)
        for entry in quar_entries:
            tarinfo = tarfile.TarInfo(av.name + "/" + entry.md5)
            tarinfo.size = len(entry.malfile)
            tar.addfile(tarinfo, io.BytesIO(entry.malfile))
        tar.close()
    if total > 0:
        print(f"Exported {total} object(s) into '{out_file}'")
    else:
        print("No quarantined files found!")


def export_meta(
    quar_entries: list[QuarEntry], dest: Path, meta_file: str = "quarantine.csv"
) -> None:
    if len(quar_entries) > 0:
        csv_path = dest.joinpath(meta_file)
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            fields = [
                "timestamp",
                "antivirus",
                "threat",
                "path",
                "orig_path",
                "size",
                "md5",
                "sha1",
                "sha256",
            ]
            writer = csv.DictWriter(f, fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(vars(e) for e in quar_entries)
        print(f"Written {len(quar_entries)} row(s) into file '{meta_file}'")
    else:
        print(
            f"The file '{meta_file}' wasn't created as there is nothing in quarantine"
        )


def list_files(quar_entries: list[QuarEntry]) -> None:
    if not quar_entries:
        print("No quarantined files found!")
        return

    for e in quar_entries:
        print(e.path)


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
        action="store_true",
        help="try only avs which were detected in the system",
    )
    parser.add_argument(
        "-t",
        "--log-level",
        choices=["critical", "fatal", "error", "warn", "warning", "info", "debug"],
        default="error",
        help="log level",
    )
    parser.add_argument(
        "--velociraptor",
        action="store_true",
        help="load quarantine from velociraptor dump",
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
