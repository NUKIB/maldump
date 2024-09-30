#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import ctypes
import io
import os
import sys
import tarfile
from pathlib import Path
from typing import List

from colorama import Fore, Style, init

from maldump.av_manager import AVManager
from maldump.structures import Quarantine

__version__ = '0.4.0'


def main() -> None:

    init()
    args = parse_cli()

    # Admin privileges are required for optimal function (windows only)
    if sys.platform == 'win32' and not ctypes.windll.shell32.IsUserAnAdmin():
        print('Please try again with admin privileges')
        exit(1)

    # Save the destination directory
    dest: Path = args.dest.resolve()

    # Switch to root partition
    os.chdir(args.root_dir)

    # Get a list of all installed avs
    avs = AVManager.detect()

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
        avs: List[Quarantine],
        dest: Path,
        out_file: str = 'quarantine.tar') -> None:
    total = 0
    for av in avs:
        entries = av.export()
        if (len(entries)) > 0:
            tar_path = dest.joinpath(out_file)
            tar = tarfile.open(tar_path, total and 'a' or 'w')
            total += len(entries)
            for entry in entries:
                tarinfo = tarfile.TarInfo(av.name + '/' + entry.md5)
                tarinfo.size = len(entry.malfile)
                tar.addfile(tarinfo, io.BytesIO(entry.malfile))
            tar.close()
    if total > 0:
        print(f"Exported {total} object(s) into '{out_file}'")


def export_meta(
        avs: List[Quarantine],
        dest: Path,
        meta_file: str = 'quarantine.csv') -> None:
    entries = []
    for av in avs:
        for e in av.export():
            d = vars(e)
            d.update(antivirus=av.name)
            entries.append(d)
    if len(entries) > 0:
        csv_path = dest.joinpath(meta_file)
        with open(csv_path, 'w', encoding='utf-8', newline='') as f:
            fields = [
                'timestamp',
                'antivirus',
                'threat',
                'path',
                'size',
                'md5'
            ]
            writer = csv.DictWriter(f, fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(entries)
        print(f"Written {len(entries)} row(s) into file '{meta_file}'")


def list_files(avs: List[Quarantine]) -> None:
    for i, av in enumerate(avs):
        entries = av.export()
        if len(entries) > 0:
            if i != 0:
                print()
            print(Fore.YELLOW + '---', av.name, '---' + Style.RESET_ALL)
            for e in entries:
                print(e.path)


def parse_cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='maldump',
        formatter_class=argparse.RawTextHelpFormatter,
        description='Multi-quarantine extractor',
        epilog=(
            'Supported quarantines:\n' +
            '\n'.join(sorted(['  * ' + av.name for av in AVManager.avs]))
        )
    )

    parser.add_argument(
        'root_dir', type=Path,
        help=r'root directory where OS is installed (example C:\)'
    )
    parser.add_argument(
        '-l', '--list', action='store_true',
        help='list quarantined file(s) to stdout (default action)'
    )
    parser.add_argument(
        '-q', '--quar', action='store_true',
        help='dump quarantined file(s) to archive \'quarantine.tar\''
    )
    parser.add_argument(
        '-m', '--meta', action='store_true',
        help='dump metadata to CSV file \'quarantine.csv\''
    )
    parser.add_argument(
        '-a', '--all', action='store_true',
        help='equivalent of running both -q and -m'
    )
    parser.add_argument(
        '-v', '--version', action='version', version='%(prog)s ' + __version__
    )
    parser.add_argument(
        '-d', '--dest', type=Path,
        help='destination of (quarantine.tar/quaratine.csv)',
        default=os.getcwd()
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()
