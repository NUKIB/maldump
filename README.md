# maldump

[![](https://img.shields.io/badge/Category-Applications%20in%20Python-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Language-Python-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Version-0.2.0-E5A505?style=flat-square&color=green)]()

Maldump makes it easy to extract quarantined files of multiple AVs from a live system or a mounted disk image.

## Features

Supports extraction from the following AV products

  * Avast Antivirus
  * Avira Antivirus
  * Eset NOD32
  * FortiClient
  * G Data
  * Kaspersky for Windows Server
  * Malwarebytes
  * Microsoft Defender

## Installation

Using pip (Recommended)

```bash
$ pip install maldump
```

Or alternatively using git and Virtual Environment

```
$ git clone https://github.com/NUKIB/maldump
$ cd maldump
```

Create new environment and activate it

```
$ python3 -m venv venv
$ . venv/bin/activate
```

Install dependencies

```
(env) $ pip install -r requirements.txt
```

Run it as a module

```
(env) $ python3 -m maldump
```

## Usage

```
usage: maldump [-h] [-l] [-q] [-m] [-a] [-v] root_dir

Multi-quarantine extractor

positional arguments:
  root_dir       root directory where OS is installed (example C:\)

optional arguments:
  -h, --help     show this help message and exit
  -l, --list     list quarantined file(s) to stdout (default action)
  -q, --quar     dump quarantined file(s) to archive 'quarantine.tar'
  -m, --meta     dump metadata to CSV file 'quarantine.csv'
  -a, --all      equivalent of running both -q and -m
  -v, --version  show program's version number and exit     
```

## Examples

### On Windows

List quarantine files located on disk C

```
$ maldump C:\
```

Dump quarantine files from disk C into archive `quarantine.tar`

```
$ maldump C:\ --quar
```

Export quarantine metadata from disk C into `quarantine.csv`

```
$ maldump C:\ --meta
```

Export both files and metadata from a mounted disk F

```
$ maldump F:\ --all
```

### On Linux

List quarantine files from a windows partition mounted on `/mnt/win`

```
$ maldump /mnt/win
```

## Disclaimer

Keep in mind, all timestamps are in UTC **except** for "Kaspersky for Windows Server" which stores timestamps in a local timezone.

For optimal results, admin privileges are required when running on Windows system. Linux does not require admin rights.


## Contributing

To contribute to this project, follow these steps:

1. Fork this repository.
2. Create a branch: `git checkout -b <branch_name>`
3. Make your changes and commit them: `git commit -m '<commit_message>'`
4. Push to the original branch: `git push origin <project_name/location>`
5. Create a pull request.

## License

This software is licensed under GNU General Public License version 3.

* Copyright (C) 2022 [National Cyber and Information Security Agency of the Czech Republic (NÚKIB)](https://www.nukib.cz/en/)
