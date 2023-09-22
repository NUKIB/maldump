Welcome to the Maldump project, and thank you for your interest in contributing to Maldump. This document will briefly explain how the project and workflow works. Please read the whole document so you have a clear picture of how everything is set up.

You can join our community [discord](https://discord.gg/VYZADbrm) server to get in touch with all the funs and devs of Maldump.

# Project structure

* [maldump](torch) - The Maldump root directory containing the main function handles all the operations. Also, the types and utils are located here.
  * [avs](maldump/avs) - Classes handle all the essential AV-related tasks.
  * [parsers](maldump/parsers) - Parser for every AV class.
    * [kaitai](maldump/parsers/kaitai) - Subfolder for parsers using kaitai.
* [test](test) - This directory stores all the important data used to test Maldump functionality.
  * [root](test/root) - This directory represents the root of the target system (Currently supporting only Windows).

# Code style

Linter and type checking are prepared to keep the codebase healthy.

## Argument convention

There should always be an extended version name, e.g.: "--dest" and an optional short version, e.g.: "-d".

# Development

Here are some tips for developing on Windows (+ WSL 2). Download and install the VS code from the official web page(https://code.visualstudio.com/). Run VS code and install the following extensions:

  -  Python - Python extension for Visual Studio Code
  -  Flake8 - Flake8 extension for Visual Studio Code
  -  WSL - Visual Studio Code WSL
  -  Remote Development - Visual Studio Code Remote Development Extension Pack
  -  Python Auto Venv - Python Auto Venv (Archived)

## Set up the environment in the WSL: Debian

```sh
# clone repo
git clone git@github.com:<your-fork>.git

# install requirements
pip install -r requirements.txt
pip install -r requirements-dev.txt

# start maldump
python3 -m maldump
```

## Testing

```sh
# to run tests:
python3 -m unittest

# to check typing:
mypy maldump

# to check code style:
flake8 . --show-source --statistics

# to check imports:
isort . --check --diff
```

## Reversing AV quarantine format

Use [eicar.com](https://www.eicar.org/download-anti-malware-testfile/) together with [RegShot](https://github.com/Seabreg/Regshot) in virtual enviroment. [CyberChef](https://gchq.github.io/CyberChef/) might be handy for the analysis too.

# Contributing

To contribute to this project, create new issue depending on the type.

Changes should be prepared in a separate branch with a reasonable name.

1. Fork this repository.
2. Create a branch: `git checkout -b <branch_name>`
3. Make your changes and commit them: `git commit -m '<commit_message>'`
4. Push to the original branch: `git push origin <project_name/location>`
5. Create a pull request linked to the issue.

# Hall of fame

| name | value |
| --- | --- |
| [@Jezdo0](https://github.com/Jezdo0) | Developer |
| [@JohnyBembel](https://github.com/JohnyBembel) | Lead developer |
| [@knez](https://www.github.com/knez) | Lead developer |
