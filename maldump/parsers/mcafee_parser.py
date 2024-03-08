import re
import zipfile
from datetime import datetime as dt
from hashlib import md5
from typing import List
from zipfile import ZipFile

import defusedxml.ElementTree as ET

from maldump.structures import QuarEntry


class McafeeParser():
    """XML parser"""
    _zip_password = 'infected'
    _re_xml = '[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}'

    _raw_malware = ''
    _xml_data = ''

    def from_file(self, name, location) -> List[QuarEntry]:
        self.name = name
        self.location = location
        quarfiles = []

        for metafile in self.location.glob('*.zip'):
            # parser = McafeeParser.from_file(metafile)
            parser = self._get_data(file_name=metafile)
            q = QuarEntry()
            q.timestamp = dt.strptime(parser['timestamp'], "%Y-%m-%d %H:%M:%S")
            q.threat = parser['threat']
            q.path = parser['file_name']
            q.size = int(parser['size'])
            q.md5 = md5(parser['mal_file']).digest().hex()
            q.malfile = parser['mal_file']
            quarfiles.append(q)

        return quarfiles

    def _get_data(self, file_name):
        # unzip file
        if zipfile.is_zipfile(filename=file_name):
            with ZipFile(file=file_name, mode="r") as archive:
                archive.setpassword(f'{self._zip_password}'.encode())
                for file in archive.namelist():
                    # save files to private variables
                    text = archive.read(file).decode(encoding="utf-8")
                    if re.search(self._re_xml, text) and self._xml_data == '':
                        self._xml_data = text
                    elif self._raw_malware == '' and not re.search(self._re_xml, text):
                        self._raw_malware = text
                return self._read()
        else:
            print(
                f'Error durring unziping zip file {file_name} in class {self.__name__}.')
            raise

    def _read(self):
        root = ET.fromstring(self._xml_data)
        parser = {}

        parser['timestamp'] = root.find("creationTime").text
        parser['threat'] = root.find("detectionName").text
        parser['file_name'] = root.find("Files/File/originalPath").text
        parser['size'] = root.find("Files/File/size").text
        parser['mal_file'] = bytes(self._raw_malware, 'utf-8')

        return parser
