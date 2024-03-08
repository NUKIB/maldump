'''
EsetLogParser: Python script for parsing ESET (NOD32) virlog.dat file.
Copyright (C) 2017 Ladislav Baco
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''


import binascii
import struct
import sys
from datetime import datetime
from hashlib import md5
from pathlib import Path
from typing import List

from maldump.structures import QuarEntry

__author__ = 'Ladislav Baco'
__copyright__ = 'Copyright (C) 2017'
__credits__ = 'Ladislav Baco'
__license__ = 'GPLv3'
__version__ = '0.2.1'
__maintainer__ = 'Ladislav Baco'
__status__ = 'Development'

TIMEFORMAT = '%Y-%m-%d %H:%M:%S'
NULL = b'\x00\x00'
RECORD_HEADER = b'\x24\x00\x00\x00\x01\x00\x01\x00'
OBJECT_HEADER = b'\xbe\x0b\x4e\x00'
INFILTRATION_HEADER = b'\x4d\x1d\x4e\x00'
USER_HEADER = b'\xee\x03\x4e\x00'
VIRUSDB_HEADER = b'\x17\x27\x4e\x00'
PROGNAME_HEADER = b'\xc4\x0b\x4e\x00'
PROGHASH_HEADER = b'\x9d\x13\x42\x00'
OBJECTHASH_HEADER = b'\x9e\x13\x42\x00'
FIRSTSEEN_HEADER = b'\x9f\x13\x46\x00'

_dataTypeHeaders = {'Object': OBJECT_HEADER,
                    'Infiltration': INFILTRATION_HEADER,
                    'User': USER_HEADER,
                    'VirusDB': VIRUSDB_HEADER,
                    'ProgName': PROGNAME_HEADER}
_hashTypeHeaders = {'ObjectHash': OBJECTHASH_HEADER,
                    'ProgHash': PROGHASH_HEADER}


def eprint(*args, **kwargs):
    '''Prints debug messages to stderr'''
    print(*args, file=sys.stderr, **kwargs)


def _infoNotFound(field):
    eprint('Eset Info: field not found: ' + field)


def _warningUnexpected(field):
    eprint('Eset Warning: unexpected bytes in field ' + field)


def _winToUnixTimestamp(winTimestamp):
    magicNumber = 11644473600
    return (winTimestamp / 10000000) - magicNumber


def _extractDataType(dataType, rawRecord):
    # Format: dataType_HEADER + '??' + NULL + objectData + NULL

    dataType_HEADER = _dataTypeHeaders[dataType]
    dataOffset = rawRecord.find(dataType_HEADER)
    if dataOffset < 0:
        _infoNotFound(dataType)
        return ''
    if rawRecord[dataOffset+6:dataOffset+8] != NULL:
        _warningUnexpected(dataType)
    # find NULL char, but search for (\x00)*3, because third zero byte is part of last widechar
    dataEnd = dataOffset + 8 + 1 + \
        rawRecord[dataOffset+8:].find(b'\x00' + NULL)
    dataWideChar = rawRecord[dataOffset+8:dataEnd]
    return dataWideChar.decode('utf-16')


def _extractHashType(hashType, rawRecord):
    # Format: hashType_HEADER + '??' + NULL + hashData[20]

    hashType_HEADER = _hashTypeHeaders[hashType]
    hashOffset = rawRecord.find(hashType_HEADER)
    if hashOffset < 0:
        _infoNotFound(hashType)
        return ''
    if rawRecord[hashOffset+6:hashOffset+8] != NULL:
        _warningUnexpected(hashType)
    hashEnd = hashOffset + 8 + 20
    hashHex = rawRecord[hashOffset+8:hashEnd]
    # return hashHex.encode('hex')
    return binascii.hexlify(hashHex).decode('utf-8')


def _extractFirstSeen(rawRecord):
    # Format: FIRSTSEEN_HEADER + UnixTimestamp[4]

    offset = rawRecord.find(FIRSTSEEN_HEADER)
    if offset < 0:
        _infoNotFound('FirstSeen')
        return ''
    littleEndianTimestamp = rawRecord[offset+4:offset+8]
    timestamp = struct.unpack('<L', littleEndianTimestamp)[0]
    return datetime.utcfromtimestamp(timestamp).strftime(TIMEFORMAT)


def _extractTimestamp(rawRecord):
    # Format: RECORD_HEADER + ID[4] + MicrosoftTimestamp[8]

    littleEndianTimestamp = rawRecord[4:12]
    winTimestamp = struct.unpack('<Q', littleEndianTimestamp)[0]
    timestamp = _winToUnixTimestamp(winTimestamp)
    return datetime.fromtimestamp(int(timestamp))


def _checkID(recordId, rawRecord):
    littleEndianIds = [rawRecord[0:4], rawRecord[16:20]]
    for littleEndianId in littleEndianIds:
        if struct.unpack('<L', littleEndianId)[0] != recordId:
            _warningUnexpected('ID')


def getRawRecords(rawData):
    rawRecords = rawData.split(RECORD_HEADER)[1:]
    ziprecords = zip(range(len(rawRecords)), rawRecords)
    records = []
    for recordId, rawRecord in ziprecords:
        _checkID(recordId, rawRecord)
        # create 2D array instead of zip-object in Python 3
        records.append((recordId, rawRecord))
    return records


def parseRecord(recordId, rawRecord):
    record = dict()
    record['timestamp'] = _extractTimestamp(rawRecord)
    record['virusdb'] = _extractDataType('VirusDB', rawRecord)
    record['obj'] = _extractDataType('Object', rawRecord)
    record['objhash'] = _extractHashType('ObjectHash', rawRecord)
    record['infiltration'] = _extractDataType('Infiltration', rawRecord)
    record['user'] = _extractDataType('User', rawRecord).split('\\')[1]
    record['progname'] = _extractDataType('ProgName', rawRecord)
    record['proghash'] = _extractHashType('ProgHash', rawRecord)
    record['firstseen'] = _extractFirstSeen(rawRecord)

    return record


def mainParsing(virlog_path):
    with open(virlog_path, 'rb') as f:
        virlog_data = f.read()
    rawRecords = getRawRecords(virlog_data)
    parsedRecords = []
    for recordId, rawRecord in rawRecords:
        parsedRecords.append(parseRecord(recordId, rawRecord))

    return parsedRecords


class EsetParser():

    def __init__(self):
        # Quarantine folder per user
        self.quarpath = 'Users/{username}/AppData/Local/ESET/ESET Security/Quarantine/'

    def _decrypt(self, data):
        return bytes([((b - 84) % 256) ^ 0xA5 for b in data])

    def _get_malfile(self, username, sha1):
        quarfile = self.quarpath.format(username=username)
        quarfile = Path(quarfile) / (sha1.upper() + '.NQF')
        try:
            with open(quarfile, 'rb') as f:
                data = f.read()
                decrypted_data = self._decrypt(data)
        except IOError:
            print('Eset Error: could not read file', quarfile)

        return decrypted_data

    def from_file(self, name, location) -> List[QuarEntry]:
        self.name = name
        self.location = location

        quarfiles = []
        for metadata in mainParsing(self.location):
            if metadata['user'] == 'SYSTEM':
                continue
            q = QuarEntry()
            q.timestamp = metadata['timestamp']
            q.threat = metadata['infiltration']
            q.path = metadata['obj']
            q.malfile = self._get_malfile(metadata['user'],
                                          metadata['objhash'])
            q.size = len(q.malfile)
            q.md5 = md5(q.malfile).digest().hex()
            quarfiles.append(q)

        return quarfiles
