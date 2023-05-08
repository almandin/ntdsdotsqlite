# This is a modified version of impacket/impacket/examples/secretsdump.py
# What is modified here is :
# - it doesnt do anything remotely
# - it doesnt logs things to a file nor print it on the terminal but rather return secrets
# directly as a library
#   - @almandin
import hashlib
import random
from binascii import unhexlify, hexlify
from datetime import datetime
from struct import unpack, pack
from six import b, PY2

from impacket import LOG
from impacket import winregistry, ntlm
from impacket.dcerpc.v5 import samr
from impacket.ese import ESENT_DB
from impacket.structure import Structure
from impacket.crypto import transformKey
try:
    from Cryptodome.Cipher import DES, ARC4, AES
except ImportError:
    LOG.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
    LOG.critical("See https://pypi.org/project/pycryptodomex/")

from ntdsdotsqlite.utils import raw_to_guid

try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random
    pass


class SAMR_RPC_SID_IDENTIFIER_AUTHORITY(Structure):
    structure = (
        ('Value', '6s'),
    )


class SAMR_RPC_SID(Structure):
    structure = (
        ('Revision', '<B'),
        ('SubAuthorityCount', '<B'),
        ('IdentifierAuthority', ':', SAMR_RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubLen', '_-SubAuthority', 'self["SubAuthorityCount"]*4'),
        ('SubAuthority', ':'),
    )

    def formatCanonical(self):
        ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority']['Value'][5:6]))
        for i in range(self['SubAuthorityCount']):
            ans += '-%d' % (unpack('>L', self['SubAuthority'][i*4:i*4+4])[0])
        return ans


class CryptoCommon:
    # Common crypto stuff used over different classes
    def deriveKey(self, baseKey):
        # 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
        # Let I be the little-endian, unsigned integer.
        # Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
        # Note that because I is in little-endian byte order, I[0] is the least significant byte.
        # Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
        # Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
        key = pack('<L', baseKey)
        key1 = [key[0], key[1], key[2], key[3], key[0], key[1], key[2]]
        key2 = [key[3], key[0], key[1], key[2], key[3], key[0], key[1]]
        if PY2:
            return transformKey(b''.join(key1)), transformKey(b''.join(key2))
        else:
            return transformKey(bytes(key1)), transformKey(bytes(key2))

    @staticmethod
    def decryptAES(key, value, iv=b'\x00'*16):
        plainText = b''
        if iv != b'\x00'*16:
            aes256 = AES.new(key, AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            if iv == b'\x00'*16:
                aes256 = AES.new(key, AES.MODE_CBC, iv)
            cipherBuffer = value[index:index+16]
            # Pad buffer to 16 bytes
            if len(cipherBuffer) < 16:
                cipherBuffer += b'\x00' * (16-len(cipherBuffer))
            plainText += aes256.decrypt(cipherBuffer)

        return plainText


class NTDSHashes:
    class SECRET_TYPE:
        NTDS = 0
        NTDS_CLEARTEXT = 1
        NTDS_KERBEROS = 2

    NAME_TO_INTERNAL = {
        'uSNCreated': b'ATTq131091',
        'uSNChanged': b'ATTq131192',
        'name': b'ATTm3',
        'objectGUID': b'ATTk589826',
        'objectSid': b'ATTr589970',
        'userAccountControl': b'ATTj589832',
        'primaryGroupID': b'ATTj589922',
        'accountExpires': b'ATTq589983',
        'logonCount': b'ATTj589993',
        'sAMAccountName': b'ATTm590045',
        'sAMAccountType': b'ATTj590126',
        'lastLogonTimestamp': b'ATTq589876',
        'userPrincipalName': b'ATTm590480',
        'unicodePwd': b'ATTk589914',
        'dBCSPwd': b'ATTk589879',
        'ntPwdHistory': b'ATTk589918',
        'lmPwdHistory': b'ATTk589984',
        'pekList': b'ATTk590689',
        'supplementalCredentials': b'ATTk589949',
        'pwdLastSet': b'ATTq589920',
    }

    NAME_TO_ATTRTYP = {
        'userPrincipalName': 0x90290,
        'sAMAccountName': 0x900DD,
        'unicodePwd': 0x9005A,
        'dBCSPwd': 0x90037,
        'ntPwdHistory': 0x9005E,
        'lmPwdHistory': 0x900A0,
        'supplementalCredentials': 0x9007D,
        'objectSid': 0x90092,
        'userAccountControl': 0x90008,
    }

    ATTRTYP_TO_ATTID = {
        'userPrincipalName': '1.2.840.113556.1.4.656',
        'sAMAccountName': '1.2.840.113556.1.4.221',
        'unicodePwd': '1.2.840.113556.1.4.90',
        'dBCSPwd': '1.2.840.113556.1.4.55',
        'ntPwdHistory': '1.2.840.113556.1.4.94',
        'lmPwdHistory': '1.2.840.113556.1.4.160',
        'supplementalCredentials': '1.2.840.113556.1.4.125',
        'objectSid': '1.2.840.113556.1.4.146',
        'pwdLastSet': '1.2.840.113556.1.4.96',
        'userAccountControl': '1.2.840.113556.1.4.8',
    }

    KERBEROS_TYPE = {
        1: 'dec-cbc-crc',
        3: 'des-cbc-md5',
        17: 'aes128-cts-hmac-sha1-96',
        18: 'aes256-cts-hmac-sha1-96',
        0xffffff74: 'rc4_hmac',
    }

    INTERNAL_TO_NAME = dict((v, k) for k, v in NAME_TO_INTERNAL.items())

    SAM_NORMAL_USER_ACCOUNT = 0x30000000
    SAM_MACHINE_ACCOUNT = 0x30000001
    SAM_TRUST_ACCOUNT = 0x30000002

    ACCOUNT_TYPES = (SAM_NORMAL_USER_ACCOUNT, SAM_MACHINE_ACCOUNT, SAM_TRUST_ACCOUNT)

    class PEKLIST_ENC(Structure):
        structure = (
            ('Header', '8s=b""'),
            ('KeyMaterial', '16s=b""'),
            ('EncryptedPek', ':'),
        )

    class PEKLIST_PLAIN(Structure):
        structure = (
            ('Header', '32s=b""'),
            ('DecryptedPek', ':'),
        )

    class PEK_KEY(Structure):
        structure = (
            ('Header', '1s=b""'),
            ('Padding', '3s=b""'),
            ('Key', '16s=b""'),
        )

    class CRYPTED_HASH(Structure):
        structure = (
            ('Header', '8s=b""'),
            ('KeyMaterial', '16s=b""'),
            ('EncryptedHash', '16s=b""'),
        )

    class CRYPTED_HASHW16(Structure):
        structure = (
            ('Header', '8s=b""'),
            ('KeyMaterial', '16s=b""'),
            ('Unknown', '<L=0'),
            ('EncryptedHash', ':'),
        )

    class CRYPTED_HISTORY(Structure):
        structure = (
            ('Header', '8s=b""'),
            ('KeyMaterial', '16s=b""'),
            ('EncryptedHash', ':'),
        )

    class CRYPTED_BLOB(Structure):
        structure = (
            ('Header', '8s=b""'),
            ('KeyMaterial', '16s=b""'),
            ('EncryptedHash', ':'),
        )

    def __init__(self, ntdsFile, bootKey):
        self.__bootKey = bootKey
        self.__NTDS = ntdsFile
        self.__ESEDB = ESENT_DB(ntdsFile)
        self.__cursor = self.__ESEDB.openTable('datatable')
        self.__tmpUsers = list()
        self.__PEK = list()
        self.__cryptoCommon = CryptoCommon()

        # these are all the columns that we need to get the secrets.
        # If in the future someone finds other columns containing interesting things please extend
        # this table.
        self.__filter_tables_usersecret = {
            "DNT_col": 1,
            self.NAME_TO_INTERNAL["objectGUID"]: 1,
            self.NAME_TO_INTERNAL['objectSid']: 1,
            self.NAME_TO_INTERNAL['dBCSPwd']: 1,
            self.NAME_TO_INTERNAL['name']: 1,
            self.NAME_TO_INTERNAL['sAMAccountType']: 1,
            self.NAME_TO_INTERNAL['unicodePwd']: 1,
            self.NAME_TO_INTERNAL['sAMAccountName']: 1,
            self.NAME_TO_INTERNAL['userPrincipalName']: 1,
            self.NAME_TO_INTERNAL['ntPwdHistory']: 1,
            self.NAME_TO_INTERNAL['lmPwdHistory']: 1,
            self.NAME_TO_INTERNAL['pwdLastSet']: 1,
            self.NAME_TO_INTERNAL['userAccountControl']: 1,
            self.NAME_TO_INTERNAL['supplementalCredentials']: 1,
            self.NAME_TO_INTERNAL['pekList']: 1,
        }

    def __getPek(self):
        LOG.info('Searching for pekList, be patient')
        peklist = None
        while True:
            try:
                record = self.__ESEDB.getNextRow(
                    self.__cursor, filter_tables=self.__filter_tables_usersecret
                )
            except:
                LOG.error('Error while calling getNextRow(), trying the next one')
                continue

            if record is None:
                break
            elif record[self.NAME_TO_INTERNAL['pekList']] is not None:
                peklist = unhexlify(record[self.NAME_TO_INTERNAL['pekList']])
                break
            elif record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                # Okey.. we found some users, but we're not yet ready to process them.
                # Let's just store them in a temp list
                self.__tmpUsers.append(record)

        if peklist is not None:
            encryptedPekList = self.PEKLIST_ENC(peklist)
            if encryptedPekList['Header'][:4] == b'\x02\x00\x00\x00':
                # Up to Windows 2012 R2 looks like header starts this way
                md5 = hashlib.new('md5')
                md5.update(self.__bootKey)
                for i in range(1000):
                    md5.update(encryptedPekList['KeyMaterial'])
                tmpKey = md5.digest()
                rc4 = ARC4.new(tmpKey)
                decryptedPekList = self.PEKLIST_PLAIN(rc4.encrypt(encryptedPekList['EncryptedPek']))
                PEKLen = len(self.PEK_KEY())
                for i in range(len(decryptedPekList['DecryptedPek']) // PEKLen):
                    cursor = i * PEKLen
                    pek = self.PEK_KEY(decryptedPekList['DecryptedPek'][cursor:cursor+PEKLen])
                    LOG.info(
                        "PEK # %d found and decrypted: %s", i, hexlify(pek['Key']).decode('utf-8')
                    )
                    self.__PEK.append(pek['Key'])

            elif encryptedPekList['Header'][:4] == b'\x03\x00\x00\x00':
                # Windows 2016 TP4 header starts this way
                # Encrypted PEK Key seems to be different, but actually similar to decrypting
                # LSA Secrets.
                # using AES:
                # Key: the bootKey
                # CipherText: PEKLIST_ENC['EncryptedPek']
                # IV: PEKLIST_ENC['KeyMaterial']
                decryptedPekList = self.PEKLIST_PLAIN(
                    self.__cryptoCommon.decryptAES(self.__bootKey, encryptedPekList['EncryptedPek'],
                                                   encryptedPekList['KeyMaterial']))

                # PEK list entries take the form:
                #   index (4 byte LE int), PEK (16 byte key)
                # the entries are in ascending order, and the list is terminated
                # by an entry with a non-sequential index (08080808 observed)
                pos, cur_index = 0, 0
                while True:
                    pek_entry = decryptedPekList['DecryptedPek'][pos:pos+20]
                    if len(pek_entry) < 20:
                        break  # if list truncated, should not happen
                    index, pek = unpack('<L16s', pek_entry)
                    if index != cur_index:
                        break  # break on non-sequential index
                    self.__PEK.append(pek)
                    LOG.info(
                        "PEK # %d found and decrypted: %s", index, hexlify(pek).decode('utf-8')
                    )
                    cur_index += 1
                    pos += 20

    def __removeRC4Layer(self, cryptedHash):
        md5 = hashlib.new('md5')
        # PEK index can be found on header of each ciphered blob (pos 8-10)
        pekIndex = hexlify(cryptedHash['Header'])
        md5.update(self.__PEK[int(pekIndex[8:10])])
        md5.update(cryptedHash['KeyMaterial'])
        tmpKey = md5.digest()
        rc4 = ARC4.new(tmpKey)
        plainText = rc4.encrypt(cryptedHash['EncryptedHash'])

        return plainText

    def __removeDESLayer(self, cryptedHash, rid):
        Key1, Key2 = self.__cryptoCommon.deriveKey(int(rid))

        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)

        decryptedHash = Crypt1.decrypt(cryptedHash[:8]) + Crypt2.decrypt(cryptedHash[8:])

        return decryptedHash

    @staticmethod
    def __fileTimeToDateTime(t):
        t -= 116444736000000000
        t //= 10000000
        if t < 0:
            return 'never'
        else:
            dt = datetime.fromtimestamp(t)
            return dt.strftime("%Y-%m-%d %H:%M")

    def __decryptSupplementalInfo(self, record):
        # This is based on [MS-SAMR] 2.2.10 Supplemental Credentials Structures
        haveInfo = False
        LOG.debug('Entering NTDSHashes.__decryptSupplementalInfo')
        if record[self.NAME_TO_INTERNAL['supplementalCredentials']] is not None:
            if len(unhexlify(record[self.NAME_TO_INTERNAL['supplementalCredentials']])) > 24:
                cipherText = self.CRYPTED_BLOB(
                    unhexlify(record[self.NAME_TO_INTERNAL['supplementalCredentials']])
                )

                if cipherText['Header'][:4] == b'\x13\x00\x00\x00':
                    # Win2016 TP4 decryption is different
                    pekIndex = hexlify(cipherText['Header'])
                    plainText = self.__cryptoCommon.decryptAES(self.__PEK[int(pekIndex[8:10])],
                                                               cipherText['EncryptedHash'][4:],
                                                               cipherText['KeyMaterial'])
                    haveInfo = True
                else:
                    plainText = self.__removeRC4Layer(cipherText)
                    haveInfo = True

        if haveInfo:
            answers = []
            try:
                userProperties = samr.USER_PROPERTIES(plainText)
            except:
                # On some old w2k3 there might be user properties that don't
                # match [MS-SAMR] structure, discarding them
                return []
            propertiesData = userProperties['UserProperties']
            for propertyCount in range(userProperties['PropertyCount']):
                userProperty = samr.USER_PROPERTY(propertiesData)
                propertiesData = propertiesData[len(userProperty):]
                # For now, we will only process Newer Kerberos Keys and CLEARTEXT
                if userProperty['PropertyName'].decode('utf-16le') == 'Primary:Kerberos-Newer-Keys':
                    propertyValueBuffer = unhexlify(userProperty['PropertyValue'])
                    kerbStoredCredentialNew = samr.KERB_STORED_CREDENTIAL_NEW(propertyValueBuffer)
                    data = kerbStoredCredentialNew['Buffer']
                    kerb_keys = []
                    for credential in range(kerbStoredCredentialNew['CredentialCount']):
                        keyDataNew = samr.KERB_KEY_DATA_NEW(data)
                        data = data[len(keyDataNew):]
                        keyValue = (
                            propertyValueBuffer[keyDataNew['KeyOffset']:][:keyDataNew['KeyLength']]
                        )

                        if keyDataNew['KeyType'] in self.KERBEROS_TYPE:
                            kerb_keys.append(
                                (
                                    self.KERBEROS_TYPE[keyDataNew['KeyType']],
                                    hexlify(keyValue).decode('utf-8')
                                )
                            )
                        else:
                            kerb_keys.append(
                                (
                                    hex(keyDataNew['KeyType']),
                                    hexlify(keyValue).decode('utf-8')
                                )
                            )
                    answers += kerb_keys
                elif userProperty['PropertyName'].decode('utf-16le') == 'Primary:CLEARTEXT':
                    # [MS-SAMR] 3.1.1.8.11.5 Primary:CLEARTEXT Property
                    # This credential type is the cleartext password. The value format is the
                    # UTF-16 encoded cleartext password.
                    try:
                        answers.append(
                            (
                                "cleartext",
                                unhexlify(userProperty['PropertyValue']).decode('utf-16le')
                            )
                        )
                    except UnicodeDecodeError:
                        # This could be because we're decoding a machine password. Printing it hex
                        answers.append(("cleartext", userProperty['PropertyValue'].decode('utf-8')))
                return answers
        else:
            # no supplemental info
            return []
        LOG.debug('Leaving NTDSHashes.__decryptSupplementalInfo')

    def __decryptHash(self, record):
        LOG.debug('Entering NTDSHashes.__decryptHash')
        LOG.debug('Decrypting hash for user: %s' % record[self.NAME_TO_INTERNAL['name']])

        sid = SAMR_RPC_SID(unhexlify(record[self.NAME_TO_INTERNAL['objectSid']]))
        rid = sid.formatCanonical().split('-')[-1]

        if record[self.NAME_TO_INTERNAL['dBCSPwd']] is not None:
            encryptedLMHash = self.CRYPTED_HASH(unhexlify(record[self.NAME_TO_INTERNAL['dBCSPwd']]))
            if encryptedLMHash['Header'][:4] == b'\x13\x00\x00\x00':
                # Win2016 TP4 decryption is different
                encryptedLMHash = self.CRYPTED_HASHW16(
                    unhexlify(record[self.NAME_TO_INTERNAL['dBCSPwd']])
                )
                pekIndex = hexlify(encryptedLMHash['Header'])
                tmpLMHash = self.__cryptoCommon.decryptAES(self.__PEK[int(pekIndex[8:10])],
                                                           encryptedLMHash['EncryptedHash'][:16],
                                                           encryptedLMHash['KeyMaterial'])
            else:
                tmpLMHash = self.__removeRC4Layer(encryptedLMHash)
            LMHash = self.__removeDESLayer(tmpLMHash, rid)
        else:
            LMHash = ntlm.LMOWFv1('', '')

        if record[self.NAME_TO_INTERNAL['unicodePwd']] is not None:
            encryptedNTHash = self.CRYPTED_HASH(
                unhexlify(record[self.NAME_TO_INTERNAL['unicodePwd']])
            )
            if encryptedNTHash['Header'][:4] == b'\x13\x00\x00\x00':
                # Win2016 TP4 decryption is different
                encryptedNTHash = self.CRYPTED_HASHW16(
                    unhexlify(record[self.NAME_TO_INTERNAL['unicodePwd']])
                )
                pekIndex = hexlify(encryptedNTHash['Header'])
                tmpNTHash = self.__cryptoCommon.decryptAES(self.__PEK[int(pekIndex[8:10])],
                                                           encryptedNTHash['EncryptedHash'][:16],
                                                           encryptedNTHash['KeyMaterial'])
            else:
                tmpNTHash = self.__removeRC4Layer(encryptedNTHash)
            NTHash = self.__removeDESLayer(tmpNTHash, rid)
        else:
            NTHash = ntlm.NTOWFv1('', '')

        if record[self.NAME_TO_INTERNAL['userPrincipalName']] is not None:
            domain = record[self.NAME_TO_INTERNAL['userPrincipalName']].split('@')[-1]
            userName = '%s\\%s' % (domain, record[self.NAME_TO_INTERNAL['sAMAccountName']])
        else:
            userName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]
        guid = record[self.NAME_TO_INTERNAL["objectGUID"]]
        # Prints user hashes
        answer = {
            "username": userName,
            "guid": raw_to_guid(unhexlify(guid.decode("utf-8"))),
            "lmhash": hexlify(LMHash).decode("utf-8"),
            "nthash": hexlify(NTHash).decode("utf-8"),
        }

        LMHistory = []
        NTHistory = []
        if record[self.NAME_TO_INTERNAL['lmPwdHistory']] is not None:
            encryptedLMHistory = self.CRYPTED_HISTORY(
                unhexlify(record[self.NAME_TO_INTERNAL['lmPwdHistory']])
            )
            tmpLMHistory = self.__removeRC4Layer(encryptedLMHistory)
            for i in range(0, len(tmpLMHistory) // 16):
                LMHash = self.__removeDESLayer(tmpLMHistory[i * 16:(i + 1) * 16], rid)
                LMHistory.append(LMHash)

        if record[self.NAME_TO_INTERNAL['ntPwdHistory']] is not None:
            encryptedNTHistory = self.CRYPTED_HISTORY(
                unhexlify(record[self.NAME_TO_INTERNAL['ntPwdHistory']])
            )

            if encryptedNTHistory['Header'][:4] == b'\x13\x00\x00\x00':
                # Win2016 TP4 decryption is different
                encryptedNTHistory = self.CRYPTED_HASHW16(
                    unhexlify(record[self.NAME_TO_INTERNAL['ntPwdHistory']]))
                pekIndex = hexlify(encryptedNTHistory['Header'])
                tmpNTHistory = self.__cryptoCommon.decryptAES(self.__PEK[int(pekIndex[8:10])],
                                                              encryptedNTHistory['EncryptedHash'],
                                                              encryptedNTHistory['KeyMaterial'])
            else:
                tmpNTHistory = self.__removeRC4Layer(encryptedNTHistory)

            for i in range(0, len(tmpNTHistory) // 16):
                NTHash = self.__removeDESLayer(tmpNTHistory[i * 16:(i + 1) * 16], rid)
                NTHistory.append(NTHash)

        answer["lmhistory"] = [hexlify(h).decode("utf-8") for h in LMHistory]
        answer["nthistory"] = [hexlify(h).decode("utf-8") for h in NTHistory]
        LOG.debug('Leaving NTDSHashes.__decryptHash')
        return answer

    def dump(self):
        # Let's check if we need to save results in a file
        LOG.info('Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)')
        # We start getting rows from the table aiming at reaching
        # the pekList. If we find users records we stored them
        # in a temp list for later process.
        self.__getPek()
        if self.__PEK is not None:
            LOG.info('Reading and decrypting hashes from %s ' % self.__NTDS)
            # First of all, if we have users already cached, let's decrypt their hashes
            for record in self.__tmpUsers:
                try:
                    h = self.__decryptHash(record)
                    sup_info = self.__decryptSupplementalInfo(record)
                    yield {
                        **h, "supplemental_credentials": sup_info
                    }
                except Exception as e:
                    LOG.debug('Exception', exc_info=True)
                    try:
                        LOG.error(
                            "Error while processing row for user %s" % record[self.NAME_TO_INTERNAL['name']])
                        LOG.error(str(e))
                        pass
                    except:
                        LOG.error("Error while processing row!")
                        LOG.error(str(e))
                        pass

            # Now let's keep moving through the NTDS file and decrypting what we find
            while True:
                try:
                    record = self.__ESEDB.getNextRow(
                        self.__cursor, filter_tables=self.__filter_tables_usersecret
                    )
                except:
                    LOG.error('Error while calling getNextRow(), trying the next one')
                    continue

                if record is None:
                    break
                try:
                    if record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                        h = self.__decryptHash(record)
                        sup_info = self.__decryptSupplementalInfo(record)
                        yield {
                            **h, "supplemental_credentials": sup_info
                        }
                except Exception as e:
                    LOG.debug('Exception', exc_info=True)
                    try:
                        LOG.error(
                            "Error while processing row for user %s"
                            % record[self.NAME_TO_INTERNAL['name']]
                        )
                        LOG.error(str(e))
                        pass
                    except:
                        LOG.error("Error while processing row!")
                        LOG.error(str(e))
                        pass

    def finish(self):
        self.__ESEDB.close()


class LocalOperations:
    def __init__(self, systemHive):
        self.__systemHive = systemHive

    def getBootKey(self):
        # Local Version whenever we are given the files directly
        bootKey = b''
        tmpKey = b''
        winreg = winregistry.Registry(self.__systemHive, False)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet
        for key in ['JD', 'Skew1', 'GBG', 'Data']:
            LOG.debug('Retrieving class info for %s' % key)
            ans = winreg.getClass('\\%s\\Control\\Lsa\\%s' % (currentControlSet, key))
            digit = ans[:16].decode('utf-16le')
            tmpKey = tmpKey + b(digit)

        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]

        tmpKey = unhexlify(tmpKey)

        for i in range(len(tmpKey)):
            bootKey += tmpKey[transforms[i]:transforms[i] + 1]

        LOG.info('Target system bootKey: 0x%s' % hexlify(bootKey).decode('utf-8'))

        return bootKey

    def checkNoLMHashPolicy(self):
        LOG.debug('Checking NoLMHash Policy')
        winreg = winregistry.Registry(self.__systemHive, False)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet

        # noLmHash = winreg.getValue('\\%s\\Control\\Lsa\\NoLmHash' % currentControlSet)[1]
        noLmHash = winreg.getValue('\\%s\\Control\\Lsa\\NoLmHash' % currentControlSet)
        if noLmHash is not None:
            noLmHash = noLmHash[1]
        else:
            noLmHash = 0

        if noLmHash != 1:
            LOG.debug('LMHashes are being stored')
            return False
        LOG.debug('LMHashes are NOT being stored')
        return True
