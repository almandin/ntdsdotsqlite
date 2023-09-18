from Cryptodome.Cipher import DES, ARC4, AES
from impacket.structure import Structure
from binascii import unhexlify, hexlify
from impacket.dcerpc.v5 import samr
from impacket import winregistry
from hashlib import md5
from struct import pack
from six import b


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


KERBEROS_TYPE = {
    1: 'dec-cbc-crc',
    3: 'des-cbc-md5',
    17: 'aes128-cts-hmac-sha1-96',
    18: 'aes256-cts-hmac-sha1-96',
    0xffffff74: 'rc4_hmac',
}


def getBootKey(systemHivePath):
    # Local Version whenever we are given the files directly
    bootKey = b''
    tmpKey = b''
    winreg = winregistry.Registry(systemHivePath, False)
    # We gotta find out the Current Control Set
    currentControlSet = winreg.getValue('\\Select\\Current')[1]
    currentControlSet = "ControlSet%03d" % currentControlSet
    for key in ['JD', 'Skew1', 'GBG', 'Data']:
        ans = winreg.getClass('\\%s\\Control\\Lsa\\%s' % (currentControlSet, key))
        digit = ans[:16].decode('utf-16le')
        tmpKey = tmpKey + b(digit)

    transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]

    tmpKey = unhexlify(tmpKey)

    for i in range(len(tmpKey)):
        bootKey += tmpKey[transforms[i]:transforms[i] + 1]
    return bootKey


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


def removeRC4Layer(peklist, cryptedHash):
    md5h = md5()
    pekIndex = hexlify(cryptedHash['Header'])
    md5h.update(peklist[int(pekIndex[8:10])])
    md5h.update(cryptedHash['KeyMaterial'])
    tmpKey = md5h.digest()
    rc4 = ARC4.new(tmpKey)
    plainText = rc4.encrypt(cryptedHash['EncryptedHash'])

    return plainText


def removeDESLayer(cryptedHash, rid):
    Key1, Key2 = DESderiveKey(int(rid))
    Crypt1 = DES.new(Key1, DES.MODE_ECB)
    Crypt2 = DES.new(Key2, DES.MODE_ECB)
    decryptedHash = Crypt1.decrypt(cryptedHash[:8]) + Crypt2.decrypt(cryptedHash[8:])
    return decryptedHash


def DESderiveKey(baseKey):
    key = pack('<L', baseKey)
    key1 = [key[0], key[1], key[2], key[3], key[0], key[1], key[2]]
    key2 = [key[3], key[0], key[1], key[2], key[3], key[0], key[1]]
    return transformKey(bytes(key1)), transformKey(bytes(key2))


def transformKey(InputKey):
    OutputKey = []
    OutputKey.append(chr(ord(InputKey[0:1]) >> 0x01))
    OutputKey.append(chr(((ord(InputKey[0:1]) & 0x01) << 6) | (ord(InputKey[1:2]) >> 2)))
    OutputKey.append(chr(((ord(InputKey[1:2]) & 0x03) << 5) | (ord(InputKey[2:3]) >> 3)))
    OutputKey.append(chr(((ord(InputKey[2:3]) & 0x07) << 4) | (ord(InputKey[3:4]) >> 4)))
    OutputKey.append(chr(((ord(InputKey[3:4]) & 0x0F) << 3) | (ord(InputKey[4:5]) >> 5)))
    OutputKey.append(chr(((ord(InputKey[4:5]) & 0x1F) << 2) | (ord(InputKey[5:6]) >> 6)))
    OutputKey.append(chr(((ord(InputKey[5:6]) & 0x3F) << 1) | (ord(InputKey[6:7]) >> 7)))
    OutputKey.append(chr(ord(InputKey[6:7]) & 0x7F))

    for i in range(8):
        OutputKey[i] = chr((ord(OutputKey[i]) << 1) & 0xfe)

    return b("".join(OutputKey))


def decrypt_hash(peklist, account, key):
    if key == "nt":
        _key = "encrypted_nthash"
        default = "31d6cfe0d16ae931b73c59d7e0c089c0"
    else:
        _key = "encrypted_lmhash"
        default = "aad3b435b51404eeaad3b435b51404ee"
    if account[_key] is not None:
        rid = account["SID"].split('-')[-1]
        encryptedHash = CRYPTED_HASH(account[_key])
        if encryptedHash['Header'][:4] == b'\x13\x00\x00\x00':
            # Win2016 TP4 decryption is different
            encryptedHash = CRYPTED_HASHW16(account[_key])
            pekIndex = hexlify(encryptedHash['Header'])
            tmpNTHash = decryptAES(
                peklist[int(pekIndex[8:10])],
                encryptedHash['EncryptedHash'][:16],
                encryptedHash['KeyMaterial']
            )
        else:
            tmpNTHash = removeRC4Layer(peklist, encryptedHash)
        return bytes.hex(removeDESLayer(tmpNTHash, rid))
    else:
        return default


def decrypt_history(peklist, account, key):
    history = list()
    if key == "nt":
        _key = "encrypted_ntPwdHistory"
    else:
        _key = "encrypted_lmPwdHistory"
    if account[_key] is None:
        return history

    rid = account["SID"].split('-')[-1]
    encryptedHistory = CRYPTED_HISTORY(account[_key])
    pekIndex = hexlify(encryptedHistory['Header'])
    pekKey = peklist[int(pekIndex[8:10])]
    if encryptedHistory['Header'][:4] == b'\x13\x00\x00\x00':
        encryptedHistory = CRYPTED_HASHW16(account[_key])
        tmpHistory = decryptAES(
            pekKey,
            encryptedHistory['EncryptedHash'],
            encryptedHistory['KeyMaterial']
        )
    else:
        tmpHistory = removeRC4Layer(peklist, encryptedHistory)
    for i in range(0, len(tmpHistory) // 16):
        interesting_slice = slice(i * 16, (i + 1) * 16)
        hash = removeDESLayer(tmpHistory[interesting_slice], rid)
        history.append(bytes.hex(hash))
    return history


def decryptSupplementalInfo(peklist, account):
    # This is based on [MS-SAMR] 2.2.10 Supplemental Credentials Structures
    haveInfo = False
    encsuppcreds = account["encrypted_supplementalCredentials"]
    if encsuppcreds is not None:
        if len(encsuppcreds) > 24:
            cipherText = CRYPTED_BLOB(encsuppcreds)
            if cipherText['Header'][:4] == b'\x13\x00\x00\x00':
                pekIndex = hexlify(cipherText['Header'])
                plainText = decryptAES(
                    peklist[int(pekIndex[8:10])],
                    cipherText['EncryptedHash'][4:],
                    cipherText['KeyMaterial']
                )
            else:
                plainText = removeRC4Layer(peklist, cipherText)
            haveInfo = len(plainText) > 0x6f + 2 + 4
    if haveInfo:
        answers = []
        try:
            userProperties = samr.USER_PROPERTIES(plainText)
        except:
            return list()
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

                    if keyDataNew['KeyType'] in KERBEROS_TYPE:
                        kerb_keys.append(
                            (
                                KERBEROS_TYPE[keyDataNew['KeyType']],
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
