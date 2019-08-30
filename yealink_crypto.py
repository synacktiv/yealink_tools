#!/usr/bin/env python3

#coding: utf-8
"""
    Yealink updates cryptographic functions
    (c) Synacktiv 2019

    Licensed under the "THE BEER-WARE LICENSE" (Revision 42):
    Tristan P. wrote this file. As long as you retain this notice you
    can do whatever you want with this stuff. If we meet some day, and you think
    this stuff is worth it, you can buy me a beer or coffee in return
"""

from binascii import unhexlify, hexlify

from Crypto.Cipher import AES

def get_crypto(crypto_type):
    """
        Returns the string corresponding to the algorithm according to
        the update format
    """
    output = ""
    if crypto_type == 0x80:
        output = "AES"
    elif crypto_type == 0x81:
        output = "DES"
    elif crypto_type == 4:
        output = "CYPHER4 / ADD-XOR COMB 512"
    elif crypto_type == 0:
        output = "NULL CIPHER"
    elif crypto_type == 1:
        output = "CYPHER1 / LZMA compression"
    elif crypto_type == 2:
        output = "CYPHER2 Unknown"
    elif crypto_type == 3:
        output = "CYPHER3 / SUB-XOR 256"
    else:
        raise NotImplementedError

    return output


def cypher3_decrypt(enc):
    """
        Method of decryption number 3 inside yealink firmwares
    """
    xorkey = unhexlify("75A467AFD195CF5A7B871B33C147EBD6BEA73A03CEBCF02A749066B36B3E09CC")
    addkey = unhexlify("82180D326A92124E80172CE9A2F2222577AB49DFD5C70693699BF6415F615935")
    out = bytearray()
    mindex = 0
    for mindex, cur_char in enumerate(enc):
        tmp = cur_char - addkey[mindex % len(xorkey)]
        tmp = tmp ^ xorkey[mindex % len(xorkey)]
        tmp = tmp & 0xFF
        out.append(tmp)
    return out

def cypher3_encrypt(enc):
    """
        Referenced as "cypher3_encode" inside yealink firmwares
    """
    xorkey = unhexlify("75A467AFD195CF5A7B871B33C147EBD6BEA73A03CEBCF02A749066B36B3E09CC")
    addkey = unhexlify("82180D326A92124E80172CE9A2F2222577AB49DFD5C70693699BF6415F615935")
    out = bytearray()
    mindex = 0
    for mindex, cur_char in enumerate(enc):
        tmp = cur_char ^ xorkey[mindex % len(xorkey)]
        tmp = tmp + addkey[mindex % len(xorkey)]
        tmp = tmp & 0xFF
        out.append(tmp)
    return out

def cypher4_encrypt(data):
    """
        Slightly more complicated cryptography, including a "mix" step
    """
    c4_subkey = unhexlify("0591E065B04C9C76F99DC0689533FA12CBFE83BFF35A38A37B8169D6BE25136D3B06CC72266197B842451A96D3E3CE2BAF2DDCE81F57F4C89F8B630AA0312819")
    c4_xorkey = unhexlify("FD14E58F5DC66BA992F24E0C01244954713DC9372E2A5BB94AC5BCC4203404F607364716BA73FCC24F53E1395F988693A117670878C1BD3A1BB443E6AB4BD4DD")

    out = bytearray()
    for index, cur_char in enumerate(data):
        tmp = cur_char
        tmp = (cur_char - c4_subkey[index % 64]) & 0xFF
        tmp = tmp ^ c4_xorkey[index % 64]
        out.append(tmp)

    out_mix = [c for c in out]
    for j in range(0, len(data)-32, 32):
        start_index = j
        for end_index in range(j+31, start_index, -1):
            print("Start index: %d End index: %d" % (start_index, end_index))
            start_byte = out_mix[start_index]
            end_byte = out_mix[end_index]

            out_mix[end_index] = start_byte

            start_index += 1
            out_mix[start_index] = (end_byte - start_byte)&0xFF

    return bytes(out_mix)

def cypher4_decrypt(data):
    c4_subkey = unhexlify("0591E065B04C9C76F99DC0689533FA12CBFE83BFF35A38A37B8169D6BE25136D3B06CC72266197B842451A96D3E3CE2BAF2DDCE81F57F4C89F8B630AA0312819")
    c4_xorkey = unhexlify("FD14E58F5DC66BA992F24E0C01244954713DC9372E2A5BB94AC5BCC4203404F607364716BA73FCC24F53E1395F988693A117670878C1BD3A1BB443E6AB4BD4DD")

    mdata = [c for c in data]

    for i in range(0, len(data)-32, 32):
        start_index = i
        for end_index in range(i+31, start_index, -1):
            start_byte = data[start_index]
            end_byte = data[end_index]
            mdata[start_index] = end_byte
            mdata[end_index] = (start_byte + end_byte)&0xFF

            start_index += 1

    out = bytearray()
    for index, cur_char in enumerate(mdata):
        tmp = cur_char ^ c4_xorkey[index % 64]
        tmp = (tmp + c4_subkey[index % 64])&0xFF
        out.append(tmp)

    return bytes(out)

def aes_decrypt(data):
    """
        This key is hardcoded inside the firmware updater library
        However, it does not work for the AES encrypted firmwares...
    """
    rom_cypher_key = unhexlify("7AE5AB76DF05569CC74508E3E300971059735C041195A4178BA6DBBF77EADC9F")
    dec = AES.new(rom_cypher_key, AES.MODE_ECB)

    out = dec.decrypt(data[:len(data)-len(data)%0x10])
    return out

def decrypt_data(data, crypto_type):
    """
        Decipher the data according to the specified algorithm
    """
    if crypto_type == 0:
        return data
    if crypto_type == 3:
        return cypher3_decrypt(data)
    if crypto_type == 128:
        return aes_decrypt(data)
    raise NotImplementedError


def tests():
    """
        Testing cyphers implementation
    """
    buf = b"\xf8\xbc\x74\xe1\x3a\x27\xe1\xa8\x04\x8f\x47\x1c\x63\x39\x0d\xfb"
    verif = b"\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00"
    out = cypher3_decrypt(buf)
    if verif != out:
        print("Error in cypher3_decrypt")
        print(buf)
        print(verif)
    else:
        print("cypher3 decryption seems OK")

    out = cypher3_encrypt(verif)

    if out != buf:
        print("Error in cypher3_encrypt")
    else:
        print("cypher3 encryption seems OK")


    tmp = cypher4_encrypt(b"\x00"*10)
    if cypher4_decrypt(tmp) != b"\x00"*10:
        print("Error in cypher4")
        print(hexlify(tmp))
        print(hexlify(cypher4_decrypt(tmp)))
    else:
        print("Cypher4 at least is reversible")
    aes_test_data = unhexlify("675ff10cdf9f7299f6ca71387153bf71")
    aes_decrypt(aes_test_data)

if __name__ == "__main__":
    tests()
