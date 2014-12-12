#!/usr/bin/env python3
# ----------------------------------------------------------------------------
# "THE SCOTCH-WARE LICENSE" (Revision 42):
# <DonMarco42@gmail.com> wrote this file. As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a scotch whisky in return
# Marco 'don' Kaulea
# ----------------------------------------------------------------------------


import Crypto.Cipher.AES as AES
import struct
import hashlib


def parse_comment(content):
    return dict(comment=content)


def parse_cypher_id(content):
    return dict(cypher_id=content)


def parse_compression_flags(content):
    return dict(compression_flags=struct.unpack('I', content)[0])


def parse_master_seed(content):
    return dict(master_seed=content)


def parse_transform_seed(content):
    return dict(transform_seed=content)


def parse_transform_rounds(content):
    return dict(transform_rounds=struct.unpack('L', content)[0])


def parse_encryption_iv(content):
    return dict(encryption_iv=content)


def parse_protected_stream_key(content):
    return dict(protected_stream_key=content)


def parse_stream_start_bytes(content):
    return dict(stream_start_bytes=content)


def parse_inner_random_stream_id(content):
    return dict(inner_random_stream_id=content)


header_parser = {0x01: parse_comment,
                 0x02: parse_cypher_id,
                 0x03: parse_compression_flags,
                 0x04: parse_master_seed,
                 0x05: parse_transform_seed,
                 0x06: parse_transform_rounds,
                 0x07: parse_encryption_iv,
                 0x08: parse_protected_stream_key,
                 0x09: parse_stream_start_bytes,
                 0x0a: parse_inner_random_stream_id}


def handle_kdbx(kdbx_file):
    unknown = kdbx_file.read(4)
    header = parse_header(kdbx_file)
    key = generate_final_master_key(generate_composite_key('asdfg'),
                                    header['transform_seed'],
                                    header['transform_rounds'],
                                    header['master_seed'])
    aes = AES.new(key,
                  mode=AES.MODE_CBC,
                  IV=header['encryption_iv'])
    body = kdbx_file.read() + b'\00\00\00\00\00\00\00\00\00\00\00\00'
    body = aes.decrypt(body)
    print(body)


def parse_header(kdbx_file):
    header = dict()
    type, length = struct.unpack('=BH', kdbx_file.read(3))
    while 0x00 != type:
        content = kdbx_file.read(length)
        header.update(header_parser[type](content).items())
        type, length = struct.unpack('=BH', kdbx_file.read(3))
    return header


def generate_composite_key(password, keyfile=None):
    hash = hashlib.sha256(password.encode('utf-8')).digest()
    if keyfile is not None:
        hash += hashlib.sha256(keyfile).digest()
    return hashlib.sha256(hash).digest()


def generate_final_master_key(composite_key,
                              transform_seed,
                              transform_rounds,
                              master_seed):
    aes = AES.new(transform_seed)
    transformed_key = composite_key
    for i in range(transform_rounds):
        transformed_key = aes.encrypt(transformed_key)
    transformed_key = hashlib.sha256(transformed_key).digest()
    final_master_key = hashlib.sha256(master_seed + transformed_key).digest()
    return final_master_key


def main():
    filename = 'keypass_test.kdbx'
    with open(filename, 'rb') as f:
        sig1, sig2 = struct.unpack('II', f.read(8))
        if 0x9AA2D903 != sig1:
            return
        if 0xB54BFB67 == sig2:
            handle_kdbx(f)
        elif 0xB54BFB65 == sig2:
            pass
        elif 0xB54BFB66 == sig2:
            pass
        else:
            print("Signature not recognised")


if __name__ == "__main__":
    main()
