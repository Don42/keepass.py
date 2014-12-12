#!/usr/bin/env python3
# ----------------------------------------------------------------------------
# "THE SCOTCH-WARE LICENSE" (Revision 42):
# <DonMarco42@gmail.com> wrote this file. As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a scotch whisky in return
# Marco 'don' Kaulea
# ----------------------------------------------------------------------------


import struct


def handle_kdbx(kdbx_file):
    print("Keepass2.x")
    unknown = kdbx_file.read(4)
    print("Not idea what this is. {}", unknown)
    type, length = struct.unpack('=BH', kdbx_file.read(3))
    while 0x00 != type:
        content = kdbx_file.read(length)
        if 0x01 == type:
            print("Comment: {}", content)
        elif 0x02 == type:
            print("Cypher ID: {}", content)
        elif 0x03 == type:
            print("Compression Flags: {}", content)
        elif 0x04 == type:
            print("Master Seed: {}", content)
        elif 0x05 == type:
            print("Transform Seed: {}", content)
        elif 0x06 == type:
            print("Transform Rounds: {}", content)
        elif 0x07 == type:
            print("Encryption IV: {}", content)
        elif 0x08 == type:
            print("Protected Stream Key: {}", content)
        elif 0x09 == type:
            print("Stream Start Bytes: {}", content)
        elif 0x0a == type:
            print("Inner Random Stream ID: {}", content)
        type, length = struct.unpack('=BH', kdbx_file.read(3))


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
