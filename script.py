import socket
import os
import sys


class Networking:
    def BannerGrabb(ip, port):
        socket.setdefaulttimeout(2)
        s = socket.socket()
        try:
            s.connect((str(ip), port))
            ban = s.recv(1024)
            return str(ban)
        except Exception as e:
            return f"[-] Error = {str(e)}"


class Cryptography:
    def PasswordCracker(hash, wordlist):
        pass


def main():
    pass


if __name__ == "__main__":
    main()
