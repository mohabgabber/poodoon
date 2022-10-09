import socket
import os
import sys
import hashlib


class Networking:
    def networkintro():
        while True:
            print('''
            Available Tools
                0 - Banner Grab
                100 - Back To Main Menu
            ''')
            choice = int(input("Choose The Desired Tools' Number: "))
            if choice == 0:
                ip = input("Please Enter Ip: ")
                port = int(input("Please Enter Port: "))
                print(f"\n\n{Networking.BannerGrab(ip, port)}")
            elif choice == 100:
                break

    def BannerGrab(ip, port):
        socket.setdefaulttimeout(2)
        s = socket.socket()
        try:
            s.connect((str(ip), port))
            ban = s.recv(1024)
            return f"[*] The Returned Banner:\n {str(ban)}\n\n"
        except Exception as e:
            return f"[-] Error = {str(e)}"


class Crypto:
    def cryptointro():
        while True:
            print('''
            Available Tools
                0 - Sha512 Cracker
                100 - Back To Main Menu
        ''')
            choice = int(input("Choose The Desired Tools' Number: "))
            if choice == 0:
                hash = input("Please Paste The Hash To Crack: ")
                wordlist = input(
                    "Please Enter The Full Path To The Wordlist: ")
                print(Crypto.Sha512Cracker(hash, wordlist))
            elif choice == 100:
                break

    def Sha512Cracker(hash, wordlist):
        if not os.path.isfile(wordlist):
            return f"The File {wordlist}\n Doesn't Exist!"
        if not os.access(wordlist, os.R_OK):
            return f"The File {wordlist}\n Is Not Readable"
        wlist = open(wordlist, 'r')
        for word in wlist.readlines():
            w = word.strip("\n")
            hashsum = hashlib.sha512(w.encode("utf-8")).hexdigest()
            if hashsum == hash:
                return f"\n\n[*] Found Password: {w}\n"
                break
        print("\n\n[-] Password Not Found.\n")


def main():
    while True:
        print('''
        Available Modules 
            0 - Cryptography 
            1 - Networking
            700 - exit
        ''')
        choice = int(input("Insert The Desired Modules' Number: "))
        if choice == 0:
            Crypto.cryptointro()
        elif choice == 1:
            Networking.networkintro()
        elif choice == 700:
            break


if __name__ == "__main__":
    main()
