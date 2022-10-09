import socket
import os
import sys
import hashlib
import crypt

# Repeated Functionalities


def filecheckr(file):
    if not os.path.isfile(file):
        return False
    if not os.access(file, os.R_OK):
        return False
    return True

# Modules


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
                0 - Hash Cracker
                1 - Shadow Cracker
                100 - Back To Main Menu
        ''')
            choice = int(input("Choose The Desired Tool's Number: "))
            if choice == 0:
                hash = input("Please Paste The Hash To Crack: ")
                wordlist = input(
                    "Please Enter The Full Path To The Wordlist: ")
                print('''
                Choose Hashing Algorithm:
                    0 - md5
                    1 - sha1
                    2 - sha224
                    3 - sha256
                    4 - sha384
                    5 - sha512
                ''')
                algo = int(
                    input("Please Enter The Desired Algorithm's Number: "))
                print(Crypto.HashCracker(hash, wordlist, algo))
            elif choice == 1:
                shadow = input("Please Enter The Shadow File: ")
                wordlist = input("Please Enter The Wordlist: ")
                Crypto.ShadowCracker(shadow, wordlist)
            elif choice == 100:
                break

    def HashCracker(hash, wordlist, algo):
        if filecheckr(wordlist) == True:

            wlist = open(wordlist, 'r')
            for word in wlist.readlines():
                w = word.strip("\n")
                if algo == 0:
                    hashsum = hashlib.md5(w.encode("utf-8")).hexdigest()
                elif algo == 1:
                    hashsum = hashlib.sha1(w.encode("utf-8")).hexdigest()
                elif algo == 2:
                    hashsum = hashlib.sha224(w.encode("utf-8")).hexdigest()
                elif algo == 3:
                    hashsum = hashlib.sha256(w.encode("utf-8")).hexdigest()
                elif algo == 4:
                    hashsum = hashlib.sha384(w.encode("utf-8")).hexdigest()
                elif algo == 5:
                    hashsum = hashlib.sha512(w.encode("utf-8")).hexdigest()
                else:
                    return "Invalid Algorithm"
                if hashsum == hash:
                    return f"\n\n[*] Found Password: {w}\n"
                    break
            print("\n\n[-] Password Not Found.\n")
        else:
            return f"The file {wordlist} \nis either doesn't exist or is unreadable."

    def ShadowCracker(shadow, wordlist):
        if filecheckr(wordlist) == True:
            if filecheckr(shadow) == True:
                shfile = open(shadow, 'r')
                for line in shfile.readlines():
                    wlist = open(wordlist, 'r')
                    splitted = line.split(":")
                    if splitted[1] == "!*" or splitted[1] == "":
                        pass
                    else:
                        user = splitted[0]
                        hash = splitted[1]
                        salt0 = hash.split("$")
                        saltfin = f"${salt0[1]}${salt0[2]}"
                        for word in wlist.readlines():
                            w = word.strip("\n")
                            crypthash = crypt.crypt(w, saltfin)
                            if crypthash == hash:
                                print(
                                    f"\n\n[*] Password Found, User: {user} Password: {w}\n\n with hash: {crypthash}")
                                break

        else:
            return f"The file {wordlist} \nis either doesn't exist or is unreadable."


def main():
    while True:
        print('''
        Available Modules 
            0 - Cryptography 
            1 - Networking
            700 - exit
        ''')
        choice = int(input("Insert The Desired Module's Number: "))
        if choice == 0:
            Crypto.cryptointro()
        elif choice == 1:
            Networking.networkintro()
        elif choice == 700:
            print("I will miss you <3")
            break


if __name__ == "__main__":
    main()
