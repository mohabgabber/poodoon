import socket
import os
import zipfile
import pyzipper
import nmap
import sys
import hashlib
import crypt
import requests
from pyfiglet import Figlet
import colorama
from colorama import Fore
from colorama import Style


# Functionalities

colorama.init()
custom_fig = Figlet(font="slant").renderText("Python\nOffensive\nTools")
print(f"{Fore.GREEN}{custom_fig}{Style.RESET_ALL}")
print("Made By Mohab Gabber. https://twitter.com/fuckhumanity12s")


def successprint(text):
    print(f'''{Fore.GREEN}{text}{Style.RESET_ALL}''')


def failprint(text):
    print(f'''{Fore.RED}{text}{Style.RESET_ALL}''')


def infoprint(text):
    print(f'''{Fore.YELLOW}{text}{Style.RESET_ALL}''')


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
            infoprint('''
            Available Tools
                0 - Banner Grab
                1 - Nmap Scan
                100 - Back To Main Menu
            ''')
            choice = int(input("Choose The Desired Tools' Number: "))
            if choice == 0:
                ip = input("Please Enter Ip: ")
                port = int(input("Please Enter Port: "))
                # print(f"\n\n{Networking.BannerGrab(ip, port)}")
                Networking.BannerGrab(ip, port)
            elif choice == 1:
                infoprint("You Whole Network, Example: '192.168.1.0/24'")
                ip = input("Please Enter An Ip To Scan: ")
                arguments = input(
                    "Please Enter Your Nmap Arguments, (Same As nmap cli): ")
                Networking.PortScan(ip, arguments)
            elif choice == 100:
                break

    def BannerGrab(ip, port):
        socket.setdefaulttimeout(2)
        s = socket.socket()
        try:
            s.connect((str(ip), port))
            ban = s.recv(1024)
            successprint(f"[*] The Returned Banner:\t {str(ban)}")
            return
        except Exception as e:
            failprint(f"[-] Error = {str(e)}")
            return

    def PortScan(ip, arguments):
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments=arguments)
        for host in nm.all_hosts():
            print("-"*50)
            successprint(f"Host: {host} ({nm[host].hostname()})")
            successprint(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print("-"*50)
                successprint(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                ports
                for port in ports:
                    successprint(
                        f"Port: {port}\tState: {nm[host][proto][port]['state']}\tReason: {nm[host][proto][port]['reason']}\tName: {nm[host][proto][port]['name']}\tProduct: {nm[host][proto][port]['product']}\tVersion: {nm[host][proto][port]['version']}")


class Crypto:
    def cryptointro():
        while True:
            infoprint('''
            Available Tools
                0 - Hash Cracker
                1 - Shadow Cracker
                2 - Zip File Brute Force
                100 - Back To Main Menu
        ''')
            choice = int(input("Choose The Desired Tool's Number: "))
            if choice == 0:
                hash = input("Please Paste The Hash To Crack: ")
                wordlist = input(
                    "Please Enter The Full Path To The Wordlist: ")
                infoprint('''
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
            elif choice == 2:
                zipfile = input("Please Enter The Target ZipFile: ")
                wordlist = input("Please Enter The Wordlist: ")
                Crypto.ZipCracker(zipfile, wordlist)
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
                    failprint("Invalid Algorithm")
                    return
                if hashsum == hash:
                    successprint(f"[*] Found Password: {w}\n")
                    return
                    break
            failprint("[-] Password Not Found.")
        else:
            failprint(
                f"The file {wordlist} either doesn't exist or is unreadable.")
            return

    def ShadowCracker(shadow, wordlist):
        if filecheckr(wordlist) == True:
            if filecheckr(shadow) == True:
                shfile = open(shadow, 'r')
                for line in shfile.readlines():
                    wlist = open(wordlist, 'r', encoding="EUC-JP")
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
                                successprint(
                                    f"[*] Password Found, User: {user} Password: {w}\t with hash: {crypthash}")
                                break
            else:
                failprint(
                    f"The file {shadow} either doesn't exist or is unreadable.")
        else:
            failprint(
                f"The file {wordlist} either doesn't exist or is unreadable.")

    def ZipCracker(zifile, wordlist):
        if filecheckr(zifile) == True:
            if filecheckr(wordlist) == True:
                isnew = False
                try:
                    zfile = zipfile.ZipFile(zifile)
                except:
                    failprint(f"The File {zifile}, Is Not A Zip File")
                    return
                try:
                    zfile.extractall(pwd="testing".encode())
                except NotImplementedError:
                    zfile = pyzipper.AESZipFile(zifile)
                    isnew = True
                except:
                    pass
                wlist = open(wordlist, 'r')
                for word in wlist.readlines():
                    try:
                        w = word.strip("\n")
                        if isnew:
                            zfile.setpassword(w.encode())
                            zfile.extractall()
                        else:
                            zfile.extractall(pwd=w.encode())
                        successprint(
                            f"Extraction Successful, The Password Is {w}")
                    except:
                        pass
            else:
                failprint(
                    f"The file {wordlist} either doesn't exist or is unreadable.")
        else:
            failprint(
                f"The file {zifile} either doesn't exist or is unreadable.")


class Web:
    def webintro():
        while True:
            infoprint('''
            Available Tools
                0 - Directory BruteForcing
                100 - Back To Main Menu
        ''')
            choice = int(input("Choose the desired tool's number: "))
            if choice == 0:
                url = input("Please enter the target URL (With http/https): ")
                wordlist = input("Please enter a fullpath of a wordlist: ")
                Web.DirectoryFuzzing(url, wordlist)
            elif choice == 100:
                break

    def DirectoryFuzzing(url, wordlist):
        if filecheckr(wordlist) == True:
            invresp = [500, 501, 502, 503, 504,
                       505, 506, 507, 508, 509, 510, 511, 404]
            hostup = False
            try:
                req = requests.get(url)
                successprint(
                    f"Host Is Up, Returned Response Code: {req.status_code}")
                hostup = True
            except:
                failprint(f"The URL: {url} Is Unavailable")
            if hostup:
                wlist = open(wordlist, 'r')
                for word in wlist.readlines():
                    w = word.strip("\n")
                    tryreq = requests.get(f"{url}/{w}")
                    if tryreq.status_code in invresp:
                        pass
                    else:
                        successprint(
                            f"The Path: /{w} Is Available, With Status Code: {str(tryreq.status_code)}")
        else:
            failprint(
                f"The file {wordlist} either doesn't exist or is unreadable.")

class Misc:
    def miscintro():
        while True:
            infoprint('''
            Available Tools
                0 - Wordlist Combiner
                100 - Back To Main Menu
        ''')
            choice = int(input("Choose the desired tool's number: "))
            if choice == 0:
                infoprint("Make Sure To Add A New Line At The End Of The First Wordlist.")
                finfile = input("Please enter the name of the file you wanna combine into: ")
                wordlist1 = input("Please enter the first wordlist: ")
                wordlist2 = input("Please enter the second wordlist: ")
                Misc.wordlistcombiner(finfile, wordlist1, wordlist2)
            elif choice == 100:
                break
    def wordlistcombiner(finfile, wordlist1, wordlist2):
        if filecheckr(finfile) and filecheckr(wordlist1) and filecheckr(wordlist2):
            successprint("[+] Reading Wordlists")
            wl1 = open(wordlist1, 'r').readlines()
            wl2 = open(wordlist2, 'r').readlines()
            finf = open(finfile, 'a')
            for line in wl1:
                finf.write(line)
            if wl1[-1] != '\n':
                finf.write("\n")
            for line in wl2:
                isrepeated = False
                finr = open(finfile, "r")
                for lin in finr.readlines():
                    if lin == line:
                        isrepeated = True
                        break
                if isrepeated == True:
                    pass
                else:
                    finf.write(line)
            successprint(f"Finished Merging Wordlists Into File: {finfile}")
        else:
            failprint(f"The files you entered don't exist or are unreadable.")


def main():
    while True:
        infoprint('''
        Available Modules
            0 - Cryptography
            1 - Networking
            2 - Web
            3 - Misc
            700 - exit
        ''')
        choice = int(input("Insert The Desired Module's Number: "))
        if choice == 0:
            Crypto.cryptointro()
        elif choice == 1:
            Networking.networkintro()
        elif choice == 2:
            Web.webintro()
        elif choice == 3:
            Misc.miscintro()
        elif choice == 700:
            print("I will miss you <3")
            break


if __name__ == "__main__":
    main()
