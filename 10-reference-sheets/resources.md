<!-- TITLE: Resources -->
<!-- SUBTITLE: Miscellaneous noteworthy resources from around the web-->

# HTB Walkthroughs

## IPPSEC Videos

### Celestial

00:58 - Begin of Recon
03:00 - Looking at the web application and finding the Serialized Cookie
04:38 - Googling for Node JS Deserialization Exploits
06:30 - Start of building our payload
07:10 - Examining Node-Serialize to see what the heck _$$ND_FUNC$$_ is
09:10 - Moving our serialized object to "Name", hoping to get to read stdout
11:30 - Really busing the deserialize function by removing the Immediately Invokked Expression (IIFE)
13:25 - Failing to convert an object (stdout) to string.
14:02 - Verifying code execution via ping
15:32 - Code execution verified, gaining a shell
(Get a shell via NodeJSShell at end of video)
18:49 - Reverse shell returned, running LinEnum.sh
21:26 - Examining logs to find the Cron Job running as root
22:09 - Privesc by placing a python root shell in script.py
24:15 - Going back and getting a shell with NodeJSShell

[video](https://www.youtube.com/watch?v=aS6z4NgRysU){.youtube}


### Oz

00:50 - Start of the box
05:30 - Attempting GoBuster but wildcard response gives issue
07:40 - Start of doing wfuzz to find content
10:38 - Manually testing SQLInjection
13:07 - Running SQLMap and telling it exactly where the injection is
16:04 - Manually extracting files with the SQL Injection
19:50 - Cracking the hash with hashcat
25:00 - Start of examining the custom webapp, playing with Template Injection
27:00 - Explaining a way to enumerate language behind a webapp
35:17 - Reverse Shell returned on first Docker Container
38:00 - Examining SQL Database
39:40 - Doing the Port Knock to open up SSH
43:50 - Gain a foothold on the host of the docker container via ssh
46:00 - Identifying containers running
50:10 - Creating SSH Port Forwards without exiting SSH Session then NMAP through
 SSH
55:11 - Begin looking into Portainer, finding a weak API Endpoint
59:00 - Start of creating a container in portainer that can access the root file
 system
01:08:25 - Changing sudoers so dorthy can privesc to root
01:09:50 - Lets go back and create a python script to play with SQL Injection

https://www.youtube.com/watch?v=yX00n1UmalE

### Mischief

01:20 - Begin of NMAP
02:30 - Extra nmaps, SNMP and AllPorts
04:00 - Playing with OneSixtyOne (SNMP BruteForce)
07:00 - Looking at SNMPWalk Output
08:40 - Installing SNMP Mibs so SMPWalk is readable
10:05 - Accessing the box over Link Local IPv6 Address
14:00 - Looking at Por 3366 (Website), getting PW from SNMP Info
17:50 - Getting IPv6 Routable Address via SNMP
19:20 - NMAP the IPv6 Address
21:00 - Accessing the page over IPv6
23:00 - Getting output from the command execution page
24:55 - Viewing Credentials Files and accessing the box via SSH
29:00 - Examining why loki cannot use /bin/su (getfacl)
31:00 - Getting a shell as www-data
38;10 - Finding the root.txt file from using find command to search for files by
 date
40:30 - Extra content, reading files via ICMP

https://www.youtube.com/watch?v=GKo6xoB1g4Q
