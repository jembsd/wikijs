<!-- TITLE: Discovery -->
<!-- SUBTITLE: A quick summary of Discovery -->

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

## Masscan

TODO

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

When port scanning a host, you will be presented with a list of open ports. In many cases, the port number tells you which application is running. Port 25 is usually SMTP, port 80 mostly HTTP. However, this is not always the case, and especially when dealing with proprietary protocols running on non-standard ports you will not be able to determine which application is running.

By using **amap**, we can identify which services are running on a given port. For example is there a SSL server running on port 3445 or some oracle listener on port 23? Note that the application can also handle services that requires SSL. Therefore it will perform an SSL connect followed by trying to identify the SSL-enabled protocol!. e.g. One of the vulnhub VM’s was running http and https on the same port.

    amap -A 192.168.1.2 12380
    amap v5.4 (www.thc.org/thc-amap) started at 2016-08-10 05:48:09 - APPLICATION MAPPING mode
    Protocol on 192.168.1.2:12380/tcp matches http
    Protocol on 192.168.1.2:12380/tcp matches http-apache-2
    Protocol on 192.168.1.2:12380/tcp matches ntp
    Protocol on 192.168.1.2:12380/tcp matches ssl
    Unidentified ports: none.
    amap v5.4 finished at 2016-08-10 05:48:16
