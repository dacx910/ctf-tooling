#!/usr/bin/env python3
from pwn import *

exe = ELF("BINARY_NAME")

context.binary = exe


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

	offset = 0 # The offset in the stack that our input exists at
	writes = {0x0: 0x1337babe, # Write 0x1337babe to 0x0
			  0x1337babe: 0x0} # Write 0x0 to 0x1337babe
	nWritten = 0 # Bytes written before our fstr is printed (will affect %n)

	payload = fmtstr_payload(offset, writes, numbwritten=nWritten)

	r.sendlineafter(b'', payload)

	r.interactive()


if __name__ == "__main__":
	main()
