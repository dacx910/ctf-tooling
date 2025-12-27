#!/usr/bin/env python3
from pwn import *

exe = ELF("BINARY_NAME", checksec=False)

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
	
	# Data stuff here

	offset = 0
	payload = flat({
		offset: b'DATA_HERE'
	})
	r.sendlineafter(b'DELIM_HERE', payload)

	r.interactive()


if __name__ == "__main__":
	main()
