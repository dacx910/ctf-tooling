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

	# good luck pwning :)

	r.interactive()


if __name__ == "__main__":
	main()
