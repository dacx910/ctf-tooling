#!/usr/bin/env python3
from pwn import *

exe = ELF("BINARY_NAME")
rop = ROP(exe)

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

	rop(eax=0xcafebabe)

	log.info(rop.dump())

	offset = 0
	payload = flat({
		offset: rop.chain()
	})

	r.interactive()


if __name__ == "__main__":
	main()
