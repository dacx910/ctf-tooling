from pwn import *
import sys

exe = ELF("EXE_NAME", checksec=False)

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

		# recv until the input area

		maps = r.maps()

		# send leakStack(i)

		addr = r.recvline() # modify to receive the address

		findInteresting(maps, addr, i)

		close(r)

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print(f"Usage: {sys.argv[0]} [start] [stop]",file=sys.stderr)
		exit(1)
	start = int(sys.argv[1])
	stop = int(sys.argv[2])
	if start < 1 or stop < start:
		print("Invalid start-stop bounds", file=sys.stderr)
		exit(2)
	context.log_level = 'error'
	main(start,stop)
