.PHONY: x86 x64 all clean

all: x64 x86
x64: vuln_x64
x86: vuln_x86
vuln_x64: vuln.c
	gcc -fno-stack-protector -no-pie -m64 vuln.c -o vuln_x64
vuln_x86: vuln.c
	gcc -fno-stack-protector -no-pie -m32 vuln.c -o vuln_x86
clean:
	@rm -f vuln_x64 vuln_x86
