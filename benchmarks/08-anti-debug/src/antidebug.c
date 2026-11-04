/* Benchmark 8: two debugger checks in front of a message that is decoded at run time. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

#define MESSAGE_KEY 0x2a

static const unsigned char MESSAGE[] = {0x65, 0x78, 0x69, 0x62, 0x63, 0x6e, 0x07, 0x1e, 0x18};

static int ptrace_is_taken(void) {
    return ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1;
}

static int status_shows_a_tracer(void) {
    char line[128];
    int traced = 0;
    FILE *status = fopen("/proc/self/status", "r");
    if (status == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), status) != NULL) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            traced = atoi(line + 10) != 0;
            break;
        }
    }
    fclose(status);
    return traced;
}

int main(void) {
    if (status_shows_a_tracer() || ptrace_is_taken()) {
        puts("Nothing to see here.");
        return 0;
    }
    printf("The launch code is ");
    for (size_t index = 0; index < sizeof(MESSAGE); index++) {
        putchar(MESSAGE[index] ^ MESSAGE_KEY);
    }
    putchar('\n');
    return 0;
}
