/*
 * test_read.c - Simple file reader for testing DYLD_INSERT_LIBRARIES
 *
 * System binaries like /bin/cat are SIP-protected and strip DYLD_* variables.
 * This custom binary is not restricted, so DYLD_INSERT_LIBRARIES works.
 *
 * Usage:
 *   cc -o test_read test_read.c
 *   DYLD_INSERT_LIBRARIES=./libcontextfilter.dylib ./test_read CLAUDE.md
 */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        write(1, buf, n);
    }
    close(fd);
    return 0;
}
