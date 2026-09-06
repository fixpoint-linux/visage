/* outbox_dkim_verify.c — test helper: verify a DKIM-Signature against a public
 * key PEM file.  Reads the message and the public key, calls dkim_verify_key
 * (src/dkim.c), and prints "VERIFIED" / "FAILED".  Exit 0 on VERIFIED.
 *
 * Usage: outbox_dkim_verify MSG PEM
 */
#include "dkim.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static char *read_file(const char *path, size_t *outlen) {
    struct stat st;
    int fd;
    char *buf;
    size_t off = 0;
    *outlen = 0;
    fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    if (fstat(fd, &st) != 0 || st.st_size < 0) { close(fd); return NULL; }
    buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return NULL; }
    while (off < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + off, (size_t)st.st_size - off);
        if (r < 0) { free(buf); close(fd); return NULL; }
        if (r == 0) break;
        off += (size_t)r;
    }
    close(fd);
    buf[off] = '\0';
    *outlen = off;
    return buf;
}

int main(int argc, char **argv) {
    char *msg, *pem;
    size_t msglen, pemlen;
    int r;

    if (argc != 3) {
        fprintf(stderr, "usage: outbox_dkim_verify MSG PEM\n");
        return 2;
    }
    msg = read_file(argv[1], &msglen);
    pem = read_file(argv[2], &pemlen);
    if (!msg || !pem) {
        fprintf(stderr, "outbox_dkim_verify: cannot read inputs\n");
        return 2;
    }
    (void)pemlen;
    r = dkim_verify_key(msg, msglen, pem);
    if (r == 0) {
        printf("VERIFIED\n");
        return 0;
    }
    printf("FAILED (%d)\n", r);
    return 1;
}
