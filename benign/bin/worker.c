/*
 * worker.c -- tiny benign "worker" built in BOTH static (musl) and dynamic
 * (glibc) linkage. It exists to NEUTRALISE the CIC-YNU P7 loader-signature
 * shortcut: there, the first ~20 syscalls of a run (fcntl64, mmap2, statx,
 * set_thread_area / set_tid_address -- the dynamic-loader signature) gave
 * benign-vs-malware AUC 1.000, purely because the benign programs were all
 * dynamically linked and the malware statically linked.
 *
 * By shipping the SAME behaviour in both linkages (and requiring the malware
 * set to also span both -- see the campaign methodology), the first-k syscall
 * counts become 50/50 across classes and can no longer separate them.
 *
 * Behaviour (identical in both builds; deliberately overlaps execution-stage
 * host activity): open+read+write a temp file, do a TCP connect() health probe
 * to a KNOWN service (mirrors the discovery monitor -- NOT a scan), fork+exec a
 * short-lived child, poll with select(), then exit_group().
 *
 * Build: see Makefile (targets: worker-glibc-dynamic, worker-musl-static).
 * Usage: worker <health_host> <health_port>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void file_io(void) {
    char path[] = "/tmp/benign_worker_XXXXXX";
    int fd = mkstemp(path);
    if (fd >= 0) {
        for (int i = 0; i < 8; i++) {
            char buf[64];
            int n = snprintf(buf, sizeof buf, "benign line %d\n", i);
            if (write(fd, buf, n) < 0) break;
        }
        lseek(fd, 0, SEEK_SET);
        char rb[128];
        while (read(fd, rb, sizeof rb) > 0) { /* touch the data */ }
        close(fd);
        unlink(path);
    }
}

static void health_connect(const char *host, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &a.sin_addr) == 1) {
        /* best-effort liveness probe of a KNOWN endpoint; ignore result */
        if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) {
            fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
            struct timeval tv = { 0, 200000 };  /* 200 ms poll via select() */
            select(s + 1, &rf, NULL, NULL, &tv);
        }
    }
    close(s);
}

static void spawn_child(void) {
    pid_t pid = fork();
    if (pid == 0) {
        /* short-lived helper: prefer busybox true, fall back to /bin/true */
        execl("/bin/busybox", "busybox", "true", (char *)NULL);
        execl("/bin/true", "true", (char *)NULL);
        _exit(0);
    } else if (pid > 0) {
        int st; waitpid(pid, &st, 0);
    }
}

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : 8080;
    file_io();
    health_connect(host, port);
    spawn_child();
    return 0;   /* -> exit_group */
}
