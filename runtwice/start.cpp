#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#ifndef INPUTFILE
#define INPUTFILE "input"
#endif

#define seccomp_fiter(prog_name) {                                                         \
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),               \
                                                                                           \
    /*  1 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fork, 0, 1),                         \
    /*  2 */ BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),                          \
                                                                                           \
    /*  3 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_vfork, 0, 1),                        \
    /*  4 */ BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),                          \
                                                                                           \
    /*  5 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_clone, 0, 1),                        \
    /*  6 */ BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),                          \
                                                                                           \
    /*  7 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_clone3, 0, 1),                       \
    /*  8 */ BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),                          \
                                                                                           \
    /*  9 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execveat, 0, 1),                     \
    /* 10 */ BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),                          \
                                                                                           \
    /* 11 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_memfd_create, 0, 1),                 \
    /* 12 */ BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),                          \
                                                                                           \
    /* 13 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_open, 0, 1),                         \
    /* 14 */ BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),                          \
                                                                                           \
    /* 15 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_unshare, 0, 1),                      \
    /* 16 */ BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),                          \
                                                                                           \
    /* 17 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_creat, 0, 1),                        \
    /* 18 */ BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),                          \
                                                                                           \
    /* 19 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execve, 0, 3),                       \
    /* 20 */ BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, args[0]))), \
    /* 21 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (uintptr_t)prog_name, 1, 0),              \
    /* 22 */ BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),                          \
                                                                                           \
    /* 23 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 0, 4),                       \
    /* 24 */ BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, args[2]))), \
    /* 25 */ BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 07),                                      \
    /* 26 */ BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                                 \
    /* 27 */ BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),                          \
                                                                                           \
    /* 28 */ BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),                                 \
}

#define seccomp_prog(flt) {                                \
    .len = (unsigned short)(sizeof(flt) / sizeof(flt[0])), \
    .filter = flt,                                         \
}

#define setup_filter() prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L)

#define install_filter(prog) prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)

extern char **environ;
static char program_name[PATH_MAX];
static int out, mfd[2][2];
static pid_t pid;
static int status;

void process_input();

void process_first_run();

void process_second_run();

int main(int argc, char *argv[]) {

    // Argparsing

    snprintf(program_name, sizeof(program_name), "%s", argv[1]);

    // Filter setup

    setup_filter();
    sock_filter filter[] = seccomp_fiter(program_name);
    sock_fprog prog = seccomp_prog(filter);

    // Pd opening

    out = dup(STDOUT_FILENO);
    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 2; ++j) {
            char name[100];
            snprintf(name, sizeof(name), "%d_%d", i, j);
            mfd[i][j] = memfd_create(name, MFD_CLOEXEC);
        }
    }

    // Process input

    fflush(stdin);
    dup2(mfd[0][0], STDOUT_FILENO);
    process_input();
    unlink(INPUTFILE);
    fflush(stdout);

    // First run

    pid = fork();
    if (!pid) {
        lseek(mfd[0][0], 0, SEEK_SET);
        dup2(mfd[0][0], STDIN_FILENO);
        dup2(mfd[0][1], STDOUT_FILENO);
        freopen("/dev/null", "w", stderr);
        close(out);
        install_filter(prog);
        execve(program_name, argv + 1, environ);
        fprintf(stderr, "Failed to invoke first run.");
        _exit(127);
    }
    waitpid(pid, &status, 0);
    if (status) {
        fprintf(stderr, "First run has exited with code %d.", WTERMSIG(status));
        _exit(127);
    }

    // Process first run

    fflush(stdin);
    lseek(mfd[0][1], 0, SEEK_SET);
    dup2(mfd[0][1], STDIN_FILENO);
    dup2(mfd[1][0], STDOUT_FILENO);
    process_first_run();
    fflush(stdout);

    // Second run

    pid = fork();
    if (!pid) {
        lseek(mfd[1][0], 0, SEEK_SET);
        dup2(mfd[1][0], STDIN_FILENO);
        dup2(mfd[1][1], STDOUT_FILENO);
        freopen("/dev/null", "w", stderr);
        close(out);
        install_filter(prog);
        execve(program_name, argv + 1, environ);
        fprintf(stderr, "Failed to invoke second run.");
        _exit(127);
    }
    waitpid(pid, &status, 0);
    if (status) {
        fprintf(stderr, "Second run has exited with code %d.", WTERMSIG(status));
        _exit(127);
    }

    // Second run processing

    fflush(stdin);
    lseek(mfd[1][1], 0, SEEK_SET);
    dup2(mfd[1][1], STDIN_FILENO);
    dup2(out, STDOUT_FILENO);
    process_second_run();
    fflush(stdout);

    // Fd closing

    close(out);
    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 2; ++j) {
            close(mfd[i][j]);
        }
    }

    return 0;
}
