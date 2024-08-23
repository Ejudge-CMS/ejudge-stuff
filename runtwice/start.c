#define _GNU_SOURCE
#include <linux/sched.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <stddef.h>
#include <linux/limits.h>
#include <stdint.h>

#define PIPESZ 1000000

#ifndef INPUTFILE
#define INPUTFILE "input"
#endif

static char program_name[PATH_MAX] = "";

 #define seccomp_fiter(prog_name) { \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr))), \
 \
    /*  1 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fork, 0, 1), \
    /*  2 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS), \
 \
    /*  3 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_vfork, 0, 1), \
    /*  4 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS), \
 \
    /*  5 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_clone, 0, 1), \
    /*  6 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS), \
 \
    /*  7 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_clone3, 0, 1), \
    /*  8 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS), \
 \
    /*  9 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execveat, 0, 1), \
    /* 10 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS), \
 \
    /* 11 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_memfd_create, 0, 1), \
    /* 12 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS), \
 \
    /* 13 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 0, 1), \
    /* 14 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS), \
 \
    /* 15 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_unshare, 0, 1), \
    /* 16 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS), \
 \
    /* 17 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_creat, 0, 1), \
    /* 18 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS), \
 \
    /* 19 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execve, 0, 3), \
    /* 20 */ BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, args[0]))), \
    /* 21 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (uintptr_t) prog_name, 1, 0), \
    /* 22 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS), \
 \
    /* 23 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 4), \
    /* 24 */ BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, args[2]))), \
    /* 25 */ BPF_STMT(BPF_ALU+BPF_AND+BPF_K, 07), \
    /* 26 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), \
    /* 27 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS), \
 \
    /* 28 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
}

#define seccomp_prog(flt) { \
    .len = (unsigned short)(sizeof(flt) / sizeof(flt[0])), \
    .filter = flt, \
}

#define setup_filter() prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L)

#define install_filter(prog) prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)

static int out;
static int tin[2];
static int tout[2];

static int status;
static pid_t pid;

void prepare(int *pp) {
    fcntl(pp[1], F_SETPIPE_SZ, PIPESZ);
}

void clearpipe(int *pp) {
    close(pp[0]); close(pp[1]);
    pipe2(pp, O_NONBLOCK | O_CLOEXEC);
}

void process_input();

void process_first_run();

void process_final();

int main(int argc, char* argv[]) {

    setup_filter();
    snprintf(program_name, sizeof(program_name), "%s", argv[1]);

    struct sock_filter filter[] = seccomp_fiter(program_name);
    struct sock_fprog prog = seccomp_prog(filter);

    out = dup(STDOUT_FILENO);

    pipe2(tin, O_NONBLOCK | O_CLOEXEC); prepare(tin);
    pipe2(tout, O_NONBLOCK | O_CLOEXEC); prepare(tout);
    
    dup2(tin[1], STDOUT_FILENO);
    process_input();
    fflush(stdin); fflush(stdout);

    unlink(INPUTFILE);

    pid = fork();
    if (!pid) {
        dup2(tin[0], STDIN_FILENO);
        dup2(tout[1], STDOUT_FILENO);
        install_filter(prog);
        execve(program_name, NULL, NULL);
    }

    waitpid(pid, &status, 0);
    if (status) _exit(127);
    
    clearpipe(tin);
    dup2(tout[0], STDIN_FILENO); dup2(tin[1], STDOUT_FILENO);
    process_first_run();
    fflush(stdin); fflush(stdout);
    clearpipe(tout);

    pid = fork();
    if (!pid) {
        dup2(tin[0], STDIN_FILENO);
        dup2(tout[1], STDOUT_FILENO);
	    install_filter(prog);
        execve(program_name, NULL, NULL);
    }

    waitpid(pid, &status, 0);
    if (status) _exit(127);

    dup2(tout[0], STDIN_FILENO); dup2(out, STDOUT_FILENO);
    process_final();
    fflush(stdin); fflush(stdout);

    close(tin[0]); close(tout[0]); close(tin[1]); close(tout[1]); close(out);
}
