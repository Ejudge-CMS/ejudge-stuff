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
    /* 23 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 3), \
    /* 24 */ BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, args[2]))), \
    /* 25 */ BPF_STMT(BPF_ALU+BPF_AND+BPF_K, 07), \
    /* 26 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), \
    /* 27 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS), \
 \
    /* 28 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
}

#define seccomp_prog(filter) { \
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])), \
    .filter = filter, \
}

#define setup_filter() prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L)

#define install_filter(prog) prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
