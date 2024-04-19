#include "runtwice_seccomp.h"

static int in, out;
static int tin[2];
static int tout[2];

static int ret;
static int status;
static pid_t pid;

static void __attribute__((format(printf, 3, 4), noreturn))
ffatal(int result, int code, const char *format, ...)
{
    dup2(in, STDIN_FILENO); dup2(out, STDOUT_FILENO);
    printf("%d\n", result);
    char buf[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    fprintf(stderr, "%s\n", buf);
    _exit(code);
}

void process_input() {
    // your code here ...
}

void process_first_run() {
    // your code here ...
}

void process_final() {
    // your code here ...
}

int main(int argc, char* argv[]) {

    setup_filter();
    snprintf(program_name, sizeof(program_name), "%s", argv[1]);

    struct sock_filter filter[] = seccomp_fiter(program_name);
    struct sock_fprog prog = seccomp_prog(filter);

    in = dup(STDIN_FILENO);
    out = dup(STDOUT_FILENO);

    pipe(tin); pipe(tout);

    dup2(tin[1], STDOUT_FILENO);
    process_input();
    fflush(stdin); fflush(stdout);

    pid = fork();
    if (!pid) {
        close(tin[1]); close(tout[0]);
        dup2(tin[0], STDIN_FILENO);
        dup2(tout[1], STDOUT_FILENO);
        close(tin[0]); close(tout[1]);
        close(in); close(out);
        install_filter(prog);
        execve(program_name, NULL, NULL);
    }

    waitpid(pid, &status, 0);
    if (status) ffatal(1, 127, "Runtime error (first run): exit code %d\n", status);

    dup2(tout[0], STDIN_FILENO); dup2(tin[1], STDOUT_FILENO);
    process_first_run();
    fflush(stdin); fflush(stdout);
    
    pid = fork();
    if (!pid) {
        close(tin[1]); close(tout[0]);
        dup2(tin[0], STDIN_FILENO);
        dup2(tout[1], STDOUT_FILENO);
        close(tin[0]); close(tout[1]);
        install_filter(prog);
        execve(program_name, NULL, NULL);
    }

    waitpid(pid, &status, 0);
    if (status) ffatal(1, 127, "Runtime error (second run): exit code %d\n", status);

    dup2(tout[0], STDIN_FILENO); dup2(out, STDOUT_FILENO);
    process_final();
    fflush(stdin); fflush(stdout);

    dup2(in, STDIN_FILENO);
    close(in); close(tin[0]); close(tout[0]); close(tin[1]); close(tout[1]); close(out);
}
