# Контейнер изолированного запуска

Модифицированная версия контейнера для запуска недоверенных программ, написанная А.Черновым для тестирующей системы [Ejudge](https://ejudge.ru).

## Возможности

1. С помощью seccomp позволяет фильтровать системные вызовы (fork, exec, clone, unshare, memfd ...).
2. С помощью cgoup и namespaces умеет отсекать программы по времени и памяти.

## Инсталляция

Установите и скомпилируйте файл **suid-container.c** с заголовком **defines.h**.

## Использование

См. [инструкцию](https://ejudge.ru/wiki/index.php/Ej-suid-container).

## Дополнения

Также написан заголовочный файл **runtwice_seccomp.h**, предоставляющих возможность фильтрации системных вызовов. Для использования необходимо _отключить_ фильтрацию системных вызовов во встроенном контейнере, подключить заголовочный файл после всех _#include_, в начале функции main написать

```c++
int main() {
    setup_filter();
    snprintf(program_name, sizeof(program_name), argv[1]);
    struct sock_filter filter[] = seccomp_fiter(program_name);
    struct sock_fprog prog = seccomp_prog(filter);
    
    // etc ...
}
```

если вы хотите запустить решение:

```c++
// ...

int pid = fork();
if (!pid) {
    install_filter(prog);
    execve(program_name, NULL, NULL);
}

int status;
waitpid(pid, &status, 0);
if (status) {
    // your program has done something wrong ...
}

// ...
```