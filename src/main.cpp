#include <vector>
#include <memory>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  // enable all GNU speific features
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>

#define STACK_SIZE (1024 * 1024)  // 1M
static char container_stack[STACK_SIZE];

class CommandArgs
{
public:
    CommandArgs() {}

    ~CommandArgs()
    {
        for (::std::size_t i = 0; i < args.size(); ++i) {
            delete args[0];
        }
        args.clear();
    }

    void AddArg(const char* str)
    {
        args.push_back(new char[strlen(str) + 1]);
        strcpy(args.back(), str);
    }

    char** GetExecArgs()
    {
        args.push_back(NULL);
        return &args[0];
    }

private:
    CommandArgs(const CommandArgs&);
    CommandArgs& operator=(const CommandArgs&);

    ::std::vector<char*> args;
};

int pipefd[2];

void set_map(char* file, int inside_id, int outside_id, int len) {
    FILE* mapfd = fopen(file, "w");
    if (NULL == mapfd) {
        perror("open file error");
        return;
    }
    fprintf(mapfd, "%d %d %d", inside_id, outside_id, len);
    fclose(mapfd);
}

void set_uid_map(pid_t pid, int inside_id, int outside_id, int len) {
    char file[256];
    sprintf(file, "/proc/%d/uid_map", pid);
    set_map(file, inside_id, outside_id, len);
}

void set_gid_map(pid_t pid, int inside_id, int outside_id, int len) {
    char file[256];
    sprintf(file, "/proc/%d/gid_map", pid);
    set_map(file, inside_id, outside_id, len);
}


int container_main(void* arg)
{
    // no need to delete it because we execv finally.
    CommandArgs* args = reinterpret_cast<CommandArgs*>(arg);

    printf("Container [%d] - inside the container!\n", getpid());

    printf("Container: eUID = %ld;  eGID = %ld, UID=%ld, GID=%ld\n",
            (long) geteuid(), (long) getegid(), (long) getuid(), (long) getgid());

    char ch;
    close(pipefd[1]);
    int ret = read(pipefd[0], &ch, 1);
    if (ret < 0) {
        printf("Error: read failed: %d, %s\n", errno, strerror(errno));
        return 1;
    }

    close(pipefd[0]);

    printf("Container: eUID = %ld;  eGID = %ld, UID=%ld, GID=%ld\n",
            (long) geteuid(), (long) getegid(), (long) getuid(), (long) getgid());

    mount("proc", "/proc", "proc", 0, NULL);
    char** argv = args->GetExecArgs();
    execv(argv[0], argv);
    printf("Something's wrong!\n");
    return 1;
}

int main(int argc, char** argv)
{
    char* command = const_cast<char*>("/bin/bash");
    if (argc >= 2) {
        command = argv[1];
    }

    const int gid=getgid(), uid=getuid();

    printf("Parent: eUID = %ld;  eGID = %ld, UID=%ld, GID=%ld\n",
            (long) geteuid(), (long) getegid(), (long) getuid(), (long) getgid());

    int ret = pipe(pipefd);
    if (ret < 0) {
        printf("Error: pipe failed: %d, %s\n", errno, strerror(errno));
        exit(1);
    }

    printf("Parent [%d] - start a container!\n", getpid());

    ::std::auto_ptr<CommandArgs> container_args(new CommandArgs);
    container_args->AddArg(command);

    int clone_flags = SIGCHLD | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER;
    int container_pid = clone(container_main,
            container_stack + STACK_SIZE, clone_flags, container_args.get());
    if (container_pid < 0) {
        printf("Error: clone failed: %d, %s\n", errno, strerror(errno));
        exit(1);
    }

    printf("Parent [%5d] - Container [%5d]!\n", getpid(), container_pid);

    // map current user to root in child namespace
    set_uid_map(container_pid, 0, uid, 1);
    set_gid_map(container_pid, 0, gid, 1);
    printf("Parent [%5d] - user/group mapping done!\n", getpid());

    close(pipefd[0]);
    close(pipefd[1]);

    int container_status = 0;
    waitpid(container_pid, &container_status, 0);
    printf("Parent - container stopped! status: %d\n", container_status);
    return 0;
}



