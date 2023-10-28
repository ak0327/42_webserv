#include <unistd.h>
#include <stdio.h>

#include <unistd.h>

int main() {
    const char* pythonPath = "test.py";
    char* const args[] = {const_cast<char*>(pythonPath), NULL};
    char* const env[] = {NULL};

    execve(pythonPath, args, env);
    perror("execve");
    return 1;
}
