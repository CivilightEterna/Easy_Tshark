#include <string>
#ifdef _WIN32
#include <windows.h>
#include <io.h> // for _open_osfhandle
#include <fcntl.h>// for _O_RDONLY
typedef DWORD PID_T;
#else
#include <sys/types.h>
typedef pid_t PID_T;
#endif
#include"misc_util.hpp"
class ProcessUtil {
public:
    //linux/macOS
#if defined(__unix__) || defined(__APPLE__)
    static FILE* PopenEx(std::string command, PID_T* pidOut = nullptr) {
        int pipefd[2] = { 0 };
        FILE* pipeFp = nullptr;
        if (pipe(pipefd == -1)) {
            perror("pipe");
            return nullptr;
        }
        pid_t pid = fork();
        if (pid == -1) {
            perror("fork");
            close(pipefd([0]));
            close(pipefd[1]);
            return nullptr;
        }
        if (pid == 0) {
            //子进程
            close(pipefd[0]); // 关闭读端
            dup2(pipefd[1], STDOUT_FILENO); // 将stdout重定向到管道
            close(pipefd[1]); // 关闭写端
            execl("/bin/sh", "sh", "-c", command.c_str, NULL);//执行命令
            _exit(1);// 如果execl失败，退出子进程
        }
        // 父进程将读取管道,关闭写端
        close(pipefd[1]);
        pipeFd = fdopen(pipefd[0], "r");
        if (pidOut) {
            *pidOut = pid; // 返回子进程的PID
        }
        return pipeFp; // 返回管道的文件指针
    }
    static int Kill(PID_T pid) {
        return kill(pid, SIGKILL); // 发送SIGKILL信号
    }
#endif
public:
    //windows
#ifdef _WIN32
    static FILE* PopenEx(std::string command, PID_T* pidOut = nullptr) {
        //  Windows平台要转换，否则执行tshark时候，命令行参数有中文（比如网卡名）会乱码
        command = MiscUtil::UTF8ToANSIString(command);
       
        HANDLE hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES saAttr;
        PROCESS_INFORMATION piProcInfo;
        STARTUPINFO siStartInfo;
        FILE* pipeFp = nullptr;
        // 设置安全属性以允许继承句柄
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = nullptr;
        // 创建匿名管道
        if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
            perror("CreatePipe");
            return nullptr;
        }
        //确保句柄不被子进程继承
        if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
            perror("SetHandleInformation");
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return nullptr;
        }
        // 初始化STARTUPINFO结构体
        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
        ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
        siStartInfo.cb = sizeof(STARTUPINFO);
        siStartInfo.hStdError = hWritePipe;
        siStartInfo.hStdOutput = hWritePipe;
        siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
        // 创建子进程
        if (!CreateProcessA(
            nullptr,                        // No module name (use command line)
            (LPSTR)command.data(),                                          // Command line
            nullptr,                        // Process handle not inheritable
            nullptr,                        // Thread handle not inheritable
            TRUE,                           // Set handle inheritance
            CREATE_NO_WINDOW,               // No window
            nullptr,                        // Use parent's environment block
            nullptr,                        // Use parent's starting directory 
            &siStartInfo,                   // Pointer to STARTUPINFO structure
            &piProcInfo                     // Pointer to PROCESS_INFORMATION structure
        )) {
            perror("CreateProcess");
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return nullptr;
        }
        // 关闭写端句柄("父进程不使用")
        CloseHandle(hWritePipe);
        //返回子进程PID
        if (pidOut) {
            *pidOut = piProcInfo.dwProcessId;
        }
        // 将管道的读取端转换为FILE指针并返回
        pipeFp = _fdopen(_open_osfhandle(reinterpret_cast<intptr_t>(hReadPipe), _O_RDONLY), "r");
        if (!pipeFp) {
            CloseHandle(hReadPipe);
        }
        // 关闭进程句柄(不需要等待子进程)
        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);
        return pipeFp; // 返回管道的文件指针
    }
    static int Kill(PID_T pid) {

        // 打开指定进程
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess == nullptr) {
            std::cout << "Failed to open process with PID " << pid << ", error: " << GetLastError() << std::endl;
            return -1;
        }

        // 终止进程
        if (!TerminateProcess(hProcess, 0)) {
            std::cout << "Failed to terminate process with PID " << pid << ", error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return -1;
        }

        // 成功终止进程
        CloseHandle(hProcess);
        return 0;
    }

#endif
};