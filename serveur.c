#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <signal.h>

#define DEFAULT_PORT 2021

#define MAX_CLIENT 500
#define MAX_CLIENT_DEFAULT 100

#define PORT_ARG "-p"
#define MAX_CLIENT_ARG "-m"

#define WARNING_TIMEOUT 5000000
#define TIMEOUT 1800000000
#define SELECT_INTERVAL_SEC 5

#define SERVER_SHUTDOWN_COMMAND "shutdown"

#define BUFFER_SIZE 2048
#define DATE_SIZE 14
#define NAME_SIZE 20
#define HEADER_SEPARATOR ':'

#define SERVER_MSG_COMMAND 0
#define SERVER_COMMAND 1
#define SERVER_ERROR_COMMAND 2
#define SERVER_KICK_COMMAND 3
#define SERVER_JOIN_COMMAND 4
#define SERVER_LEAVE_COMMAND 5

#define CLIENT_LEAVE_COMMAND 0
#define CLIENT_NAME_COMMAND 1
#define CLIENT_MSG_COMMAND 2

#define KICK_MSG_NAME_NOT_VALID 0
#define KICK_MSG_NAME_ALREADY_USED 1
#define KICK_MSG_TIMEOUT 2
#define KICK_MSG_SERVER_FULL 3
#define KICK_MSG_COMMUNICATION_FAILED 4
#define KICK_MSG_LEFT 5
#define KICK_MSG_SERVER_SHUTDOWN 6

#define KICK_MSG_SEND_TO_NOBODY 0
#define KICK_MSG_SEND_TO_ALL 1

const int HEADER_SIZE = DATE_SIZE + NAME_SIZE + 4;

typedef struct client client;
struct client {
  client* next;
  char* name;
  struct sockaddr_in* udp;
  int tcp;
  int warning_sent;
  long last_msg;
};

typedef struct list_client {
  int size;
  client* first;
} list_client;

int isTCP(client* c) {
    return (c->udp == NULL ? 1 : 0);
}

void add_client(list_client *lst, client *c){
    lst->size += 1;
    c->next = lst->first;
    lst->first = c;
}

void free_client(client *client){
  if(isTCP(client)){
    shutdown(client->tcp, SHUT_RDWR);
    close(client->tcp);
  }

  if(client->udp != NULL)
    free(client->udp);
  if(client->name != NULL)
    free(client->name);
  free(client);
}

void rm_client(list_client *lst, client *c){
    client* clt = lst->first;

    if(clt == c) {
        lst->first = clt->next;
        free_client(c);
        lst->size--;
    }

    while(clt != NULL){
        if(clt->next == c){
            clt->next = c->next;
            free_client(c);
            lst->size--;
        }
        clt = clt->next;
    }
}

client* find_client_UDP(list_client *lst, struct sockaddr_in* udp){
  client* c = lst->first;
  while(c != NULL){
    if(isTCP(c)){
      c = c->next;
      continue;
    }
    if(c->udp->sin_addr.s_addr == udp->sin_addr.s_addr && c->udp->sin_port == udp->sin_port){
      return c;
    }
    c = c->next;
  }
  return NULL;
}

client* find_client_TCP(list_client *lst, int tcp){
  client* c = lst->first;
  int i = 0;
  while(c != NULL){
    if(isTCP(c)){
      if(c->tcp == tcp){
        return c;
      }
    }
    printf("\n");
    c = c->next;
    i++;
  }
  return NULL;
}

long get_time() {
    struct timeval time;

    gettimeofday(&time, NULL);
    return time.tv_usec + time.tv_sec * 1000000;
}

long get_time_passed(long start) {
    return (get_time() - start);
}

int check_args(int argc, char *argv[], unsigned short int *port, int* maxc){
    for(int i = 0; i < argc; i++){
        if(strcmp(argv[i], PORT_ARG) == 0){
            if(i+1 <= argc){
                int p = atoi(argv[i+1]);

                if(p == 0){
                    printf("Le port n'est pas un nombre, utilisation du port par défaut : %d\n", DEFAULT_PORT);
                } else if (p < 1024 || p > 65535) {
                    printf("Le port doit être compris entre 1024 et 65535 inclus, utilisation du port par défaut : %d\n", DEFAULT_PORT);
                } else
                    *port = p;
            }
        } else if(strcmp(argv[i], MAX_CLIENT_ARG) == 0){
            if(i+1 <= argc){
                int c = atoi(argv[i+1]);

                if(c == 0){
                    printf("Le nombre de client max n'est pas un nombre, utilisation du nombre par défaut : %d\n", MAX_CLIENT_DEFAULT);
                } else if (c < 2 || c > MAX_CLIENT) {
                    printf("Le port doit être compris entre 2 et %d inclus, utilisation du nombre par défaut : %d\n", MAX_CLIENT, MAX_CLIENT_DEFAULT);
                } else
                    *maxc = c;
            }
        }
    }

    return 1;
}

int create_socket(int type) {
    int s = socket(AF_INET, type, 0);

    if(s == -1)
        return 0;

    return s;
}

int bind_socket(struct sockaddr_in* saddr, int socket, int port) {
    saddr->sin_addr.s_addr = htonl(INADDR_ANY);
    saddr->sin_family = AF_INET;
    saddr->sin_port = htons(port);

    if(bind(socket, (struct sockaddr*) saddr, sizeof(*saddr)) != 0)
        return 0;

    return 1;
}

int openTCP(int* socket, int port, struct sockaddr_in* saddr, int max_client) {
    *socket = create_socket(SOCK_STREAM);

    if(!socket) {
        perror("Error openTCP() : invalid socket");
        return 0;
    }

    if(!bind_socket(saddr, *socket, port)) {
        perror("Error openTCP() : port TCP indisponible");
        return 0;
    }

    if(listen(*socket, max_client) != 0) {
        perror("Error openTCP() : listen error");
        return 0;
    }

    return 1;
}

int openUDP(int* socket, int port, struct sockaddr_in* saddr) {
    *socket = create_socket(SOCK_DGRAM);

    if(!socket) {
        perror("Error openUDP() : invalid socket");
        return 0;
    }

    if(!bind_socket(saddr, *socket, port)) {
        perror("Error openUDP() : port UDP indisponible");
        return 0;
    }

    return 1;
}

char* create_msg(int type, char* name, char* msg) {
    time_t t = time(NULL);
    struct tm* tm = localtime(&t);
    char* dest = (char*) malloc(sizeof(char) * strlen(msg) + HEADER_SIZE);

    sprintf(dest, "%d%c%s%c%04d%02d%02d%02d%02d%02d%c%s", type, HEADER_SEPARATOR, name, 
        HEADER_SEPARATOR, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, 
        tm->tm_min, tm->tm_sec, HEADER_SEPARATOR, msg);

    return dest;
}

int readTCP(int socket, char* buff, int buff_size) {
    return read(socket, buff, buff_size);
}

int readUDP(int socket, char* buff, int buff_size, struct sockaddr_in* saddr) {
    unsigned int sof = sizeof(*saddr);
    return recvfrom(socket, buff, buff_size, 0, (struct sockaddr*) saddr, &sof);
}

int sendTCP(int socket, char* buff, int buff_size) {
    return write(socket, buff, buff_size);
}

int sendUDP(int socket, char* buff, int buff_size, struct sockaddr_in* saddr) {
    unsigned int sof = sizeof(*saddr);
    return sendto(socket, buff, buff_size, 0, (struct sockaddr*) saddr, sof);
}

void client_left(list_client* clients, int socketUDP, fd_set* set, client* c);
void kick(int socketUDP, list_client* clients, client* c, fd_set* set, int reason, int toall);
void send_all(list_client* clients, int socketUDP, char* buff, int buff_size, fd_set* set,
        client* from) {
    client* c = clients->first;

    while(c != NULL) {
        int err = 0;

        if(from != NULL && strcmp(from->name, c->name) == 0) {
            c = c->next;
            continue;
        }

        if(isTCP(c)) {
            if(sendTCP(c->tcp, buff, buff_size) <= 0)
                err = 1;
        } else  {
            if(sendUDP(socketUDP, buff, buff_size, c->udp) <= 0)
                err = 1;
        }

        if(err)
            kick(socketUDP, clients, c, set, KICK_MSG_COMMUNICATION_FAILED, KICK_MSG_SEND_TO_ALL);

        c = c->next;
    }
}

void client_left(list_client* clients, int socketUDP, fd_set* set, client* c) {
    char* msg = create_msg(SERVER_LEAVE_COMMAND, c->name, "");

    send_all(clients, socketUDP, msg, strlen(msg), set, c);
    free(msg);
}

void kick(int socketUDP, list_client* clients, client* c, fd_set* set, int reason, int toall) {
    char msg[8];

    sprintf(msg, "%d", reason);
    char* dest = create_msg(SERVER_KICK_COMMAND, "", msg);

    if(isTCP(c)) {
        sendTCP(c->tcp, dest, strlen(dest));
        FD_CLR(c->tcp, set);
    } else
        sendUDP(socketUDP, dest, strlen(dest), c->udp);

    if(toall)
        client_left(clients, socketUDP, set, c);

    free(dest);
    rm_client(clients, c);
}

int is_name_set(client* c) {
    return (c->name == NULL ? 0 : 1);
}

int is_name_valid(char* name) {
    int len = strlen(name);

    if(len < 1 || len > NAME_SIZE || strchr(name, HEADER_SEPARATOR))
        return 0;

    return 1;
}

int is_client_name_used(list_client *lst, client* clt){
  client* c = lst->first;
  while(c != NULL){
    if(c != clt && strcmp(c->name, clt->name) == 0)
      return 1;
    c = c->next;
  }
  return 0;
}

int is_type(char* buff, int type) {
    char str[2];
    char* end;

    str[0] = buff[0];
    str[1] = '\0';

    int command = strtol(str, &end, 10);

    if((command == 0 && strcmp(str, end) == 0) || command != type)
        return 0;

    return 1;
}

int check_name(list_client* clients, client* c, char* buff, int buff_size) {
    if(!is_type(buff, CLIENT_NAME_COMMAND))
        return KICK_MSG_NAME_NOT_VALID;
    else {
        char* name = (char*) malloc(sizeof(char) * NAME_SIZE + 1);

        buff[NAME_SIZE + 2] = '\0';
        strcpy(name, &buff[2]);
        name[strlen(&buff[2])] = '\0';
        c->name = name;

        if(!is_name_valid(c->name))
            return KICK_MSG_NAME_NOT_VALID;
        else if(is_client_name_used(clients, c))
            return KICK_MSG_NAME_ALREADY_USED;
    }

    return -1;
}

void clear_stdin() {
    while(getchar() != '\n');
}

void TCP_clients(int socketTCP, int socketUDP, int socket, fd_set* set, list_client* clients, 
        int maxc, int* maxs) {

    if(socket == socketTCP) {
        client* new = (client*) malloc(sizeof(client));

        new->next = NULL;
        new->name = NULL;
        new->udp = NULL;
        new->last_msg = get_time();
        new->warning_sent = 0;
        new->tcp = accept(socketTCP, NULL, NULL);
        add_client(clients, new);
        FD_SET(new->tcp, set);

        if(clients->size > maxc) {
            kick(socketUDP, clients, new, set, KICK_MSG_SERVER_FULL, KICK_MSG_SEND_TO_NOBODY);
        } else if(*maxs < new->tcp) {
            *maxs = new->tcp;
        }
    } else {
        char buff[BUFFER_SIZE];
        int n = readTCP(socket, buff, BUFFER_SIZE - 1);
        client* c = find_client_TCP(clients, socket);

        if(n <= 0) {
            int flag = is_name_set(c) ? KICK_MSG_SEND_TO_ALL : KICK_MSG_SEND_TO_NOBODY;
            kick(socketUDP, clients, c, set, KICK_MSG_COMMUNICATION_FAILED, flag);
        } else {
            c->last_msg = get_time();
            c->warning_sent = 0;
            buff[n] = '\0';
            
            if(!is_name_set(c)) {
                int a;

                if( ( a = check_name(clients, c, buff, strlen(buff)) ) > -1 ) {
                    kick(socketUDP, clients, c, set, a, KICK_MSG_SEND_TO_NOBODY);
                } else {
                    char* dest = create_msg(SERVER_JOIN_COMMAND, c->name, "");
                    send_all(clients, socketUDP, dest, strlen(dest), set, c);
                    free(dest);
                }
            } else if(is_type(buff, CLIENT_LEAVE_COMMAND)) {
                kick(socketUDP, clients, c, set, KICK_MSG_LEFT, KICK_MSG_SEND_TO_ALL);
             } else if(is_type(buff, CLIENT_MSG_COMMAND)) {
                char* dest = create_msg(SERVER_MSG_COMMAND, c->name, &buff[2]);
                send_all(clients, socketUDP, dest, strlen(dest), set, c);
                free(dest);
            } else {
                int err = 0;
                char* dest = create_msg(SERVER_ERROR_COMMAND, "", "Une erreur est survenue lors du transfert du message. Réessayez.");
                
                if(sendTCP(c->tcp, dest, strlen(dest)) <= 0)
                    kick(socketUDP, clients, c, set, KICK_MSG_COMMUNICATION_FAILED, KICK_MSG_SEND_TO_ALL);
                
                free(dest);
            }
        }
    }
}

void UDP_clients(int socketUDP, list_client* clients, fd_set* set, int maxc) {
    struct sockaddr_in* saddr = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
    char buff[BUFFER_SIZE];
    int n = readUDP(socketUDP, buff, BUFFER_SIZE - 1, saddr);
    client* c = find_client_UDP(clients, saddr);

    if(n < 0) {
        if(c != NULL) {
            int flag = is_name_set(c) ? KICK_MSG_SEND_TO_ALL : KICK_MSG_SEND_TO_NOBODY;
            kick(socketUDP, clients, c, set, KICK_MSG_COMMUNICATION_FAILED, flag);
        }
    } else {
        buff[n] = '\0';
        
        if(c == NULL) {
            c = (client*) malloc(sizeof(client));
            c->udp = saddr;
            c->next = NULL;
            c->name = NULL;
            c->last_msg = get_time();
            c->warning_sent = 0;
            add_client(clients, c);

            if(clients->size > maxc) {
                kick(socketUDP, clients, c, set, KICK_MSG_SERVER_FULL, KICK_MSG_SEND_TO_NOBODY);
                return;
            }
        } else
            free(saddr);

        c->last_msg = get_time();
        c->warning_sent = 0;
        if(!is_name_set(c)) {
            int a;

            if( ( a = check_name(clients, c, buff, strlen(buff)) ) > -1 ) {
                kick(socketUDP, clients, c, set, a, KICK_MSG_SEND_TO_NOBODY);
            } else {
                char* dest = create_msg(SERVER_JOIN_COMMAND, c->name, "");
                send_all(clients, socketUDP, dest, strlen(dest), set, c);
                free(dest);
            }
        } else if(is_type(buff, CLIENT_LEAVE_COMMAND)) {
            kick(socketUDP, clients, c, set, KICK_MSG_LEFT, KICK_MSG_SEND_TO_ALL);
        } else if(is_type(buff, CLIENT_MSG_COMMAND)) {
            char* dest = create_msg(SERVER_MSG_COMMAND, c->name, &buff[2]);
            send_all(clients, socketUDP, dest, strlen(dest), set, c);
            free(dest);
        } else {
            int err = 0;
            char* dest = create_msg(SERVER_ERROR_COMMAND, "", "Une erreur est survenue lors du transfert du message. Réessayez.");
            
            if(sendTCP(c->tcp, dest, strlen(dest)) <= 0)
                kick(socketUDP, clients, c, set, KICK_MSG_COMMUNICATION_FAILED, KICK_MSG_SEND_TO_ALL);
            
            free(dest);
        }
    }
}

int main(int argc, char* argv[]) {
    signal(SIGCHLD, SIG_IGN);
    unsigned short int port = DEFAULT_PORT;
    int socketTCP;
    int socketUDP;
    struct sockaddr_in saddrTCP = {0};
    struct sockaddr_in saddrUDP = {0};
    int max_client = MAX_CLIENT_DEFAULT;
    fd_set set;
    list_client clients;

    clients.size = 0;
    clients.first = NULL;

    if(argc > 0) {
        if(!check_args(argc, argv, &port, &max_client))
            return EXIT_FAILURE;
    }

    printf("------ Lancement du serveur ------\n");
    printf("Port : %d\n", port);
    printf("Max clients : %d\n\n", max_client);
    
    if(!openTCP(&socketTCP, port, &saddrTCP, max_client) 
        || !openUDP(&socketUDP, port, &saddrUDP))
        return EXIT_FAILURE;

    FD_ZERO(&set);
    FD_SET(0, &set);
    FD_SET(socketTCP, &set);
    FD_SET(socketUDP, &set);

    client* c;
    fd_set tmp;
    int maxs = socketTCP > socketUDP ? socketTCP : socketUDP;
    int quit = 0;
    struct timeval timeout;

    while(!quit) {
        tmp = set;
        timeout.tv_sec = SELECT_INTERVAL_SEC;
        timeout.tv_usec = SELECT_INTERVAL_SEC * 1000;
        select(maxs + 1, &tmp, NULL, NULL, &timeout);

        for(int i = 0; i < maxs + 1; i++) {
            if(FD_ISSET(i, &tmp)) {
                if(i == 0) {
                    char* cmd = (char*) malloc(sizeof(char) * 32);

                    scanf("%s", cmd);
                    clear_stdin();
                    if(cmd != NULL) {
                        if(strcmp(cmd, SERVER_SHUTDOWN_COMMAND) == 0) {
                            quit = 1;
                        } else {
                            printf("Commande inconnue. Commandes disponibles :\n");
                            printf("%s : ferme le serveur\n", SERVER_SHUTDOWN_COMMAND);
                            printf("\n");
                        }
                    }

                    free(cmd);
                } else if(i == socketUDP)
                    UDP_clients(socketUDP, &clients, &set, max_client);
                else 
                    TCP_clients(socketTCP, socketUDP, i, &set, &clients, max_client, &maxs);
            }
        }

        printf("%d / %d clients connectées\n", clients.size, max_client);

        c = clients.first;
        client* next;
        while(c != NULL) {
            next = c->next;

            if(get_time_passed(c->last_msg) > WARNING_TIMEOUT && !c->warning_sent) {
                int err = 0;
                char* dest = create_msg(SERVER_COMMAND, "", "Attention ! Vous êtes sur le point d'être déconnecté !");
                
                c->warning_sent = 1;
                if(isTCP(c)) {
                    if(sendTCP(c->tcp, dest, strlen(dest)) <= 0)
                        err = 1;
                } else  {
                    if(sendUDP(socketUDP, dest, strlen(dest), c->udp) <= 0)
                        err = 1;
                }

                if(err)
                    kick(socketUDP, &clients, c, &set, KICK_MSG_COMMUNICATION_FAILED, KICK_MSG_SEND_TO_ALL);
                
                free(dest);
            }

            if(get_time_passed(c->last_msg) > TIMEOUT)
                kick(socketUDP, &clients, c, &set, KICK_MSG_TIMEOUT, KICK_MSG_SEND_TO_ALL);
            
            c = next;
        }
    }

    printf("------ Arrêt du serveur ------\n");
    char* dest = create_msg(SERVER_COMMAND, "", "Arrêt du serveur");
    send_all(&clients, socketUDP, dest, strlen(dest), &set, NULL);
    free(dest);

    c = clients.first;
    client* next;
    while(c != NULL) {
        next = c->next;
        kick(socketUDP, &clients, c, &set, KICK_MSG_SERVER_SHUTDOWN, KICK_MSG_SEND_TO_ALL);
        c = next;
    }

    return EXIT_SUCCESS;
}