#define _POSIX_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>

#define DEBUG 0

#define SERVER_MSG_COMMAND 0
#define SERVER_COMMAND 1
#define SERVER_ERROR_COMMAND 2
#define SERVER_KICK_COMMAND 3
#define SERVER_JOIN_COMMAND 4
#define SERVER_LEAVE_COMMAND 5

//TYPE (serveur):NOM:DATE:MSG

#define CLIENT_LEAVE_COMMAND 0
#define CLIENT_NAME_COMMAND 1
#define CLIENT_MSG_COMMAND 2

//TYPE (message):MSG

#define KICK_MSG_NAME_NOT_VALID 0
#define KICK_MSG_NAME_ALREADY_USED 1
#define KICK_MSG_TIMEOUT 2
#define KICK_MSG_SERVER_FULL 3
#define KICK_MSG_COMMUNICATION_FAILED 4
#define KICK_MSG_LEFT 5
#define KICK_MSG_SERVER_SHUTDOWN 6

//TYPE (serveur)::DATE:MSG (0 à 6)

typedef enum couleurTexte {
    NOIR,
    ROUGE,
    VERT,
    JAUNE,
    BLEU,
    VIOLET,
    CYAN,
    BLANC
} couleurTexte;

void definir_couleur_texte(couleurTexte c) {
    switch(c) {
        case NOIR:
            printf("\033[0;30m");
            break;
        case ROUGE:
            printf("\033[0;91m");
            break;
        case VERT:
            printf("\033[0;92m");
            break;
        case JAUNE:
            printf("\033[0;93m");
            break;
        case BLEU:
            printf("\033[0;94m");
            break;
        case VIOLET:
            printf("\033[0;95m");
            break;
        case CYAN:
            printf("\033[0;96m");
            break;
        default:    /* BLANC */
            printf("\033[0;97m");
            break;
    }
}

#define BUFFER_SIZE_READ 2048
#define BUFFER_SIZE_WRITE 2010

typedef struct client {
  char* name;
  struct sockaddr_in udp;
  int tcp;
} client;

void display_date_time(char date[14]){
  printf("%c%c/%c%c/%c%c%c%c %c%c:%c%c:%c%c",date[6],date[7],date[4],date[5],date[0],date[1],date[2],date[3],date[8],date[9],date[10],date[11],date[12],date[13]);
}

void display_message(char *msg) {
  //printf("MESSAGE : %s\n", msg);
  char d[] = ":";
  char *p = strtok(msg, d);
  int v = atoi(p);
  //printf("%d\n",v);
  
  switch(v){
    case SERVER_MSG_COMMAND :
      p = strtok(NULL, d);
      char* pseudo = p;
      p = strtok(NULL, d);
      definir_couleur_texte(BLEU);
      display_date_time(p);
      definir_couleur_texte(BLANC);
      printf(" -- ");
      definir_couleur_texte(CYAN);
      printf("%s", pseudo);
      definir_couleur_texte(BLANC);
      printf(" : ");
      p = strtok(NULL, d);
      printf("%s", p);
      p = strtok(NULL, d);
      while(p != NULL){
        printf(":%s", p);
        p = strtok(NULL, d);
      }
      printf("\n");
      break;
    case SERVER_COMMAND :
      p = strtok(NULL, d);
      definir_couleur_texte(JAUNE);
      display_date_time(p);
      printf(" -- ");
      printf("[SERVEUR] : ");
      p = strtok(NULL, d);
      printf("%s", p);
      p = strtok(NULL, d);
      while(p != NULL){
        printf(":%s", p);
        p = strtok(NULL, d);
      }
      definir_couleur_texte(BLANC);
      printf("\n");
      break;
    case SERVER_ERROR_COMMAND :
      p = strtok(NULL, d);
      definir_couleur_texte(ROUGE);
      display_date_time(p);
      printf(" -- ");
      printf("[SERVEUR] : ");
      p = strtok(NULL, d);
      printf("%s", p);
      p = strtok(NULL, d);
      while(p != NULL){
        printf(":%s", p);
        p = strtok(NULL, d);
      }
      definir_couleur_texte(BLANC);
      printf("\n");
      break;
    case SERVER_KICK_COMMAND :
      p = strtok(NULL, d);
      definir_couleur_texte(ROUGE);
      display_date_time(p);
      printf(" -- ");
      printf("[SERVEUR] : ");
      p = strtok(NULL, d);
      int v2 = atoi(p);
      switch(v2){
        case KICK_MSG_NAME_NOT_VALID :
          printf("EXCLU POUR CAUSE DE PSEUDO NON VALIDE");
          break;
        case KICK_MSG_NAME_ALREADY_USED :
          printf("EXCLU POUR CAUSE DE PSEUDO DÉJÀ UTILISÉ");
          break;
        case KICK_MSG_TIMEOUT :
          printf("EXCLU POUR CAUSE D'INACTIVITÉ");
          break;
        case KICK_MSG_SERVER_FULL :
          printf("EXCLU POUR CAUSE DE SERVEUR PLEIN");
          break;
        case KICK_MSG_COMMUNICATION_FAILED :
          printf("EXCLU POUR CAUSE DE COMMUNICATION ÉCHOUÉ");
          break;
        case KICK_MSG_LEFT :
          printf("EXCLU SUITE À UNE DEMANDE DE DÉCONNEXION");
          break;
        case KICK_MSG_SERVER_SHUTDOWN :
          printf("EXCLU POUR CAUSE DE FERMETURE DU SERVEUR");
          break;
        default :
          break;
      }
      definir_couleur_texte(BLANC);
      printf("\n");
      kill(getppid(), SIGKILL);
      exit(0);
      break;
    case SERVER_JOIN_COMMAND :
      p = strtok(NULL, d);
      pseudo = p;
      p = strtok(NULL, d);
      definir_couleur_texte(JAUNE);
      display_date_time(p);
      printf(" -- ");
      printf("[SERVEUR] : %s À REJOINT LE SERVEUR", pseudo);
      definir_couleur_texte(BLANC);
      printf("\n");
      break;
    case SERVER_LEAVE_COMMAND :
      p = strtok(NULL, d);
      pseudo = p;
      p = strtok(NULL, d);
      definir_couleur_texte(JAUNE);
      display_date_time(p);
      printf(" -- ");
      printf("[SERVEUR] : %s À QUITTÉ LE SERVEUR", pseudo);
      definir_couleur_texte(BLANC);
      printf("\n");
      break;
    default :
      printf("D : %s\n", msg);
  }
}

int check_args(int argc, char *argv[], char *ip[], int *protocol, unsigned short *port, char *login[]);

int write_message_server(int socket, int type_msg, char* msg) {
  char msg2[BUFFER_SIZE_WRITE];
  sprintf(msg2, "%d:%s", type_msg,msg);
  int ret;
  if(type_msg == 2)
    ret = write(socket, msg2, strlen(msg2)-1);
  else
    ret = write(socket, msg2, strlen(msg2));
  if(ret == -1) {
    perror("Error write()");
    exit(errno);
  }
  return ret;
}

int write_message_server_udp(struct sockaddr_in addr, int sock, int type_msg, char* msg) {
  char msg2[BUFFER_SIZE_WRITE];
  sprintf(msg2, "%d:%s", type_msg,msg);
  int size = sizeof(addr);
  if(type_msg == 2){
    if(sendto(sock, msg2, strlen(msg2)-1, 0, (struct sockaddr *) &addr, size) < 0) {
      perror("sendto()");
      exit(errno);
    }
    return 1;
  }
  if(sendto(sock, msg2, strlen(msg2), 0, (struct sockaddr *) &addr, size) < 0) {
    perror("sendto()");
    exit(errno);
  }
  return 1;
}

int read_message_server(int socket, char* msg) {
  int ret = read(socket, msg, BUFFER_SIZE_READ - 1);
  if(ret == -1) {
    perror("Error read()");
    exit(errno);
  }
  msg[ret] = '\0';
  return ret;
}

int read_message_server_udp(struct sockaddr_in addr, int sock, char* msg) {
  unsigned int size = sizeof(addr);
  int n;
  if((n = recvfrom(sock, msg, BUFFER_SIZE_READ - 1, 0, (struct sockaddr *) &addr, &size)) < 0) {
    perror("recvfrom()");
    exit(errno);
  }
  msg[n] = '\0';
  return 1;
}

void close_socket_client(int socket) {
  shutdown(socket, SHUT_RDWR);
  close(socket);
}

void create_client_UDP(client *client, char *ip, unsigned short port) {
  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip);

  client->udp = addr;
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if(sock == -1) {
      perror("error socket()");
      exit(1);
  }
  client->tcp = sock;
  
} 

void create_client_TCP(client *client, char *ip, unsigned short port) {
  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip);

  client->tcp = socket(AF_INET, SOCK_STREAM, 0);
  if(client->tcp == -1) {
    perror("error socket()");
    exit(1);
  }

  int ok = connect(client->tcp, (struct sockaddr *) &addr, sizeof(addr) );
  if (ok == -1) {
    perror("error connect()");
    exit(1);
  }
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Usage: %s <adresse IP> <-l username> [<-p> <-t> <-u>]\n", argv[0]);
    return EXIT_FAILURE;
  }
  char *ip;
  char *login;
  int protocol = 0;
  unsigned short port = 2021;
  if (!check_args(argc, argv, &ip, &protocol, &port, &login)) return EXIT_FAILURE;
  if(DEBUG) printf("IP : %s, pseudo : %s, port : %d, protocole : %d\n", ip, login, port, protocol);
  
  client *c = (client*) malloc(sizeof(client));
  c->name = login;
  if(protocol) {  // UDP client
    create_client_UDP(c, ip, port);
    int fork_status = fork();
    if(fork_status == -1) {
      perror("Error fork()");
      return EXIT_FAILURE;
    }
    if(fork_status > 0) { // write server
      char *msg = (char*) malloc(23*sizeof(char));;
      sprintf(msg, "%s", c->name);
      //printf("TEST\n");
      write_message_server_udp(c->udp, c->tcp, 1,msg); 
      while(1) {
        char buf_client[BUFFER_SIZE_WRITE];
        int nb_read = read(0, &buf_client, BUFFER_SIZE_WRITE-1);
        buf_client[nb_read] = '\0';
        if(!strcmp(buf_client, "/quit\n")) {
          write_message_server_udp(c->udp, c->tcp, 0, buf_client);
          //kill(fork_status, SIGKILL);
        }
        else
          write_message_server_udp(c->udp, c->tcp, 2, buf_client);
      }
    } else {              // read server
      while(1) {
        char buf_server[BUFFER_SIZE_READ];
        read_message_server_udp(c->udp, c->tcp, buf_server);
        display_message(buf_server);
      }
    }
    close_socket_client(c->tcp);
  } else {        // TCP client
    create_client_TCP(c, ip, port);
    int fork_status = fork();
    if(fork_status == -1) {
      perror("Error fork()");
      return EXIT_FAILURE;
    }
    if(fork_status > 0) { // write server
      char *msg = (char*) malloc(23*sizeof(char));;
      sprintf(msg, "%s", c->name);
      write_message_server(c->tcp, 1, msg);
      while(1) {
        char buf_client[BUFFER_SIZE_WRITE];
        int nb_read = read(0, &buf_client, BUFFER_SIZE_WRITE-1);
        buf_client[nb_read] = '\0';
        if(!strcmp(buf_client, "/quit\n")) {
          write_message_server(c->tcp, 0, buf_client);
          //kill(fork_status, SIGKILL);
        }
        else
          write_message_server(c->tcp, 2, buf_client);
      }
    } else {              // read server
      while(1) {
        char buf_server[BUFFER_SIZE_READ];
        read_message_server(c->tcp, buf_server);
        display_message(buf_server);
      }
    }
    close_socket_client(c->tcp);
  }
  free(ip);
  free(login);
}

int check_args(int argc, char *argv[], char *ip[], int *protocol, unsigned short *port, char *login[]) {
  for(int i = 1; i < argc; i++) {
    if(!strcmp(argv[i], "-i")) {
      if(i+1 <= argc) {
        int size = strlen(argv[i+1]);
        int occurences = 0;
        for(int j=0; j<size; j++) {
          if(argv[i+1][j] == '.') occurences++;
        }
        if(((size < 7) || (size > 15) || occurences != 3)) {
          printf("Veuillez fournir une adresse IP valide\n");
          return 0;
        }

        *ip = (char*) malloc(size*sizeof(char));
        strcpy(*ip, argv[i+1]);
      }
      *port = atoi(argv[i+1]);
      i++;

    } else if(!strcmp(argv[i], "-p")) {
      if(i+1 <= argc) {
        if(atoi(argv[i+1]) == 0 || (atoi(argv[i+1]) < 1024) || (atoi(argv[i+1]) > 65535)) {
          printf("Le port doit être un nombre compris entre 1024 et 65535 inclus\n");
          return 0;
        }
        *port = atoi(argv[i+1]);
      }
      i++;

    } else if(!strcmp(argv[i], "-l")) {
      if(i+1 <= argc) {
        int size = strlen(argv[i+1]);
        if(((size > 20) || (strchr(argv[i+1], ':') != NULL))) {
          printf("Vous devez entrer un nom d'utilisateur de 20 caractères maximum ne contenant pas ':'\n");
          return 0;
        }
        *login = (char*) malloc(size*sizeof(char));
        strcpy(*login, argv[i+1]);
      }
      i++;

    } else if(!strcmp(argv[i], "-t")) {
        *protocol = 0;

    } else if(!strcmp(argv[i], "-u")) {
        *protocol = 1;
    }
  }
  if((*login == NULL) || (*ip == NULL)) {
    printf("Login ou IP manquant\n");
    return 0;
  }
  return 1;
}
