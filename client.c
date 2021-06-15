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
#include <ncurses.h>

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

#define COLOR_BLACK 0
#define COLOR_RED 1
#define COLOR_GREEN 2
#define COLOR_YELLOW 3
#define COLOR_BLUE 4
#define COLOR_MAGENTA 5
#define COLOR_CYAN 6
#define COLOR_WHITE 7

#define BUFFER_SIZE 2097

typedef struct client {
  char* name;
  struct sockaddr_in udp;
  int tcp;
} client;

void display_date_time(WINDOW* chat,char date[14]){
  wprintw(chat,"%c%c/%c%c/%c%c%c%c %c%c:%c%c:%c%c",date[6],date[7],date[4],date[5],date[0],date[1],date[2],date[3],date[8],date[9],date[10],date[11],date[12],date[13]);
}

void display_message(WINDOW* write, WINDOW* chat, char *msg) {
  int y,x;
  getyx(write, y, x);
  char d[] = ":";
  char *p = strtok(msg, d);
  int v = atoi(p);
  switch(v){
    case SERVER_MSG_COMMAND :
      p = strtok(NULL, d);
      char* pseudo = p;
      p = strtok(NULL, d);
      wattron(chat,COLOR_PAIR(4));
      display_date_time(chat, p);
      wattroff(chat,COLOR_PAIR(4));
      wattron(chat,COLOR_PAIR(7));
      wprintw(chat," -- ");
      wattroff(chat,COLOR_PAIR(7));
      wattron(chat,COLOR_PAIR(6));
      wprintw(chat,"%s", pseudo);
      wattroff(chat,COLOR_PAIR(6));
      wattron(chat,COLOR_PAIR(7));
      wprintw(chat," : ");
      p = strtok(NULL, d);
      wprintw(chat,"%s", p);
      p = strtok(NULL, d);
      while(p != NULL){
        wprintw(chat,":%s", p);
        p = strtok(NULL, d);
      }
      wprintw(chat,"\n");
      wattroff(chat,COLOR_PAIR(7));
      break;
    case SERVER_COMMAND :
      p = strtok(NULL, d);
      wattron(chat,COLOR_PAIR(3));
      display_date_time(chat, p);
      wprintw(chat," -- ");
      wprintw(chat,"[SERVEUR] : ");
      p = strtok(NULL, d);
      wprintw(chat,"%s", p);
      p = strtok(NULL, d);
      while(p != NULL){
        wprintw(chat,":%s", p);
        p = strtok(NULL, d);
      }
      wattroff(chat,COLOR_PAIR(3));
      wattron(chat,COLOR_PAIR(7));
      wprintw(chat,"\n");
      wattroff(chat,COLOR_PAIR(7));
      break;
    case SERVER_ERROR_COMMAND :
      p = strtok(NULL, d);
      wattron(chat,COLOR_PAIR(1));
      display_date_time(chat, p);
      wprintw(chat," -- ");
      wprintw(chat,"[SERVEUR] : ");
      p = strtok(NULL, d);
      wprintw(chat,"%s", p);
      p = strtok(NULL, d);
      while(p != NULL){
        wprintw(chat,":%s", p);
        p = strtok(NULL, d);
      }
      wattroff(chat,COLOR_PAIR(1));
      wattron(chat,COLOR_PAIR(7));
      wprintw(chat,"\n");
      wattroff(chat,COLOR_PAIR(7));
      break;
    case SERVER_KICK_COMMAND :
      p = strtok(NULL, d);
      wattron(chat,COLOR_PAIR(1));
      display_date_time(chat, p);
      wprintw(chat," -- ");
      wprintw(chat,"[SERVEUR] : ");
      p = strtok(NULL, d);
      int v2 = atoi(p);
      switch(v2){
        case KICK_MSG_NAME_NOT_VALID :
          wprintw(chat,"EXCLU POUR CAUSE DE PSEUDO NON VALIDE");
          break;
        case KICK_MSG_NAME_ALREADY_USED :
          wprintw(chat,"EXCLU POUR CAUSE DE PSEUDO DEJA UTILISE");
          break;
        case KICK_MSG_TIMEOUT :
          wprintw(chat,"EXCLU POUR CAUSE D'INACTIVITE");
          break;
        case KICK_MSG_SERVER_FULL :
          wprintw(chat,"EXCLU POUR CAUSE DE SERVEUR PLEIN");
          break;
        case KICK_MSG_COMMUNICATION_FAILED :
          wprintw(chat,"EXCLU POUR CAUSE DE COMMUNICATION ECHOUE");
          break;
        case KICK_MSG_LEFT :
          wprintw(chat,"EXCLU SUITE A UNE DEMANDE DE DECONNEXION");
          break;
        case KICK_MSG_SERVER_SHUTDOWN :
          wprintw(chat,"EXCLU POUR CAUSE DE FERMETURE DU SERVEUR");
          break;
        default :
          break;
      }
      wattroff(chat,COLOR_PAIR(1));
      wattron(chat,COLOR_PAIR(7));
      wprintw(chat,"\n");
      wattroff(chat,COLOR_PAIR(7));
      wrefresh(chat);
      getch();
      endwin();
      kill(getppid(), SIGKILL);
      exit(0);
      break;
    case SERVER_JOIN_COMMAND :
      p = strtok(NULL, d);
      pseudo = p;
      p = strtok(NULL, d);
      wattron(chat,COLOR_PAIR(3));
      display_date_time(chat, p);
      wprintw(chat," -- ");
      wprintw(chat,"[SERVEUR] : %s A REJOINT LE SERVEUR", pseudo);
      wattroff(chat,COLOR_PAIR(1));
      wattron(chat,COLOR_PAIR(7));
      wprintw(chat,"\n");
      wattroff(chat,COLOR_PAIR(7));
      break;
    case SERVER_LEAVE_COMMAND :
      p = strtok(NULL, d);
      pseudo = p;
      p = strtok(NULL, d);
      wattron(chat,COLOR_PAIR(3));
      display_date_time(chat, p);
      wprintw(chat," -- ");
      wprintw(chat,"[SERVEUR] : %s A QUITTE LE SERVEUR", pseudo);
      wattroff(chat,COLOR_PAIR(3));
      wattron(chat,COLOR_PAIR(7));
      wprintw(chat,"\n");
      wattroff(chat,COLOR_PAIR(7));
      break;
    default :
      wprintw(chat,"D : %s\n", msg);
  }
  wmove(write,1,x);
  wrefresh(chat);
  wrefresh(write);
}

int check_args(WINDOW* chat, int argc, char *argv[], char *ip[], int *protocol, unsigned short *port, char *login[]);

int write_message_server(int socket, int type_msg, char* msg) {
  char msg2[BUFFER_SIZE];
  sprintf(msg2, "%d:%s", type_msg,msg);
  int ret = write(socket, msg2, strlen(msg2));
  if(ret == -1) {
    perror("Error write()");
    getch();
    endwin();
    exit(errno);
  }
  return ret;
}

int write_message_server_udp(struct sockaddr_in addr, int sock, int type_msg, char* msg) {
  char msg2[BUFFER_SIZE];
  sprintf(msg2, "%d:%s", type_msg,msg);
  int size = sizeof(addr);
  if(type_msg == 2){
    if(sendto(sock, msg2, strlen(msg2), 0, (struct sockaddr *) &addr, size) < 0) {
      perror("sendto()");
      getch();
      endwin();
      exit(errno);
    }
    return 1;
  }
  if(sendto(sock, msg2, strlen(msg2), 0, (struct sockaddr *) &addr, size) < 0) {
    perror("sendto()");
    getch();
    endwin();
    exit(errno);
  }
  return 1;
}

int read_message_server(int socket, char* msg) {
  int ret = read(socket, msg, BUFFER_SIZE - 1);
  if(ret == -1) {
    perror("Error read()");
    getch();
    endwin();
    exit(errno);
  }
  msg[ret] = '\0';
  return ret;
}

int read_message_server_udp(struct sockaddr_in addr, int sock, char* msg) {
  unsigned int size = sizeof(addr);
  int n;
  if((n = recvfrom(sock, msg, BUFFER_SIZE - 1, 0, (struct sockaddr *) &addr, &size)) < 0) {
    perror("recvfrom()");
    getch();
    endwin();
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
      getch();
      endwin();
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
    getch();
    endwin();
    exit(1);
  }

  int ok = connect(client->tcp, (struct sockaddr *) &addr, sizeof(addr) );
  if (ok == -1) {
    perror("error connect()");
    getch();
    endwin();
    exit(1);
  }
}



int main(int argc, char *argv[]) {
  
  WINDOW *infos, *haut, *chat, *infos2, *bas, *write,*footer;
  
  initscr();
  start_color();

  init_pair(1, COLOR_RED, COLOR_BLACK);
  init_pair(2, COLOR_GREEN, COLOR_BLACK);
  init_pair(3, COLOR_YELLOW, COLOR_BLACK);
  init_pair(4, COLOR_BLUE, COLOR_BLACK);
  init_pair(5, COLOR_MAGENTA, COLOR_BLACK);
  init_pair(6, COLOR_CYAN, COLOR_BLACK);
  init_pair(7, COLOR_WHITE, COLOR_BLACK);

  clear();

  infos= subwin(stdscr, 1, COLS, 0, 0);
  haut= subwin(stdscr, LINES - 7, COLS, 1, 0);
  chat= subwin(stdscr, LINES - 9, COLS -2, 2, 1);
  infos2= subwin(stdscr, 1, COLS, LINES - 6, 0);
  bas= subwin(stdscr,  4, COLS, LINES - 5, 0);
  write= subwin(stdscr,  2, COLS-2, LINES - 4, 1);
  footer= subwin(stdscr,  1, COLS, LINES - 1, 0);

  if (has_colors() == FALSE) {
    endwin();
    printf("Your terminal does not support color\n");
    exit(1);
  }
  
  
  

  scrollok(chat,TRUE);
  scrollok(write,TRUE);
  box(haut, ACS_VLINE, ACS_HLINE);
  box(bas, ACS_VLINE, ACS_HLINE);

  wrefresh(haut);
  wrefresh(bas);
  
  if (argc < 2) {
    wprintw(chat,"Usage: %s <adresse IP> <-l username> [<-p> <-t> <-u>]\n", argv[0]);
    wrefresh(chat);
    getch();
    endwin();
    return EXIT_FAILURE;
  }
  char *ip;
  char *login;
  int protocol = 0;
  unsigned short port = 2021;
  if (!check_args(chat, argc, argv, &ip, &protocol, &port, &login)){
    wrefresh(chat);
    getch();
    endwin();
    return EXIT_FAILURE;
  } 
  
  
    
  
  //if(DEBUG) printf("Adresse : %s:%d - Type de connexion : %d - Pseudo : %s, \n", ip, port, protocol, login);
  if(protocol)
    mvwprintw(infos, 0, 1,"Adresse : %s:%d - Type de connexion : UDP - Pseudo : %s \n", ip, port, login);
  else
    mvwprintw(infos, 0, 1,"Adresse : %s:%d - Type de connexion : TCP - Pseudo : %s \n", ip, port, login);
  wrefresh(infos);
  mvwprintw(infos2, 0, 1,"Message : ");
  wrefresh(infos2);
  mvwprintw(footer, 0, COLS/2 - 28,"Crédits : Julien Carcau - Guillaume Descroix - Louka Doz");
  wrefresh(footer);

  client *c = (client*) malloc(sizeof(client));
  c->name = login;
  if(protocol) {  // UDP client
    create_client_UDP(c, ip, port);
    int fork_status = fork();
    if(fork_status == -1) {
      perror("Error fork()");
      getch();
      endwin();
      return EXIT_FAILURE;
    }
    if(fork_status > 0) { // write server
      char *msg = (char*) malloc(23*sizeof(char));;
      sprintf(msg, "%s", c->name);
      //printf("TEST\n");
      write_message_server_udp(c->udp, c->tcp, 1,msg); 
      //free(msg);
      while(1) {
        char buf_client[BUFFER_SIZE - 3];
        int nb_read = mvwgetnstr(write, 1, 0, buf_client, BUFFER_SIZE - 3);
        if(nb_read == ERR || strlen(buf_client) == 0)
          continue;
        wprintw(write, "\n");
        wrefresh(write);
        if(!strcmp(buf_client, "/quit")) {
          write_message_server_udp(c->udp, c->tcp, 0, buf_client);
          //kill(fork_status, SIGKILL);
        }
        else
          write_message_server_udp(c->udp, c->tcp, 2, buf_client);
      }
    } else {              // read server
      while(1) {
        char buf_server[BUFFER_SIZE];
        read_message_server_udp(c->udp, c->tcp, buf_server);
        display_message(write, chat, buf_server);
      }
    }
    close_socket_client(c->tcp);
  } else {        // TCP client
    create_client_TCP(c, ip, port);
    int fork_status = fork();
    if(fork_status == -1) {
      perror("Error fork()");
      getch();
      endwin();
      return EXIT_FAILURE;
    }
    if(fork_status > 0) { // write server
      char *msg = (char*) malloc(23*sizeof(char));;
      sprintf(msg, "%s", c->name);
      write_message_server(c->tcp, 1, msg);
      while(1) {
        char buf_client[BUFFER_SIZE - 3];
        int nb_read = mvwgetnstr(write, 1, 0, buf_client, BUFFER_SIZE - 3);
        if(nb_read == ERR || strlen(buf_client) == 0)
          continue;
        wprintw(write, "\n");
        wrefresh(write);
        if(!strcmp(buf_client, "/quit")) {
          write_message_server(c->tcp, 0, buf_client);
        }
        else
          write_message_server(c->tcp, 2, buf_client);
      }
    } else {              // read server
      while(1) {
        char buf_server[BUFFER_SIZE];
        read_message_server(c->tcp, buf_server);
        display_message(write, chat, buf_server);
      }
    }
    close_socket_client(c->tcp);
  }
  free(ip);
  free(login);
  return(0);
}

int check_args(WINDOW* chat, int argc, char *argv[], char *ip[], int *protocol, unsigned short *port, char *login[]) {
  for(int i = 1; i < argc; i++) {
    if(!strcmp(argv[i], "-i")) {
      if(i+1 <= argc) {
        int size = strlen(argv[i+1]);
        int occurences = 0;
        for(int j=0; j<size; j++) {
          if(argv[i+1][j] == '.') occurences++;
        }
        if(((size < 7) || (size > 15) || occurences != 3)) {
          wprintw(chat,"Veuillez fournir une adresse IP valide\n");
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
          wprintw(chat,"Le port doit être un nombre compris entre 1024 et 65535 inclus\n");
          return 0;
        }
        *port = atoi(argv[i+1]);
      }
      i++;

    } else if(!strcmp(argv[i], "-l")) {
      if(i+1 <= argc) {
        int size = strlen(argv[i+1]);
        if(((size > 20) || (strchr(argv[i+1], ':') != NULL))) {
          wprintw(chat,"Vous devez entrer un nom d'utilisateur de 20 caractères maximum ne contenant pas ':'\n");
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
    wprintw(chat,"Login ou IP manquant\n");
    return 0;
  }
  return 1;
}
