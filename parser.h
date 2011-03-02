/* parser.h - Structures, functions and global variables for the */
/* tsocks parsing routines                                       */

#ifndef _PARSER_H

#define _PARSER_H	1

/* Structure definitions */

/* Structure representing one server specified in the config */
struct serverent
{
    int lineno;                 /* Line number in conf file this path started on */
    char *address;              /* Address/hostname of server */
    struct sockaddr_in6 prefix; /* NAT64 prefix */
    struct netent *reachnets;   /* Linked list of nets from this server */
    struct serverent *next;     /* Pointer to next server entry */
};

/* Structure representing a network */
struct netent
{
    struct in_addr localip;     /* Base IP of the network */
    struct in_addr localnet;    /* Mask for the network */
    unsigned long startport;    /* Range of ports for the */
    unsigned long endport;      /* network                */
    struct netent *next;        /* Pointer to next network entry */
};

/* Structure representing a complete parsed file */
struct parsedfile
{
    struct netent *localnets;
    struct serverent defaultserver;
    struct serverent *paths;
};

/* Functions provided by parser module */
int read_config(char *, struct parsedfile *);
int is_local(struct parsedfile *, struct in_addr *);
int pick_server(struct parsedfile *, struct serverent **, struct in_addr *, unsigned int port);
char *strsplit(char *separator, char **text, const char *search);

#endif
