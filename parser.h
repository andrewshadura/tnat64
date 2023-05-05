/* parser.h - Structures, functions and global variables for the */
/* tsocks parsing routines                                       */

#ifndef _PARSER_H

#define _PARSER_H	1

/* Structure definitions */

/* Structure representing one NAT64 prefix specified in the config */
struct prefixent
{
    int lineno;                 /* Line number in conf file this path started on */
    char *address;              /* IPv6 address prefix in textual form */
    struct in6_addr prefix;     /* the same, but in binary form */
    struct in6_addr suffix;     /* suffix to be appended to the address */
    int prefix_size;            /* IPv6 prefix size (usually 96) */
    struct netent *reachnets;   /* Linked list of nets from this prefix */
    struct prefixent *next;     /* Pointer to next prefix entry */
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
    struct prefixent defaultprefix;
    struct prefixent *paths;
};

/* Functions provided by parser module */
int read_config(char *, struct parsedfile *);
int is_local(struct parsedfile *, struct in_addr *);
int pick_prefix(struct parsedfile *, struct prefixent **, struct in_addr *, uint16_t port);
struct prefixent * check_prefix(struct parsedfile *config, struct in6_addr * addr);
char *strsplit(char *separator, char **text, const char *search);

#endif
