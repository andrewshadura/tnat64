/*

   parser.c    - Parsing routines for tsocks.conf

*/

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <config.h>
#include "common.h"
#include "parser.h"

/* Global configuration variables */
#define MAXLINE         BUFSIZ  /* Max length of conf line  */
static struct prefixent *currentcontext = NULL;

static int handle_line(struct parsedfile *, char *, int);
static int tokenize(char *, int, char *[]);
static int handle_path(struct parsedfile *, int, int, char *[]);
static int handle_endpath(struct parsedfile *, int, int, char *[]);
static int handle_subnet(struct parsedfile *, int, char *);
static int handle_local(struct parsedfile *, int, char *);
static int handle_prefix(struct parsedfile *, int, char *);
static int make_netent(char *value, struct netent **ent);

int HIDDENSYM read_config(char *filename, struct parsedfile *config)
{
    FILE *conf;
    char line[MAXLINE];
    int rc = 0;
    int lineno = 1;

    /* Clear out the structure */
    memset(config, 0x0, sizeof(*config));

    /* Initialization */
    currentcontext = &(config->defaultprefix);

    /* If a filename wasn't provided, use the default */
    if (filename == NULL)
    {
        strncpy(line, CONF_FILE, sizeof(line) - 1);
        /* Insure null termination */
        line[sizeof(line) - 1] = (char)0;
        filename = line;
    }

    show_msg(MSGDEBUG, "Opening configuration file (%s)\n", filename);
    /* Read the configuration file */
    if ((conf = fopen(filename, "r")) == NULL)
    {
        show_msg(MSGERR, "Could not open NAT64 configuration file " "(%s), assuming all networks local\n", filename);
        handle_local(config, 0, "0.0.0.0/0.0.0.0");
        rc = 1;                 /* Severe errors reading configuration */
    }
    else
    {
        memset(&(config->defaultprefix), 0x0, sizeof(config->defaultprefix));

        while (NULL != fgets(line, MAXLINE, conf))
        {
            /* This line _SHOULD_ end in \n so we  */
            /* just chop off the \n and hand it on */
            if (strlen(line) > 0)
                line[strlen(line) - 1] = '\0';
            handle_line(config, line, lineno);
            lineno++;
        }
        fclose(conf);

        /* Always add the 127.0.0.1/255.0.0.0 subnet to local */
        handle_local(config, 0, "127.0.0.0/255.0.0.0");

    }

    return (rc);
}

static int handle_line(struct parsedfile *config, char *line, int lineno)
{
    char *words[10];
    static char savedline[MAXLINE];
    int nowords = 0, i;

    /* Save the input string */
    strncpy(savedline, line, MAXLINE - 1);
    savedline[MAXLINE - 1] = (char)0;
    /* Tokenize the input string */
    nowords = tokenize(line, 10, words);

    /* Set the spare slots to an empty string to simplify */
    /* processing                                         */
    for (i = nowords; i < 10; i++)
        words[i] = "";

    if (nowords > 0)
    {
        /* Now this can either be a "path" block starter or */
        /* ender, otherwise it has to be a pair (<name> =   */
        /* <value>)                                         */
        if (!strcmp(words[0], "path"))
        {
            handle_path(config, lineno, nowords, words);
        }
        else if (!strcmp(words[0], "}"))
        {
            handle_endpath(config, lineno, nowords, words);
        }
        else
        {
            /* Has to be a pair */
            if ((nowords != 3) || (strcmp(words[1], "=")))
            {
                show_msg(MSGERR, "Malformed configuration pair " "on line %d in configuration " "file, \"%s\"\n", lineno, savedline);
            }
            else if (!strcmp(words[0], "subnet"))
            {
                handle_subnet(config, lineno, words[2]);
            }
            else if (!strcmp(words[0], "nat64_prefix"))
            {
                handle_prefix(config, lineno, words[2]);
            }
            else if (!strcmp(words[0], "local"))
            {
                handle_local(config, lineno, words[2]);
            }
            else
            {
                show_msg(MSGERR, "Invalid pair type (%s) specified " "on line %d in configuration file, " "\"%s\"\n", words[0], lineno, savedline);
            }
        }
    }

    return (0);
}

/* This routines breaks up input lines into tokens  */
/* and places these tokens into the array specified */
/* by tokens                                        */
static int tokenize(char *line, int arrsize, char *tokens[])
{
    int tokenno = -1;
    int finished = 0;

    /* Whitespace is ignored before and after tokens     */
    while ((tokenno < (arrsize - 1)) && (line = line + strspn(line, " \t")) && (*line != (char)0) && (!finished))
    {
        tokenno++;
        tokens[tokenno] = line;
        line = line + strcspn(line, " \t");
        *line = (char)0;
        line++;

        /* We ignore everything after a # */
        if (*tokens[tokenno] == '#')
        {
            finished = 1;
            tokenno--;
        }
    }

    return (tokenno + 1);
}

static int handle_path(struct parsedfile *config, int lineno, int nowords, char *words[])
{
    struct prefixent *newprefix;

    if ((nowords != 2) || (strcmp(words[1], "{")))
    {
        show_msg(MSGERR, "Badly formed path open statement on line %d " "in configuration file (should look like " "\"path {\")\n", lineno);
    }
    else if (currentcontext != &(config->defaultprefix))
    {
        /* You cannot nest path statements so check that */
        /* the current context is defaultprefix          */
        show_msg(MSGERR, "Path statements cannot be nested on line %d " "in configuration file\n", lineno);
    }
    else
    {
        /* Open up a new prefixent, put it on the list   */
        /* then set the current context                  */
        if (((int)(newprefix = (struct prefixent *)malloc(sizeof(struct prefixent)))) == -1)
            exit(-1);

        /* Initialize the structure */
        show_msg(MSGDEBUG, "New prefix structure from line %d in configuration file going " "to 0x%08x\n", lineno, newprefix);
        memset(newprefix, 0x0, sizeof(*newprefix));
        newprefix->next = config->paths;
        newprefix->lineno = lineno;
        config->paths = newprefix;
        currentcontext = newprefix;
    }

    return (0);
}

static int handle_endpath(struct parsedfile *config, int lineno, int nowords, char *words[])
{

    if (nowords != 1)
    {
        show_msg(MSGERR, "Badly formed path close statement on line " "%d in configuration file (should look like " "\"}\")\n", lineno);
    }
    else
    {
        currentcontext = &(config->defaultprefix);
    }

    /* We could perform some checking on the validty of data in */
    /* the completed path here, but thats what verifyconf is    */
    /* designed to do, no point in weighing down libtsocks      */

    return (0);
}

static int handle_subnet(struct parsedfile *config, int lineno, char *value)
{
    int rc;
    struct netent *ent;

    rc = make_netent(value, &ent);
    switch (rc)
    {
      case 1:
          show_msg(MSGERR, "Local network specification (%s) is not validly " "constructed in subnet statement on line " "%d in configuration " "file\n", value, lineno);
          return (0);
          break;
      case 2:
          show_msg(MSGERR, "IP in subnet statement " "network specification (%s) is not valid on line " "%d in configuration file\n", value, lineno);
          return (0);
          break;
      case 3:
          show_msg(MSGERR, "SUBNET in subnet statement " "network specification (%s) is not valid on " "line %d in configuration file\n", value, lineno);
          return (0);
          break;
      case 4:
          show_msg(MSGERR, "IP (%s) & ", inet_ntoa(ent->localip));
          show_msg(MSGERR, "SUBNET (%s) != IP on line %d in " "configuration file, ignored\n", inet_ntoa(ent->localnet), lineno);
          return (0);
          break;
      case 5:
          show_msg(MSGERR, "Start port in subnet statement " "network specification (%s) is not valid on line " "%d in configuration file\n", value, lineno);
          return (0);
          break;
      case 6:
          show_msg(MSGERR, "End port in subnet statement " "network specification (%s) is not valid on line " "%d in configuration file\n", value, lineno);
          return (0);
          break;
      case 7:
          show_msg(MSGERR, "End port in subnet statement " "network specification (%s) is less than the start " "port on line %d in configuration file\n", value, lineno);
          return (0);
          break;
    }

    /* The entry is valid so add it to linked list */
    ent->next = currentcontext->reachnets;
    currentcontext->reachnets = ent;

    return (0);
}

static int handle_prefix(struct parsedfile *config, int lineno, char *value)
{
    char *ip;

    ip = strsplit(NULL, &value, " ");

    if (currentcontext->address == NULL)
    {
        currentcontext->address = strdup(ip);
        if (!inet_pton(AF_INET6, ip, &currentcontext->prefix))
        {
            show_msg(MSGERR, "Cannot parse NAT64 prefix " "specified at line %d in " "configuration file\n", lineno);
        }
    }
    else
    {
        if (currentcontext == &(config->defaultprefix))
            show_msg(MSGERR, "Only one default NAT64 prefix " "may be specified at line %d in " "configuration file\n", lineno);
        else
            show_msg(MSGERR, "Only one NAT64 prefix may be specified " "per path on line %d in configuration " "file. (Path begins on line %d)\n", lineno, currentcontext->lineno);
    }

    return (0);
}

static int handle_local(struct parsedfile *config, int lineno, char *value)
{
    int rc;
    struct netent *ent;

    if (currentcontext != &(config->defaultprefix))
    {
        show_msg(MSGERR, "Local networks cannot be specified in path " "block at like %d in configuration file. " "(Path block started at line %d)\n", lineno, currentcontext->lineno);
        return (0);
    }

    rc = make_netent(value, &ent);
    switch (rc)
    {
      case 1:
          show_msg(MSGERR, "Local network specification (%s) is not validly " "constructed on line %d in configuration " "file\n", value, lineno);
          return (0);
          break;
      case 2:
          show_msg(MSGERR, "IP for local " "network specification (%s) is not valid on line " "%d in configuration file\n", value, lineno);
          return (0);
          break;
      case 3:
          show_msg(MSGERR, "SUBNET for " "local network specification (%s) is not valid on " "line %d in configuration file\n", value, lineno);
          return (0);
          break;
      case 4:
          show_msg(MSGERR, "IP (%s) & ", inet_ntoa(ent->localip));
          show_msg(MSGERR, "SUBNET (%s) != IP on line %d in " "configuration file, ignored\n", inet_ntoa(ent->localnet), lineno);
          return (0);
      case 5:
      case 6:
      case 7:
          show_msg(MSGERR, "Port specification is invalid and " "not allowed in local network specification " "(%s) on line %d in configuration file\n", value, lineno);
          return (0);
          break;
    }

    if (ent->startport || ent->endport)
    {
        show_msg(MSGERR, "Port specification is " "not allowed in local network specification " "(%s) on line %d in configuration file\n", value, lineno);
        return (0);
    }

    /* The entry is valid so add it to linked list */
    ent->next = config->localnets;
    (config->localnets) = ent;

    return (0);
}

/* Construct a netent given a string like                             */
/* "198.126.0.1[:portno[-portno]]/255.255.255.0"                      */
int HIDDENSYM make_netent(char *value, struct netent **ent)
{
    char *ip;
    char *subnet;
    char *startport = NULL;
    char *endport = NULL;
    char *badchar;
    char separator;
    static char buf[200];
    char *split;

    /* Get a copy of the string so we can modify it */
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = (char)0;
    split = buf;

    /* Now rip it up */
    ip = strsplit(&separator, &split, "/:");
    if (separator == ':')
    {
        /* We have a start port */
        startport = strsplit(&separator, &split, "-/");
        if (separator == '-')
            /* We have an end port */
            endport = strsplit(&separator, &split, "/");
    }
    subnet = strsplit(NULL, &split, " \n");

    if ((ip == NULL) || (subnet == NULL))
    {
        /* Network specification not validly constructed */
        return (1);
    }

    /* Allocate the new entry */
    if ((*ent = (struct netent *)malloc(sizeof(struct netent))) == NULL)
    {
        /* If we couldn't malloc some storage, leave */
        exit(1);
    }

    show_msg(MSGDEBUG, "New network entry for %s going to 0x%08x\n", ip, *ent);

    if (!startport)
        (*ent)->startport = 0;
    if (!endport)
        (*ent)->endport = 0;

#ifdef HAVE_INET_ADDR
    if (((*ent)->localip.s_addr = inet_addr(ip)) == -1)
    {
#elif defined(HAVE_INET_ATON)
    if (!(inet_aton(ip, &((*ent)->localip))))
    {
#endif
        /* Badly constructed IP */
        free(*ent);
        return (2);
    }
#ifdef HAVE_INET_ADDR
    else if (((*ent)->localnet.s_addr = inet_addr(subnet)) == -1)
    {
#elif defined(HAVE_INET_ATON)
    else if (!(inet_aton(subnet, &((*ent)->localnet))))
    {
#endif
        /* Badly constructed subnet */
        free(*ent);
        return (3);
    }
    else if (((*ent)->localip.s_addr & (*ent)->localnet.s_addr) != (*ent)->localip.s_addr)
    {
        /* Subnet and Ip != Ip */
        free(*ent);
        return (4);
    }
    else if (startport && (!((*ent)->startport = strtol(startport, &badchar, 10)) || (*badchar != 0) || ((*ent)->startport > 65535)))
    {
        /* Bad start port */
        free(*ent);
        return (5);
    }
    else if (endport && (!((*ent)->endport = strtol(endport, &badchar, 10)) || (*badchar != 0) || ((*ent)->endport > 65535)))
    {
        /* Bad end port */
        free(*ent);
        return (6);
    }
    else if (((*ent)->startport > (*ent)->endport) && !(startport && !endport))
    {
        /* End port is less than start port */
        free(*ent);
        return (7);
    }

    if (startport && !endport)
        (*ent)->endport = (*ent)->startport;

    return (0);
}

int HIDDENSYM is_local(struct parsedfile *config, struct in_addr *testip)
{
    struct netent *ent;

    for (ent = (config->localnets); ent != NULL; ent = ent->next)
    {
        if ((testip->s_addr & ent->localnet.s_addr) == (ent->localip.s_addr & ent->localnet.s_addr))
        {
            return (0);
        }
    }

    return (1);
}

/* Find the appropriate prefix to reach an ip */
int HIDDENSYM pick_prefix(struct parsedfile *config, struct prefixent **ent, struct in_addr *ip, unsigned int port)
{
    struct netent *net;
    char ipbuf[64];

    show_msg(MSGDEBUG, "Picking appropriate prefix for %s\n", inet_ntoa(*ip));
    *ent = (config->paths);
    while (*ent != NULL)
    {
        /* Go through all the prefixes looking for one */
        /* with a path to this network                */
        show_msg(MSGDEBUG, "Checking NAT64 prefix %s\n", ((*ent)->address ? (*ent)->address : "(No Address)"));
        net = (*ent)->reachnets;
        while (net != NULL)
        {
            strcpy(ipbuf, inet_ntoa(net->localip));
            show_msg(MSGDEBUG, "%s/%s is reachable through this prefix\n", ipbuf, inet_ntoa(net->localnet));
            if (((ip->s_addr & net->localnet.s_addr) == (net->localip.s_addr & net->localnet.s_addr)) && (!net->startport || ((net->startport <= port) && (net->endport >= port))))
            {
                show_msg(MSGDEBUG, "The target is reachable\n");
                /* Found the net, return */
                return (0);
            }
            net = net->next;
        }
        (*ent) = (*ent)->next;
    }

    *ent = &(config->defaultprefix);

    return (0);
}

int HIDDENSYM check_prefix(struct parsedfile *config, struct in6_addr * addr)
{
    char ipbuf[64];
    struct prefixent *ent;
    char addrbuffer[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, addr, addrbuffer, sizeof(addrbuffer)))
    {
        show_msg(MSGDEBUG, "Checking if IPv6 address %s is behind the NAT64...\n", addrbuffer);
    }
    ent = (config->paths);
    puts("!!!");
    while (ent != NULL)
    {
        /* Go through all the prefixes */
        show_msg(MSGDEBUG, "Checking NAT64 prefix %s\n", (ent->address ? ent->address : "(No Address)"));
        if ((ent->address))
        {
            if (!memcmp(addr, &(ent->prefix), NAT64PREFIXLEN))
            {
                show_msg(MSGDEBUG, "Match!\n");
                return 1;
            }
        }
        ent = ent->next;
    }

    ent = &(config->defaultprefix);
    show_msg(MSGDEBUG, "Checking the default NAT64 prefix %s\n", (ent->address ? ent->address : "(No Address)"));
    if (!memcmp(addr, &(ent->prefix), NAT64PREFIXLEN))
    {
        show_msg(MSGDEBUG, "Match!\n");
        return 1;
    }

    return 0;
}

/* This function is very much like strsep, it looks in a string for */
/* a character from a list of characters, when it finds one it      */
/* replaces it with a \0 and returns the start of the string        */
/* (basically spitting out tokens with arbitrary separators). If no */
/* match is found the remainder of the string is returned and       */
/* the start pointer is set to be NULL. The difference between      */
/* standard strsep and this function is that this one will          */
/* set *separator to the character separator found if it isn't null */
char HIDDENSYM *strsplit(char *separator, char **text, const char *search)
{
    int len;
    char *ret;

    ret = *text;

    if (*text == NULL)
    {
        if (separator)
            *separator = '\0';
        return (NULL);
    }
    else
    {
        len = strcspn(*text, search);
        if (len == strlen(*text))
        {
            if (separator)
                *separator = '\0';
            *text = NULL;
        }
        else
        {
            *text = *text + len;
            if (separator)
                *separator = **text;
            **text = '\0';
            *text = *text + 1;
        }
    }

    return (ret);
}
