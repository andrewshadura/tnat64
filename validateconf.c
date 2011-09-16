/*

    VALIDATECONF - Part of the tnat64 package
		   This utility can be used to validate the tnat64.conf
		   configuration file

    Copyright (C) 2000 Shaun Clowes 

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
    MA 02110-1301, USA.

*/

/* Global configuration variables */
char *progname = "tnat64-validateconf";        /* Name for error msgs      */

/* Header Files */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <common.h>
#include <parser.h>

void show_prefix(struct parsedfile *, struct prefixent *, int);
void show_conf(struct parsedfile *config);
void test_host(struct parsedfile *config, char *);

int main(int argc, char *argv[])
{
    char *usage = "Usage: [-f conf file] [-t hostname/ip[:port]]";
    char *filename = NULL;
    char *testhost = NULL;
    struct parsedfile config;
    int i;

    if ((argc > 5) || (((argc - 1) % 2) != 0))
    {
        show_msg(MSGERR, "Invalid number of arguments\n");
        show_msg(MSGERR, "%s\n", usage);
        exit(1);
    }

    for (i = 1; i < argc; i = i + 2)
    {
        if (!strcmp(argv[i], "-f"))
        {
            filename = argv[(i + 1)];
        }
        else if (!strcmp(argv[i], "-t"))
        {
            testhost = argv[(i + 1)];
        }
        else
        {
            show_msg(MSGERR, "Unknown option %s\n", argv[i]);
            show_msg(MSGERR, "%s\n", usage);
            exit(1);
        }
    }

    if (!filename)
        filename = strdup(CONF_FILE);

    printf("Reading configuration file %s...\n", filename);
    if (read_config(filename, &config) == 0)
        printf("... Read complete\n\n");
    else
        exit(1);

    /* If they specified a test host, test it, otherwise */
    /* dump the configuration                            */
    if (!testhost)
        show_conf(&config);
    else
        test_host(&config, testhost);

    return (0);
}

void test_host(struct parsedfile *config, char *host)
{
    struct in_addr hostaddr;
    struct prefixent *path;
    char *hostname, *port;
    char separator;
    unsigned long portno = 0;

    /* See if a port has been specified */
    hostname = strsplit(&separator, &host, ": \t\n");
    if (separator == ':')
    {
        port = strsplit(NULL, &host, " \t\n");
        if (port)
            portno = strtol(port, NULL, 0);
    }

    /* First resolve the host to an ip */
    if ((hostaddr.s_addr = resolve_ip(hostname, 0, 1)) == -1)
    {
        fprintf(stderr, "Error: Cannot resolve %s\n", host);
        return;
    }
    else
    {
        printf("Finding path for %s...\n", inet_ntoa(hostaddr));
        if (!(is_local(config, &(hostaddr))))
        {
            printf("Path is local\n");
        }
        else
        {
            pick_prefix(config, &path, &hostaddr, portno);
            if (path == &(config->defaultprefix))
            {
                printf("Path is reached via default NAT64 prefix:\n");
                show_prefix(config, path, 1);
            }
            else
            {
                printf("Host is reached via this path:\n");
                show_prefix(config, path, 0);
            }
        }
    }

    return;
}

void show_conf(struct parsedfile *config)
{
    struct netent *net;
    struct prefixent *prefix;

    /* Show the local networks */
    printf("=== Local networks (no NAT64 needed) ===\n");
    net = (config->localnets);
    while (net != NULL)
    {
        printf("Network: %15s ", inet_ntoa(net->localip));
        printf("Netmask: %15s\n", inet_ntoa(net->localnet));
        net = net->next;
    }
    printf("\n");

    /* If we have a default prefix configuration show it */
    printf("=== Default NAT64 prefix configuration ===\n");
    if ((config->defaultprefix).address != NULL)
    {
        show_prefix(config, &(config->defaultprefix), 1);
    }
    else
    {
        printf("No default NAT64 prefix specified, this is rarely a " "good idea\n");
    }
    printf("\n");

    /* Now show paths */
    if ((config->paths) != NULL)
    {
        prefix = (config->paths);
        while (prefix != NULL)
        {
            printf("=== Path (line no %d in configuration file)" " ===\n", prefix->lineno);
            show_prefix(config, prefix, 0);
            printf("\n");
            prefix = prefix->next;
        }
    }

    return;
}

void show_prefix(struct parsedfile *config, struct prefixent *prefix, int def)
{
    struct netent *net;

    /* Show address */
    if (prefix->address != NULL)
        printf("NAT64 prefix:       %s\n", prefix->address);
    else
        printf("NAT64 prefix:       ERROR! None specified\n");


    /* If this is the default servers and it has reachnets, thats stupid */
    if (def)
    {
        if (prefix->reachnets != NULL)
        {
            fprintf(stderr, "Error: The default NAT64 prefix has "
                    "specified networks it can be used to reach (subnet statements), "
                    "these statements are ignored since the " "default NAT64 prefix will be used for any network " "which is not specified in a subnet statement " "for other prefixes\n");
        }
    }
    else if (prefix->reachnets == NULL)
    {
        fprintf(stderr, "Error: No subnet statements specified for " "this NAT64 prefix, it will never be used\n");
    }
    else
    {
        printf("This NAT64 prefix can be used to reach:\n");
        net = prefix->reachnets;
        while (net != NULL)
        {
            printf("Network: %15s ", inet_ntoa(net->localip));
            printf("Netmask: %15s ", inet_ntoa(net->localnet));
            if (net->startport)
                printf("Ports: %5lu - %5lu", net->startport, net->endport);
            printf("\n");
            net = net->next;
        }
    }
}
