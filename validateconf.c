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
static const char *progname = "tnat64-validateconf";        /* Name for error msgs      */

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

int show_prefix(struct parsedfile *, struct prefixent *, int);
int show_conf(struct parsedfile *config);
void test_host(struct parsedfile *config, char *);

int main(int argc, char *argv[])
{
    char *usage = "Usage: [-f conf file] [-t hostname/ip[:port]]";
    char *filename = NULL;
    char *testhost = NULL;
    struct parsedfile config;
    int i;

    set_log_options(MSGERR, progname, NULL, 0);

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
    if (!testhost) {
        int retval = show_conf(&config);
        if (retval != 0) {
            fprintf(stderr, "Found %d error(s)\n", retval);
            exit(2);
        }
    }
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

int show_conf(struct parsedfile *config)
{

    int error_count = 0;

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
        error_count += show_prefix(config, &(config->defaultprefix), 1);
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
            error_count += show_prefix(config, prefix, 0);
            printf("\n");
            prefix = prefix->next;
        }
    }

    return error_count;
}

int show_prefix(struct parsedfile *config, struct prefixent *prefix, int def)
{
    int error_count = 0;
    struct netent *net;

    /* Show address */
    if (prefix->address != NULL) {
        printf("NAT64 prefix:       %s/%d\n", prefix->address, prefix->prefix_size);

        if (prefix->prefix_size < 128 && (prefix->prefix).s6_addr[8] != 0) {
            // RFC 6052 section 2.2 states that this byte in the NAT64 prefix MUST be 0.
            show_msg(MSGERR, "NAT64 prefix specified is invalid - the 8th bit must be zero (RFC6052 2.2)\n");
            (prefix->prefix).s6_addr[8] = 0;

            char corrected_prefix_buffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(prefix->prefix), corrected_prefix_buffer, sizeof(corrected_prefix_buffer));
            show_msg(MSGERR, "Corrected NAT64 prefix: %s/%d\n", corrected_prefix_buffer, prefix->prefix_size);

            error_count++;
        }

        char suffix_buffer[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(prefix->suffix), suffix_buffer, sizeof(suffix_buffer));

        if (strcmp(suffix_buffer, "::") != 0) {
            printf("NAT64 suffix:       %s\n", suffix_buffer);


            // Check if the NAT64 suffix is too large.
            int suffix_size = 0;
            switch(prefix->prefix_size) {
                case 32: suffix_size = 7; break;
                case 40: suffix_size = 6; break;
                case 48: suffix_size = 5; break;
                case 56: suffix_size = 4; break;
                case 64: suffix_size = 3; break;
            }

            int suffix_used_bytes = 0;
            for (int i = 0; i < 16; i++) {
                if ((prefix->suffix).s6_addr[15-i] != 0) {
                    suffix_used_bytes = (i + 1);
                }
            }

            if (suffix_used_bytes > suffix_size) {
                // Clear all bytes inside the suffix that would overwrite
                // bytes in the prefix.

                for (int i = 0; i < (16-suffix_size); i++) {
                    (prefix->suffix).s6_addr[i] = 0;
                }

                inet_ntop(AF_INET6, &(prefix->suffix), suffix_buffer, sizeof(suffix_buffer));

                if (suffix_size > 0) {
                    fprintf(stderr, "Error: The specified NAT64 suffix (%d bytes) is larger than "
                                "the available space inside the NAT64 prefix (%d bytes).\n"
                                "The suffix will be truncated to fit - new suffix: %s \n", 
                                suffix_used_bytes, suffix_size, suffix_buffer );
                }
                else {
                    fprintf(stderr, "Error: The specified NAT64 prefix size (/%d) "
                                "does not allow for a NAT64 suffix.\n"
                                "Please choose a different prefix or remove the suffix.\n", 
                                prefix->prefix_size);
                }

                error_count++;
            }

        }      

    }
    else {
        printf("NAT64 prefix:       ERROR! None specified\n");
        error_count++;
    }


    /* If this is the default servers and it has reachnets, thats stupid */
    if (def)
    {
        if (prefix->reachnets != NULL)
        {
            fprintf(stderr, "Error: The default NAT64 prefix has "
                    "specified networks it can be used to reach (subnet statements), "
                    "these statements are ignored since the " "default NAT64 prefix will be used for any network " "which is not specified in a subnet statement " "for other prefixes\n");
            error_count++;
        }
    }
    else if (prefix->reachnets == NULL)
    {
        fprintf(stderr, "Error: No subnet statements specified for " "this NAT64 prefix, it will never be used\n");
        error_count++;
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

    return error_count;
}
