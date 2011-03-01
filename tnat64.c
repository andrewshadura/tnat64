/*

    TNAT64 - Wrapper library for redirecting IPv4 connections to NAT64
    Copyright (C) 2011 Andrew O. Shadoura
    Based on original code of TNAT64, copyright (C) 2000 Shaun Clowes

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
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

/* PreProcessor Defines */
#include <config.h>

#ifdef USE_GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Global configuration variables */
char *progname = "libtnat64";   /* Name used in err msgs    */

/* Header Files */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <common.h>
#include <stdarg.h>
#include <parser.h>
#include <tsocks.h>

/* Global Declarations */
static int (*realconnect) (CONNECT_SIGNATURE);
static int (*realselect) (SELECT_SIGNATURE);
static int (*realpoll) (POLL_SIGNATURE);
static int (*realclose) (CLOSE_SIGNATURE);
static struct parsedfile *config;
static struct connreq *requests = NULL;
static int suid = 0;
static char *conffile = NULL;

/* Exported Function Prototypes */
void _init(void);
int connect(CONNECT_SIGNATURE);
int select(SELECT_SIGNATURE);
int poll(POLL_SIGNATURE);
int close(CLOSE_SIGNATURE);

/* Private Function Prototypes */
static int get_config();
static int get_environment();

void _init(void)
{
#ifdef USE_OLD_DLSYM
    void *lib;
#endif

    /* We could do all our initialization here, but to be honest */
    /* most programs that are run won't use our services, so     */
    /* we do our general initialization on first call            */

    /* Determine the logging level */
    suid = (getuid() != geteuid());

#ifndef USE_OLD_DLSYM
    realconnect = dlsym(RTLD_NEXT, "connect");
    realselect = dlsym(RTLD_NEXT, "select");
    realpoll = dlsym(RTLD_NEXT, "poll");
    realclose = dlsym(RTLD_NEXT, "close");
#else
    lib = dlopen(LIBCONNECT, RTLD_LAZY);
    realconnect = dlsym(lib, "connect");
    realselect = dlsym(lib, "select");
    realpoll = dlsym(lib, "poll");
    dlclose(lib);

    lib = dlopen(LIBC, RTLD_LAZY);
    realclose = dlsym(lib, "close");
    dlclose(lib);
#endif
}

static int get_environment()
{
    static int done = 0;
    int loglevel = MSGERR;
    char *logfile = NULL;
    char *env;

    if (done)
        return (0);

    /* Determine the logging level */
#ifndef ALLOW_MSG_OUTPUT
    set_log_options(-1, stderr, 0);
#else
    if ((env = getenv("TSOCKS_DEBUG")))
        loglevel = atoi(env);
    if (((env = getenv("TSOCKS_DEBUG_FILE"))) && !suid)
        logfile = env;
    set_log_options(loglevel, logfile, 1);
#endif

    done = 1;

    return (0);
}

static int get_config()
{
    static int done = 0;

    if (done)
        return (0);

    /* Determine the location of the config file */
#ifdef ALLOW_ENV_CONFIG
    if (!suid)
        conffile = getenv("TSOCKS_CONF_FILE");
#endif

    /* Read in the config file */
    config = malloc(sizeof(*config));
    if (!config)
        return (0);
    read_config(conffile, config);
    if (config->paths)
        show_msg(MSGDEBUG, "First lineno for first path is %d\n", config->paths->lineno);

    done = 1;

    return (0);

}

int connect(CONNECT_SIGNATURE)
{
    struct sockaddr_in *connaddr;
    struct sockaddr_in peer_address;
    struct sockaddr_in server_address;
    int gotvalidserver = 0, rc, namelen = sizeof(peer_address);
    int sock_type = -1;
    int sock_type_len = sizeof(sock_type);
    unsigned int res = -1;
    struct serverent *path;
    struct connreq *newconn;

    get_environment();

    /* If the real connect doesn't exist, we're stuffed */
    if (realconnect == NULL)
    {
        show_msg(MSGERR, "Unresolved symbol: connect\n");
        return (-1);
    }

    show_msg(MSGDEBUG, "Got connection request\n");

    connaddr = (struct sockaddr_in *)__addr;

    /* Get the type of the socket */
    getsockopt(__fd, SOL_SOCKET, SO_TYPE, (void *)&sock_type, &sock_type_len);

    /* If this isn't an INET socket for a TCP stream we can't  */
    /* handle it, just call the real connect now               */
    if ((connaddr->sin_family != AF_INET) || (sock_type != SOCK_STREAM))
    {
        show_msg(MSGDEBUG, "Connection isn't a TCP stream ignoring\n");
        return (realconnect(__fd, __addr, __len));
    }

    /* If we haven't initialized yet, do it now */
    get_config();

    /* Are we already handling this connect? */
    if ((newconn = find_socks_request(__fd, 1)))
    {
        if (memcmp(&newconn->connaddr, connaddr, sizeof(*connaddr)))
        {
            /* Ok, they're calling connect on a socket that is in our
             * queue but this connect() isn't to the same destination, 
             * they're obviously not trying to check the status of 
             * they're non blocking connect, they must have close()d 
             * the other socket and created a new one which happens
             * to have the same fd as a request we haven't had the chance
             * to delete yet, so we delete it here. */
            show_msg(MSGDEBUG, "Call to connect received on old " "tsocks request for socket %d but to " "new destination, deleting old request\n", newconn->sockid);
            kill_socks_request(newconn);
        }
        else
        {
            /* Ok, this call to connect() is to check the status of 
             * a current non blocking connect(). */
            if (newconn->state == FAILED)
            {
                show_msg(MSGDEBUG, "Call to connect received on failed " "request %d, returning %d\n", newconn->sockid, newconn->err);
                errno = newconn->err;
                rc = -1;
            }
            else if (newconn->state == DONE)
            {
                show_msg(MSGERR, "Call to connect received on completed " "request %d\n", newconn->sockid, newconn->err);
                rc = 0;
            }
            else
            {
                show_msg(MSGDEBUG, "Call to connect received on current request %d\n", newconn->sockid);
                rc = handle_request(newconn);
                errno = rc;
            }
            if ((newconn->state == FAILED) || (newconn->state == DONE))
                kill_socks_request(newconn);
            return ((rc ? -1 : 0));
        }
    }

    /* If the socket is already connected, just call connect  */
    /* and get its standard reply                             */
    if (!getpeername(__fd, (struct sockaddr *)&peer_address, &namelen))
    {
        show_msg(MSGDEBUG, "Socket is already connected, defering to " "real connect\n");
        return (realconnect(__fd, __addr, __len));
    }

    show_msg(MSGDEBUG, "Got connection request for socket %d to " "%s\n", __fd, inet_ntoa(connaddr->sin_addr));

    /* If the address is local call realconnect */
    if (!(is_local(config, &(connaddr->sin_addr))))
    {
        show_msg(MSGDEBUG, "Connection for socket %d is local\n", __fd);
        return (realconnect(__fd, __addr, __len));
    }

    /* Ok, so its not local, we need a path to the net */
    pick_server(config, &path, &(connaddr->sin_addr), ntohs(connaddr->sin_port));

    show_msg(MSGDEBUG, "Picked server %s for connection\n", (path->address ? path->address : "(Not Provided)"));
    if (path->address == NULL)
    {
        if (path == &(config->defaultserver))
            show_msg(MSGERR, "Connection needs to be made " "via default server but " "the default server has not " "been specified\n");
        else
            show_msg(MSGERR, "Connection needs to be made " "via path specified at line " "%d in configuration file but " "the server has not been " "specified for this path\n", path->lineno);
    }
    else if ((res = resolve_ip(path->address, 0, HOSTNAMES)) == -1)
    {
        show_msg(MSGERR, "The SOCKS server (%s) listed in the configuration " "file which needs to be used for this connection " "is invalid\n", path->address);
    }
    else
    {
        /* Construct the addr for the socks server */
        server_address.sin_family = AF_INET;    /* host byte order */
        server_address.sin_addr.s_addr = res;
        server_address.sin_port = htons(path->port);
        bzero(&(server_address.sin_zero), 8);

        /* Complain if this server isn't on a localnet */
        if (is_local(config, &server_address.sin_addr))
        {
            show_msg(MSGERR, "SOCKS server %s (%s) is not on a local subnet!\n", path->address, inet_ntoa(server_address.sin_addr));
        }
        else
            gotvalidserver = 1;
    }

    /* If we haven't found a valid server we return connection refused */
    if (!gotvalidserver || !(newconn = new_socks_request(__fd, connaddr, &server_address, path)))
    {
        errno = ECONNREFUSED;
        return (-1);
    }
    else
    {
        /* Now we call the main function to handle the connect. */
        rc = handle_request(newconn);
        /* If the request completed immediately it mustn't have been
         * a non blocking socket, in this case we don't need to know
         * about this socket anymore. */
        if ((newconn->state == FAILED) || (newconn->state == DONE))
            kill_socks_request(newconn);
        errno = rc;
        return ((rc ? -1 : 0));
    }
}

int select(SELECT_SIGNATURE)
{
    int nevents = 0;
    int rc = 0;
    int setevents = 0;
    int monitoring = 0;
    struct connreq *conn, *nextconn;
    fd_set mywritefds, myreadfds, myexceptfds;

    /* If we're not currently managing any requests we can just 
     * leave here */
    if (!requests)
        return (realselect(n, readfds, writefds, exceptfds, timeout));

    get_environment();

    show_msg(MSGDEBUG, "Intercepted call to select with %d fds, " "0x%08x 0x%08x 0x%08x, timeout %08x\n", n, readfds, writefds, exceptfds, timeout);

    for (conn = requests; conn != NULL; conn = conn->next)
    {
        if ((conn->state == FAILED) || (conn->state == DONE))
            continue;
        conn->selectevents = 0;
        show_msg(MSGDEBUG, "Checking requests for socks enabled socket %d\n", conn->sockid);
        conn->selectevents |= (writefds ? (FD_ISSET(conn->sockid, writefds) ? WRITE : 0) : 0);
        conn->selectevents |= (readfds ? (FD_ISSET(conn->sockid, readfds) ? READ : 0) : 0);
        conn->selectevents |= (exceptfds ? (FD_ISSET(conn->sockid, exceptfds) ? EXCEPT : 0) : 0);
        if (conn->selectevents)
        {
            show_msg(MSGDEBUG, "Socket %d was set for events\n", conn->sockid);
            monitoring = 1;
        }
    }

    if (!monitoring)
        return (realselect(n, readfds, writefds, exceptfds, timeout));

    /* This is our select loop. In it we repeatedly call select(). We 
     * pass select the same fdsets as provided by the caller except we
     * modify the fdsets for the sockets we're managing to get events
     * we're interested in (while negotiating with the socks server). When
     * events we're interested in happen we go off and process the result
     * ourselves, without returning the events to the caller. The loop
     * ends when an event which isn't one we need to handle occurs or 
     * the select times out */
    do
    {
        /* Copy the clients fd events, we'll change them as we wish */
        if (readfds)
            memcpy(&myreadfds, readfds, sizeof(myreadfds));
        else
            FD_ZERO(&myreadfds);
        if (writefds)
            memcpy(&mywritefds, writefds, sizeof(mywritefds));
        else
            FD_ZERO(&mywritefds);
        if (exceptfds)
            memcpy(&myexceptfds, exceptfds, sizeof(myexceptfds));
        else
            FD_ZERO(&myexceptfds);

        /* Now enable our sockets for the events WE want to hear about */
        for (conn = requests; conn != NULL; conn = conn->next)
        {
            if ((conn->state == FAILED) || (conn->state == DONE) || (conn->selectevents == 0))
                continue;
            /* We always want to know about socket exceptions */
            FD_SET(conn->sockid, &myexceptfds);
            /* If we're waiting for a connect or to be able to send
             * on a socket we want to get write events */
            if ((conn->state == SENDING) || (conn->state == CONNECTING))
                FD_SET(conn->sockid, &mywritefds);
            else
                FD_CLR(conn->sockid, &mywritefds);
            /* If we're waiting to receive data we want to get 
             * read events */
            if (conn->state == RECEIVING)
                FD_SET(conn->sockid, &myreadfds);
            else
                FD_CLR(conn->sockid, &myreadfds);
        }

        nevents = realselect(n, &myreadfds, &mywritefds, &myexceptfds, timeout);
        /* If there were no events we must have timed out or had an error */
        if (nevents <= 0)
            break;

        /* Loop through all the sockets we're monitoring and see if 
         * any of them have had events */
        for (conn = requests; conn != NULL; conn = nextconn)
        {
            nextconn = conn->next;
            if ((conn->state == FAILED) || (conn->state == DONE))
                continue;
            show_msg(MSGDEBUG, "Checking socket %d for events\n", conn->sockid);
            /* Clear all the events on the socket (if any), we'll reset
             * any that are necessary later. */
            setevents = 0;
            if (FD_ISSET(conn->sockid, &mywritefds))
            {
                nevents--;
                setevents |= WRITE;
                show_msg(MSGDEBUG, "Socket had write event\n");
                FD_CLR(conn->sockid, &mywritefds);
            }
            if (FD_ISSET(conn->sockid, &myreadfds))
            {
                nevents--;
                setevents |= READ;
                show_msg(MSGDEBUG, "Socket had write event\n");
                FD_CLR(conn->sockid, &myreadfds);
            }
            if (FD_ISSET(conn->sockid, &myexceptfds))
            {
                nevents--;
                setevents |= EXCEPT;
                show_msg(MSGDEBUG, "Socket had except event\n");
                FD_CLR(conn->sockid, &myexceptfds);
            }

            if (!setevents)
            {
                show_msg(MSGDEBUG, "No events on socket %d\n", conn->sockid);
                continue;
            }

            if (setevents & EXCEPT)
            {
                conn->state = FAILED;
            }
            else
            {
                rc = handle_request(conn);
            }
            /* If the connection hasn't failed or completed there is nothing
             * to report to the client */
            if ((conn->state != FAILED) && (conn->state != DONE))
                continue;

            /* Ok, the connection is completed, for good or for bad. We now
             * hand back the relevant events to the caller. We don't delete the
             * connection though since the caller should call connect() to 
             * check the status, we delete it then */

            if (conn->state == FAILED)
            {
                /* Damn, the connection failed. Whatever the events the socket
                 * was selected for we flag */
                if (conn->selectevents & EXCEPT)
                {
                    FD_SET(conn->sockid, &myexceptfds);
                    nevents++;
                }
                if (conn->selectevents & READ)
                {
                    FD_SET(conn->sockid, &myreadfds);
                    nevents++;
                }
                if (conn->selectevents & WRITE)
                {
                    FD_SET(conn->sockid, &mywritefds);
                    nevents++;
                }
                /* We should use setsockopt to set the SO_ERROR errno for this 
                 * socket, but this isn't allowed for some silly reason which 
                 * leaves us a bit hamstrung.
                 * We don't delete the request so that hopefully we can 
                 * return the error on the socket if they call connect() on it */
            }
            else
            {
                /* The connection is done,  if the client selected for 
                 * writing we can go ahead and signal that now (since the socket must
                 * be ready for writing), otherwise we'll just let the select loop
                 * come around again (since we can't flag it for read, we don't know
                 * if there is any data to be read and can't be bothered checking) */
                if (conn->selectevents & WRITE)
                {
                    FD_SET(conn->sockid, &mywritefds);
                    nevents++;
                }
            }
        }
    } while (nevents == 0);

    show_msg(MSGDEBUG, "Finished intercepting select(), %d events\n", nevents);

    /* Now copy our event blocks back to the client blocks */
    if (readfds)
        memcpy(readfds, &myreadfds, sizeof(myreadfds));
    if (writefds)
        memcpy(writefds, &mywritefds, sizeof(mywritefds));
    if (exceptfds)
        memcpy(exceptfds, &myexceptfds, sizeof(myexceptfds));

    return (nevents);
}

int poll(POLL_SIGNATURE)
{
    int nevents = 0;
    int rc = 0, i;
    int setevents = 0;
    int monitoring = 0;
    struct connreq *conn, *nextconn;

    /* If we're not currently managing any requests we can just 
     * leave here */
    if (!requests)
        return (realpoll(ufds, nfds, timeout));

    get_environment();

    show_msg(MSGDEBUG, "Intercepted call to poll with %d fds, " "0x%08x timeout %d\n", nfds, ufds, timeout);

    for (conn = requests; conn != NULL; conn = conn->next)
        conn->selectevents = 0;

    /* Record what events on our sockets the caller was interested
     * in */
    for (i = 0; i < nfds; i++)
    {
        if (!(conn = find_socks_request(ufds[i].fd, 0)))
            continue;
        show_msg(MSGDEBUG, "Have event checks for socks enabled socket %d\n", conn->sockid);
        conn->selectevents = ufds[i].events;
        monitoring = 1;
    }

    if (!monitoring)
        return (realpoll(ufds, nfds, timeout));

    /* This is our poll loop. In it we repeatedly call poll(). We 
     * pass select the same event list as provided by the caller except we
     * modify the events for the sockets we're managing to get events
     * we're interested in (while negotiating with the socks server). When
     * events we're interested in happen we go off and process the result
     * ourselves, without returning the events to the caller. The loop
     * ends when an event which isn't one we need to handle occurs or 
     * the poll times out */
    do
    {
        /* Enable our sockets for the events WE want to hear about */
        for (i = 0; i < nfds; i++)
        {
            if (!(conn = find_socks_request(ufds[i].fd, 0)))
                continue;

            /* We always want to know about socket exceptions but they're 
             * always returned (i.e they don't need to be in the list of 
             * wanted events to be returned by the kernel */
            ufds[i].events = 0;

            /* If we're waiting for a connect or to be able to send
             * on a socket we want to get write events */
            if ((conn->state == SENDING) || (conn->state == CONNECTING))
                ufds[i].events |= POLLOUT;
            /* If we're waiting to receive data we want to get 
             * read events */
            if (conn->state == RECEIVING)
                ufds[i].events |= POLLIN;
        }

        nevents = realpoll(ufds, nfds, timeout);
        /* If there were no events we must have timed out or had an error */
        if (nevents <= 0)
            break;

        /* Loop through all the sockets we're monitoring and see if 
         * any of them have had events */
        for (conn = requests; conn != NULL; conn = nextconn)
        {
            nextconn = conn->next;
            if ((conn->state == FAILED) || (conn->state == DONE))
                continue;

            /* Find the socket in the poll list */
            for (i = 0; ((i < nfds) && (ufds[i].fd != conn->sockid)); i++)
                /* Empty Loop */ ;
            if (i == nfds)
                continue;

            show_msg(MSGDEBUG, "Checking socket %d for events\n", conn->sockid);

            if (!ufds[i].revents)
            {
                show_msg(MSGDEBUG, "No events on socket\n");
                continue;
            }

            /* Clear any read or write events on the socket, we'll reset
             * any that are necessary later. */
            setevents = ufds[i].revents;
            if (setevents & POLLIN)
            {
                show_msg(MSGDEBUG, "Socket had read event\n");
                ufds[i].revents &= ~POLLIN;
                nevents--;
            }
            if (setevents & POLLOUT)
            {
                show_msg(MSGDEBUG, "Socket had write event\n");
                ufds[i].revents &= ~POLLOUT;
                nevents--;
            }
            if (setevents & (POLLERR | POLLNVAL | POLLHUP))
                show_msg(MSGDEBUG, "Socket had error event\n");

            /* Now handle this event */
            if (setevents & (POLLERR | POLLNVAL | POLLHUP))
            {
                conn->state = FAILED;
            }
            else
            {
                rc = handle_request(conn);
            }
            /* If the connection hasn't failed or completed there is nothing
             * to report to the client */
            if ((conn->state != FAILED) && (conn->state != DONE))
                continue;

            /* Ok, the connection is completed, for good or for bad. We now
             * hand back the relevant events to the caller. We don't delete the
             * connection though since the caller should call connect() to 
             * check the status, we delete it then */

            if (conn->state == FAILED)
            {
                /* Damn, the connection failed. Just copy back the error events 
                 * from the poll call, error events are always valid even if not
                 * requested by the client */
                /* We should use setsockopt to set the SO_ERROR errno for this 
                 * socket, but this isn't allowed for some silly reason which 
                 * leaves us a bit hamstrung.
                 * We don't delete the request so that hopefully we can 
                 * return the error on the socket if they call connect() on it */
            }
            else
            {
                /* The connection is done,  if the client polled for 
                 * writing we can go ahead and signal that now (since the socket must
                 * be ready for writing), otherwise we'll just let the select loop
                 * come around again (since we can't flag it for read, we don't know
                 * if there is any data to be read and can't be bothered checking) */
                if (conn->selectevents & WRITE)
                {
                    setevents |= POLLOUT;
                    nevents++;
                }
            }
        }
    } while (nevents == 0);

    show_msg(MSGDEBUG, "Finished intercepting poll(), %d events\n", nevents);

    /* Now restore the events polled in each of the blocks */
    for (i = 0; i < nfds; i++)
    {
        if (!(conn = find_socks_request(ufds[i].fd, 1)))
            continue;

        ufds[i].events = conn->selectevents;
    }

    return (nevents);
}

int close(CLOSE_SIGNATURE)
{
    int rc;
    struct connreq *conn;

    if (realclose == NULL)
    {
        show_msg(MSGERR, "Unresolved symbol: close\n");
        return (-1);
    }

    show_msg(MSGDEBUG, "Call to close(%d)\n", fd);

    rc = realclose(fd);

    /* If we have this fd in our request handling list we 
     * remove it now */
    if ((conn = find_socks_request(fd, 1)))
    {
        show_msg(MSGDEBUG, "Call to close() received on file descriptor " "%d which is a connection request of status %d\n", conn->sockid, conn->state);
        kill_socks_request(conn);
    }

    return (rc);
}

#if 0
        /* Get the flags of the socket, (incase its non blocking */
if ((sockflags = fcntl(sockid, F_GETFL)) == -1)
{
    sockflags = 0;
}

        /* If the flags show the socket as blocking, set it to   */
        /* blocking for our connection to the socks server       */
if ((sockflags & O_NONBLOCK) != 0)
{
    fcntl(sockid, F_SETFL, sockflags & (~(O_NONBLOCK)));
}
#endif
#if 0
        /* If the socket was in non blocking mode, restore that */
if ((sockflags & O_NONBLOCK) != 0)
{
    fcntl(sockid, F_SETFL, sockflags);
}
#endif
