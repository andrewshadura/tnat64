/*

    commmon.c    - Common routines for the tnat64 package 

*/

#include <config.h>
#include <stdio.h>
#include <netdb.h>
#include <common.h>
#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* Globals */
static int loglevel = MSGERR;          /* The default logging level is to only log
                                   error messages */
static char *logfilename = NULL;       /* Name of file to which log messages should
                                   be redirected */
static FILE *logfile = NULL;           /* File to which messages should be logged */
static int logstamp = 0;               /* Timestamp (and pid stamp) messages */

static char *logprogname = NULL;

unsigned int HIDDENSYM resolve_ip(char *host, int showmsg, int allownames)
{
    struct hostent *new;
    unsigned int hostaddr;
    struct in_addr *ip;

    if ((hostaddr = inet_addr(host)) == (unsigned int)-1)
    {
        /* We couldn't convert it as a numerical ip so */
        /* try it as a dns name                        */
        if (allownames)
        {
#ifdef HAVE_GETHOSTBYNAME
            if ((new = gethostbyname(host)) == (struct hostent *)0)
            {
#endif
                return (-1);
#ifdef HAVE_GETHOSTBYNAME
            }
            else
            {
                ip = ((struct in_addr *)*new->h_addr_list);
                hostaddr = ip->s_addr;
                if (showmsg)
                    printf("Connecting to %s...\n", inet_ntoa(*ip));
            }
#endif
        }
        else
            return (-1);
    }

    return (hostaddr);
}

/* Set logging options, the options are as follows:             */
/*  level - This sets the logging threshold, messages with      */
/*          a higher level (i.e lower importance) will not be   */
/*          output. For example, if the threshold is set to     */
/*          MSGWARN a call to log a message of level MSGDEBUG   */
/*          would be ignored. This can be set to -1 to disable  */
/*          messages entirely                                   */
/*  progname - Program name prefixed to all log messages        */
/*  filename - This is a filename to which the messages should  */
/*             be logged instead of to standard error           */
/*  timestamp - This indicates that messages should be prefixed */
/*              with timestamps (and the process id)            */
void HIDDENSYM set_log_options(int level, const char *progname, const char *filename, int timestamp)
{

    loglevel = level;
    if (loglevel < MSGERR)
        loglevel = MSGNONE;

    if (progname)
    {
        logprogname = strdup(progname);
    }

    if (filename)
    {
        logfilename = strdup(filename);
    }

    logstamp = timestamp;
}

void HIDDENSYM show_msg(int level, char *fmt, ...)
{
    va_list ap;
    int saveerr;
    char timestring[20];
    time_t timestamp;

    if ((loglevel == MSGNONE) || (level > loglevel))
        return;

    if (!logfile)
    {
        if (logfilename)
        {
            logfile = fopen(logfilename, "a");
            if (logfile == NULL)
            {
                logfile = stderr;
                show_msg(MSGERR, "Could not open log file, %s, %s\n", logfilename, strerror(errno));
            }
        }
        else
            logfile = stderr;
    }

    if (logstamp)
    {
        timestamp = time(NULL);
        strftime(timestring, sizeof(timestring), "%H:%M:%S", localtime(&timestamp));
        fprintf(logfile, "%s ", timestring);
    }

    fputs(logprogname, logfile);

    if (logstamp)
    {
        fprintf(logfile, "(%d)", getpid());
    }

    fputs(": ", logfile);

    va_start(ap, fmt);

    /* Save errno */
    saveerr = errno;

    vfprintf(logfile, fmt, ap);

    fflush(logfile);

    errno = saveerr;

    va_end(ap);
}
