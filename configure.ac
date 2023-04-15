#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])

AC_INIT([tnat64],[0.06],[],[],[https://github.com/andrewshadura/tnat64])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([tnat64.c])

AM_INIT_AUTOMAKE([foreign dist-xz no-dist-gzip])
LT_INIT
AM_PROG_CC_C_O

AC_CONFIG_HEADERS([config.h])

dnl Our default prefix is /usr/ since most people will be using tsocks
dnl on Linux systems and that /usr/local/ stuff annoys them
AC_PREFIX_DEFAULT([/usr])

dnl if libdir hasn't been set by the user default it to /lib since
dnl tsocks needs to be on the root partition if put in the
dnl /etc/ld.so.preload file
test "$libdir" = "\${exec_prefix}/lib" && libdir="/lib"

dnl Arguments we allow
AC_ARG_ENABLE(oldmethod,
[  --enable-oldmethod	   use the old method to override connect ])
AC_ARG_ENABLE(envconf,
[  --disable-envconf       do not allow TNAT64_CONF_FILE to specify configuration file ])
AC_ARG_WITH(conf,
[  --with-conf=<file>      location of configuration file (/etc/tnat64.conf default)],[
if test "${withval}" = "yes" ; then
  AC_MSG_ERROR("--with-conf requires the location of the configuration file as an argument")
else
  CONF_FILE=${withval}
fi
], [
  CONF_FILE=/etc/tnat64.conf
])
AC_DEFINE_UNQUOTED(CONF_FILE,["${CONF_FILE}"],[Location of configuration file (typically /etc/tnat64.conf)])
AC_SUBST(CONF_FILE)

dnl -----------------------------------
dnl Get hostname and other information.
dnl -----------------------------------
AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_LN_S

dnl Check if the C compiler accepts -Wall
AC_MSG_CHECKING("if the C compiler accepts -Wall")
OLDCFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -Wall"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[AC_MSG_RESULT(yes)],[
   CFLAGS="$OLDCFLAGS"
   AC_MSG_RESULT(no)])

dnl Checks for standard header files.
AC_HEADER_STDC

dnl Check for the dynamic loader function header
AC_CHECK_HEADER(dlfcn.h,,AC_MSG_ERROR("dlfcn.h not found"))

dnl Check for the socket header
AC_CHECK_HEADER(sys/socket.h,,AC_MSG_ERROR("sys/socket.h not found"))

dnl Check for the arpa/inet.h header (inet_ntoa and inet_addr)
AC_CHECK_HEADER(arpa/inet.h,,AC_MSG_ERROR("arpa/inet.h not found"))

dnl Check for the fcntl header
AC_CHECK_HEADER(fcntl.h,,AC_MSG_ERROR("fcntl.h not found"))

dnl Check for the poll header
AC_CHECK_HEADER(sys/poll.h,,AC_MSG_ERROR("sys/poll.h not found"))

dnl Other headers we're interested in

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h unistd.h])

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostbyname inet_ntoa memset socket strcspn strdup strerror strspn strtol])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T

dnl First find the library that contains connect() (obviously
dnl the most important library for us). Once we've found it
dnl we chuck it on the end of LIBS, that lib may end up there
dnl more than once (since we do our search with an empty libs
dnl list) but that isn't a problem
OLDLIBS="${LIBS}"
LIBS=
CONNECTLIB=
for LIB in c socket; do
  AC_CHECK_LIB("${LIB}",connect,[
    CONNECTLIB="${LIB}"
    break
  ],)
done
LIBS="${OLDLIBS} -l${CONNECTLIB}"
if test "${CONNECTLIB}" = ""; then
  AC_MSG_ERROR('Could not find library containing connect()')
fi

dnl Check for socket
AC_CHECK_FUNC(socket,, [
  AC_CHECK_LIB(socket, socket,,AC_MSG_ERROR("socket function not found"))])

dnl Check for a function to convert an ascii ip address
dnl to a sin_addr. 
AH_TEMPLATE(HAVE_INET_ADDR,[Work out which function we have for conversion from string IPs to numerical ones])
AH_TEMPLATE(HAVE_INET_ATON,[Work out which function we have for conversion from string IPs to numerical ones])
AC_CHECK_FUNC(inet_aton, AC_DEFINE(HAVE_INET_ATON), [
  AC_CHECK_FUNC(inet_addr, AC_DEFINE(HAVE_INET_ADDR), [
    AC_CHECK_LIB(nsl, inet_addr, [ AC_DEFINE(HAVE_INET_ADDR)
                                   LIBS="${LIBS} -lnsl" ], [
		AC_MSG_ERROR("Neither inet_aton or inet_addr present")])])])

dnl Look for gethostbyname (needed by tsocks and inspectsocks)
AC_CHECK_FUNC(gethostbyname, AC_DEFINE(HAVE_GETHOSTBYNAME), [
  AC_CHECK_LIB(xnet, gethostbyname, AC_DEFINE(HAVE_GETHOSTBYNAME), [
	       AC_MSG_ERROR(["gethostbyname not found, name lookups in " \
		      "tsocks and inspectsocks disabled"])])])

dnl The simple programs (saveme and inspectsocks) have no further 
dnl requirements, so save the libs needed here and use them in the
dnl Makefile
SIMPLELIBS=${LIBS}
LIBS=

dnl Checks for libraries.
dnl Replace `main' with a function in -ldl:
AC_CHECK_LIB(dl, dlsym,,AC_MSG_ERROR("libdl is required"))

dnl If we're using gcc here define _GNU_SOURCE
AC_MSG_CHECKING(for RTLD_NEXT from dlfcn.h)
AH_TEMPLATE(USE_GNU_SOURCE,[Use _GNU_SOURCE to define RTLD_NEXT, mostly for RH7 systems])
AC_EGREP_CPP(yes,
[
 #include <dlfcn.h>
 #ifdef RTLD_NEXT
	yes
 #endif
], [
  AC_MSG_RESULT(yes)
], [
  AC_MSG_RESULT(no)
  AC_MSG_CHECKING(for RTLD_NEXT from dlfcn.h with _GNU_SOURCE)
  AC_EGREP_CPP(yes,
  [
   #define _GNU_SOURCE
   #include <dlfcn.h>
   #ifdef RTLD_NEXT
	yes
   #endif
  ], [
    AC_MSG_RESULT(yes)
    AC_DEFINE(USE_GNU_SOURCE)
  ], [
    AC_MSG_RESULT(no)
    AC_DEFINE(USE_OLD_DLSYM)
    oldmethod="yes"
  ])    
])

AH_TEMPLATE(ALLOW_ENV_CONFIG,[Allow TNAT64_CONF_FILE in environment to specify config file location])
if test "x${enable_envconf}" = "x"; then
  AC_DEFINE(ALLOW_ENV_CONFIG)
fi

AH_TEMPLATE(USE_OLD_DLSYM,,[dlopen() the old libc to get connect() instead of RTLD_NEXT, hopefully shouldn't be needed])
if test "${enable_oldmethod}" = "yes"; then
  AC_DEFINE(USE_OLD_DLSYM)
  oldmethod="yes"
fi

AH_TEMPLATE(ALLOW_MSG_OUTPUT,[Allow tsocks to generate messages to stderr when errors are encountered, this is really important and should only be disabled if you're REALLY sure. It can also be turned off at run time, see the man page for details])
if test "x${enable_debug}" = "x"; then
  AC_DEFINE(ALLOW_MSG_OUTPUT)
fi

dnl If we have to use the old method of overriding connect (i.e no
dnl RTLD_NEXT) we need to know the location of the library that
dnl contains connect(), select(), poll() and close()
if test "${oldmethod}" = "yes"; then 
  dnl We need to find the path to the library, to do 
  dnl this we use find on the usual suspects, i.e /lib and
  dnl /usr/lib

  dnl Check that find is available, it should be somehere
  dnl in the path 
  AC_CHECK_PROG(FIND, find, find)
  if test "${FIND}" = ""; then
    AC_MSG_ERROR('find not found in path')
  fi

  dnl Find tail, it should always be somewhere in the path
  dnl but for safety's sake
  AC_CHECK_PROG(TAIL, tail, tail)
  if test "${TAIL}" = ""; then
    AC_MSG_ERROR('tail not found in path')
  fi

  dnl Now find the library we need
  AC_MSG_CHECKING("location of lib${CONNECTLIB}.so")
  LIBCONNECT=
  for DIR in '/lib' '/usr/lib'; do
    if test "${LIBCONNECT}" = ""; then
      LIBCONNECT=`$FIND $DIR -name "lib${CONNECTLIB}.so.?" 2>/dev/null | $TAIL -1`
    fi
  done

  AC_DEFINE_UNQUOTED(LIBCONNECT, "${LIBCONNECT}",[path to library containing connect(), needed if USE_OLD_DLSYM is enabled])
  if test "${LIBCONNECT}" = ""; then
     AC_MSG_ERROR("not found!")
  fi

  AC_MSG_RESULT($LIBCONNECT)

  dnl close() should be in libc, find it
  AC_MSG_CHECKING("location of libc.so")
  LIBC=
  for DIR in '/lib' '/usr/lib'; do
    if test "${LIBC}" = ""; then
      LIBC=`$FIND $DIR -name "libc.so.?" 2>/dev/null | $TAIL -1`
    fi
  done

  AC_DEFINE_UNQUOTED(LIBC, "${LIBC}",[path to libc, needed if USE_OLD_DLSYM is enabled])
  if test "${LIBC}" = ""; then
     AC_MSG_ERROR("not found!")
  fi

  AC_MSG_RESULT($LIBC)
fi

dnl Find the correct connect prototype on this machine 
AC_MSG_CHECKING(for correct connect prototype)
PROTO=
PROTO1='int __fd, const struct sockaddr * __addr, int len'
PROTO2='int __fd, const struct sockaddr_in * __addr, socklen_t __len'
PROTO3='int __fd, struct sockaddr * __addr, int __len'
PROTO4='int __fd, const struct sockaddr * __addr, socklen_t __len'
for testproto in "${PROTO1}" \
                 "${PROTO2}" \
                 "${PROTO3}" \
                 "${PROTO4}" 
do
  if test "${PROTO}" = ""; then
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <sys/socket.h>
      int connect($testproto);
    ]], [[]])],[PROTO="$testproto";],[])
  fi
done
if test "${PROTO}" = ""; then
  AC_MSG_ERROR("no match found!")
fi
AC_MSG_RESULT([connect(${PROTO})])
AC_DEFINE_UNQUOTED(CONNECT_SIGNATURE, [${PROTO}],[Prototype and function header for connect function])

dnl Pick which of the sockaddr type arguments we need for
dnl connect(), we need to cast one of ours to it later 
SOCKETARG="struct sockaddr *"
case "${PROTO}" in
   *sockaddr_in*)
      SOCKETARG="struct sockaddr_in *"
      ;;
esac
AC_DEFINE_UNQUOTED(CONNECT_SOCKARG, [${SOCKETARG}],[The type of socket structure pointer to use to call the real connect])

dnl Find the correct socket prototype on this machine 
AC_MSG_CHECKING(for correct socket prototype)
PROTO=
PROTO1='int __domain, int __type, int __protocol'
for testproto in "${PROTO1}" 
do
  if test "${PROTO}" = ""; then
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <sys/socket.h>
      int socket($testproto);
    ]], [[]])],[PROTO="$testproto";],[])
  fi
done
if test "${PROTO}" = ""; then
  AC_MSG_ERROR("no match found!")
fi
AC_MSG_RESULT([socket(${PROTO})])
AC_DEFINE_UNQUOTED(SOCKET_SIGNATURE, [${PROTO}],[Prototype and function header for socket function])

dnl Find the correct getpeername prototype on this machine 
AC_MSG_CHECKING(for correct getpeername prototype)
PROTO=
PROTO1='int __fd, struct sockaddr * __addr, socklen_t * __len'
for testproto in "${PROTO1}" 
do
  if test "${PROTO}" = ""; then
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <sys/socket.h>
      int getpeername($testproto);
    ]], [[]])],[PROTO="$testproto";],[])
  fi
done
if test "${PROTO}" = ""; then
  AC_MSG_ERROR("no match found!")
fi
AC_MSG_RESULT([getpeername(${PROTO})])
AC_DEFINE_UNQUOTED(GETPEERNAME_SIGNATURE, [${PROTO}],[Prototype and function header for getpeername function])

dnl Find the correct getsockname prototype on this machine 
AC_MSG_CHECKING(for correct getsockname prototype)
PROTO=
PROTO1='int __fd, struct sockaddr * __addr, socklen_t * __len'
for testproto in "${PROTO1}" 
do
  if test "${PROTO}" = ""; then
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <sys/socket.h>
      int getsockname($testproto);
    ]], [[]])],[PROTO="$testproto";],[])
  fi
done
if test "${PROTO}" = ""; then
  AC_MSG_ERROR("no match found!")
fi
AC_MSG_RESULT([getsockname(${PROTO})])
AC_DEFINE_UNQUOTED(GETSOCKNAME_SIGNATURE, [${PROTO}],[Prototype and function header for getsockname function])

dnl Output the special librarys (libdl etc needed for tsocks)
SPECIALLIBS=${LIBS}
AC_SUBST(SPECIALLIBS)
LIBS=${SIMPLELIBS}

dnl Check if busybox is dynamically linked, so we might
dnl want to fall back to it in tests
AC_PATH_PROG(BUSYBOX, busybox, busybox)
if test -n "$BUSYBOX"
then
  AC_MSG_CHECKING(if busybox dynamically linked)
  if ldd "$BUSYBOX" 2>&1 | grep -q "not a dynamic"
  then
    AC_MSG_RESULT(no)
    BUSYBOX=""
  else
    AC_MSG_RESULT(yes)
  fi
fi


dnl See if we can run tests
AC_CHECK_PROG(DIG, dig, dig)
if test -z "$DIG"
then
  AC_CHECK_PROGS(NSLOOKUP, [host nslookup])
fi

AC_CHECK_PROGS(NETCAT, [netcat nc telnet])
if test -z "$NETCAT"
then
  if test -n "$BUSYBOX"
  then
    AC_MSG_CHECKING(if busybox has nc applet)
    if "$BUSYBOX" nc 2>/dev/null || test $? = 1
    then
      AC_MSG_RESULT(yes)
      NETCAT="$BUSYBOX nc"
    else
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(if busybox has telnet applet)
      if "$BUSYBOX" telnet 2>/dev/null || test $? = 1
      then
	AC_MSG_RESULT(yes)
	NETCAT="$BUSYBOX telnet"
      else
	AC_MSG_RESULT(no)
      fi
    fi
  fi
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
