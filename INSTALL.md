Quick Installation Instructions
-------------------------------

1. Unpack the archive (though if you're reading this you've probably
already achieved that):

        tar -zxvf tnat64-<version>.tar.bz2
   or:

        git clone https://github.com/andrewshadura/tnat64

2. Generate config scripts by running:

        autoreconf --install --symlink

3. Run `./configure`, options which might be of interest (and that are 
   specific to tnat64) include:

	`--enable-oldmethod`	This forces tnat64 not to use the
				`RTLD_NEXT` parameter to `dlsym` to get the
				address of the `connect()` method tnat64
				overrides, instead it loads a reference
				to the libc shared library and then uses
				`dlsym()`. Again this is not very elegant
				and shouldn't be required.

	`--with-conf=<filename>`	You can specify the location of the tnat64
				configuration file using this option, it
				defaults to `/etc/tnat64.conf`

    Other standard autoconf options are provided by typing `./configure
    --help`.

    NOTE: The install path for the library is _NOT_ prefixed with `--prefix`,
    this is because it is strongly recommended that tnat64 is installed into
    `/lib` (and not `/usr/lib`). This is important if tnat64 is put into
    `/etc/ld.so.preload` since /usr is not mounted on many systems at boot
    time, meaning that programs running before `/usr` is mounted will try to
    preload tnat64, fail to find it and die, making the machine unusable. If
    you really wish to install the library into some other path use `--libdir`.

4. Compile the code by typing:

        make
   
   This should result in the creation of the following:
   
   - `libtnat64.so`: the libtnat64 library
   - `tnat64-validateconf`: a utility to verify the tnat64 configuration
      file

5. If you experience any errors at this step and don't know how to fix
them, seek help using the contacts listed on the projects homepage.

6. Install the compiled library. You can skip this step if you only plan
to use the library for personal use. If you want all users on the machine
to be able to use it however, su to root, then type:

        make install

This will install the library, the tnat64 script and its man pages
(`tnat64(8)`, `tnat64(1)` and `tnat64.conf(5)`) to the paths specified to
configure.

Note that by default the library is installed to /lib and that the
configure `--prefix` is IGNORED. See above for more detail.

7. At this point you'll need to create the tnat64 configuration file.
There are two samples provided in the build directory called
`tnat64.conf.simple.example` and `tnat64.conf.complex.example`.
Documentation on the configuration file format is provided in the
tnat64.conf man page (`man tnat64.conf`).

8. Having created the tnat64.conf file you should verify it using
tnat64-validateconf (some detail on validateconf can be found in the
tnat64.conf man page). Normally validateconf is run without arguments
(`./tnat64-validateconf`). Any errors which are displayed by validateconf
need to be rectified before tnat64 will function correctly.

9. You can now choose to make the library affect all users or just those
who choose to use it. If you want users to use it themselves, they can
simply use the `tnat64(1)` shell script to run programs (see `man tnat64`)
or do the following in their shell before running applications that need
to be transparently proxied:

	(in bash/zsh) `export LD_PRELOAD=<path to library>`

	(in fish) `set -x LD_PRELOAD <path to library>`

	(in csh) `setenv LD_PRELOAD <path to library>`

	`<path to library>` = e.g. `/lib/libtnat64.so.1.8`

If you want all users to pick up the library, place the full path to the
full library in the file `/etc/ld.so.preload` (e.g. `/lib/libtnat64.so`). Be
EXTREMELY careful if you do this, if you mistype it or in some way get it
wrong this will make your machine UNUSABLE. Also, if you do this, make
sure the directory you put the library in is in the root of the
filesystem, if the library is not available at boot time, again, your
machine will be UNUSABLE.

10. Go ahead and use it! At this point everything should work. Again, if
you experience any problems, use the contact points listed at the project's
homepage.
