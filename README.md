# Introduction

**This software is still not entirely functional.  Please do not use it
unless doing so for specific testing.  Thank you!**

This is an implementation of RPKI, most generally described in [RFC
6480](https://tools.ietf.org/html/rfc6480).
It implements the *client* side of RPKI, which is responsible for
downloading and validating route ownership statements.
The focus of this tool is simplicity and security.

It runs on a current [OpenBSD](https://www.openbsd.org) installation
with the the [OpenSSL](https://www.openssl.org) external library
installed.
At this time, **rpki-client** does not work with the native
[libressl](https://www.libressl.org) due to requiring CMS parsing.

In this document, I briefly describe the deployment, architecture, and
functionality of the **rpki-client** system.

## Project background

**rpki-client** is written as part of the
[rpki-client(1)](https://medium.com/@jobsnijders/a-proposal-for-a-new-rpki-validator-openbsd-rpki-client-1-15b74e7a3f65)
project, an
[RPKI](https://en.wikipedia.org/wiki/Resource_Public_Key_Infrastructure)
validator for OpenBSD. 
It was funded by [NetNod](https://www.netnod.se),
[IIS.SE](https://www.iis.se), [SUNET](https://www.sunet.se) and
[6connect](https://www.6connect.com).

# Installation

First, you'll need a recent [OpenSSL](https://www.openssl.org/) library
on your OpenBSD system.
You'll also need the **openrsync** executable installed.
(You can obviously use plain **rsync**, but you'll need to change the
binary names in *main.c*.)
At this point, just run the following.

```
% make
```

If you have your OpenSSL installation in an alternative place, adjust
the `LDADD` and `CFLAGS` variables in the *Makefile*.

Next, you'll need the */var/cache/rpki-client* directory in place.
It must be writable by the operator of **rpki-client**.

You'll also need TAL ("trust anchor locator") files.
There are some in the *tal* directory of this system, but you can
download them on your own.

To run **rpki-client**, just point it at your TAL files:

```
% ./rpki-client -v ./tals/*.tal
```

# Architecture

The **rpki-client** run-time is split into at least three processes
which pass data back and forth.
The first (master) process orchestrates all other process.
It also formats and outputs valid route data.

The first subordinate process is responsible for obtaining certificates,
route announcements, manifests, and so on.
It waits for the master process to give it a repository and destination,
then executes **openrsync** and waits for termination.
It executes child **openrsync** processes asynchronously for maximum
efficiency.

The second subordinate process parses and validates data files.
It is given filenames by the master process, parses them in-order, and
returns the results.
The returned results are guaranteed to be valid.

The master process is responsible, in orchestrating this pipeline, with
determining which files have been downloaded.
