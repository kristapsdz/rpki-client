# Introduction

**This software is still not entirely functional.  Please do not use it
unless doing so for specific testing.  Thank you!  If you'd like to
participate in development or testing, please contact the author.**

This is an implementation of RPKI, resource public key infrastructure,
described in [RFC 6480](https://tools.ietf.org/html/rfc6480).
It implements the *client* side of RPKI, which is responsible for
downloading and validating route ownership statements.
For usage, please read [rpki-client(1)](rpki-client.1).

The design focus of **rpki-client** is simplicity and security.
As such, it focusses on only implementing components of RPKI necessary
to its operation: namely, proper key signing, IP inheritence, and so on.
A lot of tightness mandated by the RPKI RFCs (such as which X509 fields
are mandatory or not) is not followed.
These areas are specifically noted in the sources.

**rpki-client** runs on a current [OpenBSD](https://www.openbsd.org)
installation with the the [OpenSSL](https://www.openssl.org) external
library installed.
See [Portability](#portability) for instructions on how to port the
software.
Non-current OpenBSD installations will need specification of an
alternate **rsync** utility with the **-e** flag.

At this time, **rpki-client** does not work with OpenBSD's native
[libressl](https://www.libressl.org) due to requiring CMS parsing.
According to 
[this thread](http://openbsd-archive.7691.n7.nabble.com/LibreSSL-why-is-support-for-CMS-disabled-td253212.html),
this omission is not for security purposes, but happenstance.

See the [TODO](TODO.md) file for open questions regarding RPKI operation
in general.
In the remainder of this document, I describe the architecture and
algorithm of **rpki-client**.

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
At this point, just run the following.

```
% make
```

If you have your OpenSSL installation in an alternative place
(alternative to where `pkg_add` will install it), adjust the `LDADD` and
`CFLAGS` variables in the *Makefile*.

Next, you'll need the */var/cache/rpki-client* directory in place.
It must be writable by the operator of **rpki-client**.

You'll also need TAL ("trust anchor locator") files.
There are some in the *tal* directory of this system, but you can
download them on your own.

To run **rpki-client**, just point it at your TAL files.
You'll also need the [openrsync(1)](https://man.openbsd.org/openrsync.1)
(or [rsync](https://rsync.samba.org/), which may be specified with the
**-e** argument) executable installed.

```
% ./rpki-client -rv ./tals/*.tal
```

Note the **-r** flag.
At the time, this is strongly recommended since CRL parsing takes ten
times longer due to huge CRL files.
This is not currently solvable within **rpki-client** unless in
designing a new non-OpenSSL parser for CRL files entirely.

# Architecture

The **rpki-client** run-time is split into at least three processes
which pass data back and forth.
"At least" since the system will dynamically spawn additional process.

The master process orchestrates all other process.
It also formats and outputs valid route data.

The first subordinate process is responsible for obtaining certificates,
route announcements, manifests, and so on.
It waits for the master process to give it a repository and destination,
then executes [openrsync(1)](https://man.openbsd.org/openrsync.1) and
waits for termination.
It executes child openrsync(1) processes asynchronously for maximum
efficiency.

*Side note*: although **rpki-client** can use [rsync](https://rsync.samba.org/)
instead of openrsync(1), this is not recommended for security reasons:
the latter has been designed to make maximum use of OpenBSD's security
framework, as has **rpki-client**.

The second subordinate process parses and validates data files.
It is given filenames by the master process, parses them in-order, and
returns the results.
The files are assumed to exist on disc by virtue of being downloaded
earlier by the first subordinate process.
This process performs the bulk of the work.

The master process is responsible for orchestrating this pipeline.
It seeds the parser process with the TAL files, retrieves TAL output,
then begins parsing certificates (X509), manifests (MFT), revocation
lists (CRL), and routes (ROA).
If any of these files sits in a repository not yet fetched, that
repository is fetched or refreshed.
When the repository is fetched, those pending entries are flushed into
the parser.

The master process also outputs valid routes.
At this time, it does so only in the
[bgpd.conf(5)](https://man.openbsd.org/bgpd.conf.5) format.

## Future security

It's trivially possible to put each type of file parse into its own
process, but it's not clear whether this adds any security since the
file-system available to a parser consists of all file types.

Alternatively, each repository might have its own parser that's
restricted to files only within the repository.
This would allow [unveil(2)](https://man.openbsd.org/unveil.2) to limit
the parser only to those in its repository.
The repository cache would need to be redesigned to nest repositories so
that a top-level repository would be able to access its children.

The latter is not difficult to implement.

# Algorithm

At its heart, **rpki-client** is a tool for validating hierarchical
statements.
The terminals of this hierarchy consist of IP address prefix and
numerical AS identifier components.
The non-terminal statements provide both acceptable ranges of both
components and links to further terminal and non-terminal nodes in the
tree.

Terminal nodes are ROA (route origin authorisation) and CRL (certificate
revocation list) files.  Non-terminal nodes are X509 (certificate) and
MFT (manifest) files.  The root node (there may be multiple roots) is a
TAL (trust anchor locator) file.

The validation algorithm is a breadth-first (though whether depth or
breadth first is irrelevant) tree walk.
It begins with a TAL file, which specifies a top-level X509 and a digest
of the file.

(TODO...)

# Portability

Just some notes here.
Nothing structured yet.

- `long` needs to be >32 bits to encompass all possible AS number
  values as specified by RFC 6793.  Anything less will require special
  conversion from the `ASN1_INTEGER` values, as the standard way of
  extracting via a `long` will truncate.
