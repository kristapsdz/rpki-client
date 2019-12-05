# Introduction

**This system has been merged into OpenBSD base.  If you'd like to
contribute to rpki-client, please mail your patches to tech@openbsd.org.
This repository is simply the OpenBSD version plus some glue for
portability.**

**rpki-client** is an implementation of RPKI (resource public key
infrastructure) described in [RFC
6480](https://tools.ietf.org/html/rfc6480).
It implements the *client* side of RPKI, which is responsible for
downloading and validating route origin statements.
For usage, please read [rpki-client(8)](rpki-client.8).

The design focus of **rpki-client** is simplicity and security.
To wit, it implements RPKI components necessary for validating route
statements and omits superfluities (such as, for example, which X509
certificate sections must be labelled "Critical").

The system runs on modern UNIX operating systems with the the
[OpenSSL](https://www.openssl.org) external library installed, version
1.1 and above.
See [Portability](#portability) for details.
The reference operating system is [OpenBSD](https://www.openbsd.org),
which we strongly suggest for all installations for security reasons.
It will support [LibreSSL](https://www.libressl.org/) once the library
gains CMS parsing.

See the [TODO](TODO.md) file for open questions regarding RPKI operation
in general.

## Project background

**rpki-client** is written as part of the
[rpki-client(8)](https://medium.com/@jobsnijders/a-proposal-for-a-new-rpki-validator-openbsd-rpki-client-1-15b74e7a3f65)
project, an
[RPKI](https://en.wikipedia.org/wiki/Resource_Public_Key_Infrastructure)
validator for OpenBSD. 
It was funded by [NetNod](https://www.netnod.se),
[IIS.SE](https://www.iis.se), [SUNET](https://www.sunet.se) and
[6connect](https://www.6connect.com).

# Installation

First, you'll need a recent [OpenSSL](https://www.openssl.org/) library
(version 1.1 and above) on your operating system.
At this point, just run the following.
The installation rule will install into `PREFIX`, defaulting to
*/usr/local*.

```
% ./configure
% make
# make install
```

It may be necessary to pass `pkg-config` values for OpenSSL to the
configure script.

```
% ./configure CPPFLAGS="`pkg-config --cflags openssl`" \
> LDFLAGS="`pkg-config --libs-only-L openssl`" \
> LDADD="`pkg-config --libs-only-l openssl`"
```

On OpenBSD, the package is `eopenssl11`, but using `pkg-config` for this
will produce the wrong values for OpenBSD 6.6 and before.  You'll need
to hardcode the values yourself.

Most Linux systems additionally need `-lresolv` for `LDADD`.
Contrarily, FreeBSD only needs `LDADD="-lssl -lcrypto"` as the required
libraries are in the base system.

If you're packaging the software, these may be put directly into a
*configure.local* script, which overrides the variables during
configuration, for example:

```
CPPFLAGS="`pkg-config --cflags openssl`"
LDFLAGS="`pkg-config --libs-only-L openssl`"
LDADD="`pkg-config --libs-only-l openssl`"
```

Next, you'll need the */var/cache/rpki-client* directory in place.
It must be writable by the operator of **rpki-client**.  The default
output directory is */var/db/rpki-client*, which must also be writable
(if not overriden).

You'll also need TAL ("trust anchor locator") files.
There are some in the [tals](tals) directory of this system, but you can
download them on your own.
For default operation, load these into */etc/rpki*.

You'll also need [openrsync(1)](https://man.openbsd.org/openrsync.1) or
[rsync](https://rsync.samba.org/) as specified with the **-e** argument.
To hardcode an alternate rsync implementation, override the `RSYNC`
variable in the
[Makefile](https://github.com/kristapsdz/rpki-client/blob/master/Makefile).

In the following, the first uses a custom TAL file, while the second
loads all TAL files from their default location.  Output for the first
is written into *./openbgpd* and */var/db/rpki-client/openbgpd* for the
second.

```
% ./rpki-client -v -t sometal.tal .
% ./rpki-client -v
```

If you later want to uninstall the system, simply run

```
# make uninstall
```

If the manpages in the install root have already been indexed, you may
need to re-run [makewhatis(8)](https://man.openbsd.org/makewhatis.8) to
purge the system's manpage.

# Architecture

The **rpki-client** run-time is split into at least three processes
which pass data back and forth.
"At least" since the system will dynamically spawn additional process in
addition to the three core processes.
Most of the architecture is implemented in [main.c](main.c).

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
lists (CRL), and Route Origin Authorizations (ROAs).
If any of these files sits in a repository not yet fetched, that
repository is fetched or refreshed.
When the repository is fetched, those pending entries are flushed into
the parser.

The master process also outputs valid routes.  At this time, it does so
in [bgpd.conf(5)](https://man.openbsd.org/bgpd.conf.5),
[BIRD](https://bird.network.cz), RIPE NCC RPKI JSON, or CSV formats.

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

Most of the certificate validation in RPKI comes from the `X509_STORE`
functionality of OpenSSL.  This covers CRL revocation, expiration dates,
and so on.

## TAL validation

It begins by parsing a TAL file, [RFC
7730](https://tools.ietf.org/html/rfc7730), which specifies a trust
anchor certificate address and its public key.
The parsing and validation of the TAL file occurs in [tal.c](tal.c).

*Side note*: the TAL file may technically specify multiple top-level
certificates; but in the case of **rpki-client**, only the first is
processed.

## Trust anchor validation

A trust anchor is an X509 ([RFC
6487](https://tools.ietf.org/html/rfc6487) certificate given by the TAL
file.
Beyond the usual certificate parsing in [cert.c](cert.c), the trust
anchor files also have a number of additional constraints imposed in
[validate.c](validate.c):

- the certificate must be self-signed
- the public key must match the one given in the TAL file
- it must have an SKI (subject key identifier)
- the SKI must be unique in the set of all parsed certificates (trust
  anchors and otherwise)
- must not specify a CRL resource

Furthermore:

- it may only contain non-inheritance AS identifiers
- it may only contain non-inheritance IP blocks

Each trust anchor (inheriting from the X509 validation) contains a
reference to a manifest file that's used for further parsing.

## Manifest validation

Manifests ([RFC 6486](https://tools.ietf.org/html/rfc6487)) contain
links to more resources.
They are parsed in [mft.c](mft.c), with the CMS ([RFC
6488](https://tools.ietf.org/html/rfc6488)) envelope parsed in
[cms.c](cms.c), and additional checks implemented in
[validate.c](validate.c).

- self-signed CMS envelope
- CMS envelope self-signed certificate is signed by the AKI's
  certificate
- manifest time window has not expired

Manifests contain a list of files they manage that must be ROA, CRL, or
X509 (`roa`, `crl`, or `cer` suffixes, respectively).
Each file is associated with a hash.

Stale manifests---those whose validity period has elapsed---are
accepted (and noted), but will contain zero members.

## Route origin validation

ROA (route origin authorisation, [RFC
6482](https://tools.ietf.org/html/rfc6482)) files are stipulated in
manifests.
These are the focus of RPKI: those that pass validation are emitted as
valid routes.
ROA files consist of data wrapped in a CMS envelope.
They are parsed in [roa.c](roa.c), with the CMS ([RFC
6488](https://tools.ietf.org/html/rfc6488)) envelope parsed in
[cms.c](cms.c), and additional checks implemented in
[validate.c](validate.c).

- computed digest matches that given by the manifest
- self-signed CMS envelope
- CMS envelope self-signed certificate is signed by the AKI's
  certificate
- IP blocks must be within the ranges allocated by the *nearest*
  non-inheriting certificate in the chain to the trust anchor

An ROA may technically contain zero IP prefixes.
If this is the case, it is merely skipped.

A "stale" ROA (time validity has elapsed) is also ignored.

## Certificate validation

X509 certificates ([RFC 6487](https://tools.ietf.org/html/rfc6487) certificate
are the mainstay of RPKI's validation.
They are parsed in [cert.c](cert.c) with further validation being
performed in [validate.c](validate.c).

- computed digest matches that given by the manifest (if applicable)
- the certificate must be signed by the AKI's certificate
- the SKI must be unique in the set of all parsed certificates (trust
  anchors and otherwise)
- must specify a CRL resource
- AS identifiers/ranges must be within the ranges allocated by the
  nearest non-inheriting certificate in the chain to the trust anchor
  (see [TODO](TODO.md) for notes)
- IP blocks must be within the ranges allocated by the nearest
  non-inheriting certificate in the chain to the trust anchor

## Revocation list validation

**rpki-client** imposes no specific checks on CRL than those provided by
OpenSSL's `X509_STORE` functionality.

Some repositories, however, contain enormous CRL files with thousands
and thousands of entries.  These take quite some time to parse.

# Portability

The **rpki-client** is portable to the extent that it will compile and
run on most modern UNIX systems.
To date it is known to compile on GNU/Linux, FreeBSD, and OpenBSD.
It uses [oconfigure](https://github.com/kristapsdz/oconfigure) for its
compatibility layer.

However, the system depends heavily on OpenBSD's security mechanisms
(only enabled on OpenBSD installations) to safely and securely parse
untrusted content.
Those running on a non-OpenBSD operating system should be aware that
this additional protection is not available.

## Privilege dropping

If the `PRIVDROP` macro is defined in the
[Makefile](https://github.com/kristapsdz/rpki-client/blob/master/Makefile), it
is used as the username into which to privilege-drop.
On OpenBSD, this is *_rpki-client*.
Privilege dropping only occurs when running the utility as root.

If the `PRIVDROP` macro is not defined, no privilege dropping occurs.

## Pledge

**rpki-client** makes significant use of
[pledge(2)](https://man.openbsd.org/pledge.2) to constrain resources
available to the running process.
On FreeBSD, the same (or similar) may be effected by judicious use of
Capsicum.
On Linux, seccomp, although it's an unholy mess.

This function is used in [main.c](main.c).
On non-OpenBSD systems it is redefined to be empty in [extern.h](extern.h).

## Unveil

Once TAL files have been parsed (these may sit anywhere on the
file-system), the parsing process restricts file-system access to the
local repository directory with
[unveil(2)](https://man.openbsd.org/unveil.2).

It's not trivial to port this to FreeBSD or Linux.
First, calls to `BIO_new_file` would need to use `BIO_new_fp` with a
separate `fdopen` call.
This descriptor would need to be opened with `openat` and the input
paths stripped of their common prefix.
This way, calls directly to `open` could be filtered.

This function is used in [main.c](main.c).
On non-OpenBSD systems it is redefined to be empty in [extern.h](extern.h).
