# Introduction

**This software is still not entirely functional.  Please do not use it
unless doing so for specific testing.  Thank you!  If you'd like to
participate in development or testing, please contact the author.**

**rpki-client** is an implementation of RPKI (resource public key
infrastructure) described in [RFC
6480](https://tools.ietf.org/html/rfc6480).
It implements the *client* side of RPKI, which is responsible for
downloading and validating route origin statements.
For usage, please read [rpki-client(1)](rpki-client.1).

The design focus of **rpki-client** is simplicity and security.
To wit, it implements RPKI components necessary for validating route
statements and omits superfluities (such as, for example, which X509
certificate sections must be labelled "Critical").

The system runs on current [OpenBSD](https://www.openbsd.org)
installations with the the [OpenSSL](https://www.openssl.org) external
library installed.
See [Portability](#portability) for instructions on how to port the
software.
Non-current OpenBSD installations, or older versions, will need
specification of an alternate **rsync** utility with the **-e** flag.

At this time, **rpki-client** does not work with OpenBSD's native
[libressl](https://www.libressl.org) due to requiring CMS parsing.
According to 
[this thread](http://openbsd-archive.7691.n7.nabble.com/LibreSSL-why-is-support-for-CMS-disabled-td253212.html),
this omission from libressl is not for security purposes, but
happenstance.

See the [TODO](TODO.md) file for open questions regarding RPKI operation
in general.

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

If you're running on an i386 system, you'll also need to uncomment the
line adding `UNSAFE_i386` as a compile-time CPP flag.
This is a yet-unexplained quirk of OpenSSL on i386.
For the time being, I recommend only using i386 as a testing system for
this reason---the compile-time flag loosens parsing restrictions.

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
- AS identifier must be within the range allocated by *any* certificate
  in the chain to the trust anchor (see [TODO](TODO.md) for notes)
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
and thousands of entries.
Since these take quite some time to parse, the **-r** flag disables CRL
checking.

# Portability

For the most part, **rpki-client** is trivially portable to any system
supporting OpenSSL or libressl.
However, the system depends heavily on OpenBSD's security mechanisms to
safely and securely parse untrusted content.
A port of the system without equivalent security measures is not
complete and should not be trusted.
