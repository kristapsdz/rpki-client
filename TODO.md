
The following are unclear to me.

- When validating an ROA's asID (RFC 6482, section 3.2), it's not clear
  how to handle the hierarchy of issuer asID numbers.  RFC 6482 says
  nothing at all, and RFC 6487 section 4.8.11 simply says that AS
  numbers must be encompassed.

  What's not clear to me is whether the asID must be encompassed by the
  terminal (issuing) certificate, or by any certificate along the chain.

  For example, let's take a chain of three certificates: trust anchor,
  intermediate, terminal.  The terminal specifies AS number 4, the
  intermediate specifies none at all, the trust anchor specifies 1--4.
  If an ROA issued by the terminal has AS number 3, it makes sense that
  this would not be valid since the terminal issuer has "narrowed" the
  scope of available identifiers.  However, in practise, this happens
  all the time.

  This is currently implemented in [validate.c](validate.c),
  `x509_auth_as()`.

- Following up on validating AS numbers for certificates or ROAs.  The
  specification is not clear on what happens with empty AS extensions in
  a chain of certificates.  Do we consider that inheritence?  If so,
  what's the point of having an inheritence clause?

- I get that ASid 0 has special meaning for ROAs (see RFC 6483 sec 4),
  but it doesn't make sense that some top-level certificates (e.g.,
  Afrinic) have a range inclusive of zero, since it's reserved.  In this
  system, I let the range through but don't let a specific ASid of 0 in
  certificates---only ROAs.
