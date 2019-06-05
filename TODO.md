
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

  This is currently implemented in [validate.c](validate.c), `valid_as()`.

- Following up on validating AS numbers for certificates or ROAs.  The
  specification is not clear on what happens with empty AS extensions in
  a chain of certificates.  Do we consider that inheritence?  If so,
  what's the point of having an inheritence clause?

- I get that ASid 0 has special meaning for ROAs (see RFC 6483 sec 4),
  but it doesn't make sense that some top-level certificates (e.g.,
  Afrinic) have a range inclusive of zero, since it's reserved.  In this
  system, I let the range through but don't let a specific ASid of 0 in
  certificates---only ROAs.

- Route duplication.  When run as-is, there are duplicate routes and
  that doesn't seem right.  It happens when two ROAs have their validity
  period overlap.  I need to see if there's a more programmatic way to
  check before commiting the routes to output.

- The validators should all be run in their own process: the syntax
  parser should not be performing the route validation.  This is a
  mechanical step, as all the logic to do so is in place.

- Using `X509_STORE` and validating using `X509_verify_cert` is overkill
  and costs us the most in performance because it effectively
  re-validates the entire chain.  Instead, apply the immediate parent as
  the "trusted" certificate once it has been validated.

- Stipulating `X509_V_FLAG_IGNORE_CRITICAL` might be dangerous.  Which
  extensions are being ignored should be double-checked.
