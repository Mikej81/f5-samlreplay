# F5 ILX SAML-Replay
![diagram](https://imgur.com/EOXy4An)

## Requirements
BIG-IP 13.1.0.x

## Install
-Import workspace

-Create plugin (samlreplay_plugin)

-Attach TCL iRule to VS

-APM integration hasnt been completed yet.

## TODO
-APM Integration: ACCESS_ACL_ALLOWED {} // if MRHSession then ACCESS::session data set session.samlreplay.attributes.*

## Notes

SP-Initiated:  Will currently generate AuthNRequest on GET / if no MRHSession.  

HTTP-REDIRECT -- Binding currently seems good.  SigAlg and RelayState querystrings currently ignored.  SAMLResponse is pulled in and the signature is verified against a known public key for the issuer.

HTTP-POST -- Will currently parse incoming POST body and build a new (self-submitting) form, and will auto-post afer signatureverification.  (v0.1.0)
