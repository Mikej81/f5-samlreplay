# F5 ILX SAML-Replay

## Requirements
BIG-IP 13.1.0.x

## Install
-Import workspace

-Create plugin (saml_replay_plugin)

-Attach TCL iRule to VS

## TODO
-APM Integration: ACCESS_ACL_ALLOWED {}

## Notes

SP-Initiated:  Will currently generate AuthNRequest on GET / if no MRHSession.  

HTTP-REDIRECT Binding currently seems good.  SigAlg and RelayState querystrings currently ignored.  SAMLResponse is pulled in and the signature is verified against a known public key for the issuer.

HTTP-POST Binding needs some love.  Will currently parse incoming POST body and build a new (self-submitting) form, and will auto-post afer signatureverification.
