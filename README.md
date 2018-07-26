# F5 ILX SAML-Replay
![diagram](https://i.imgur.com/EOXy4An.png "Diagram")

## Requirements
BIG-IP 13.1.0.x

## Install
-Import workspace

-Create plugin (samlreplay_plugin)

-Attach TCL iRule to VS

-APM integration hasnt been completed yet.

-Datagroup creation for config items, details in TCL irule.

## TODO
-APM Integration: ACCESS_ACL_ALLOWED {} // if MRHSession then ACCESS::session data set session.samlreplay.attributes.*

## Notes

SP-Initiated:  Will currently generate AuthNRequest on GET / if no MRHSession.  

HTTP-REDIRECT -- Binding currently seems good.  SigAlg and RelayState querystrings ignored, extract whats needed directly from assertion.  SAMLResponse is pulled in and the signature is verified against a known public key for the issuer.  Then forwarded on to the application.

HTTP-POST -- May need to adjust camel case of SAMLReplay form-data, string tolower was causing me some greif, ill look into that eventually.  SAMLResponse is pulled in and the signature is verified against a known public key for the issuer.  Then forwarded on to the application.  Application Cookie is a configuration item in the datagroup as well, this tells the system which cookie to look for to ignore verification on follow-on requests.

APM MRH Session cookies can be used for this as well.
