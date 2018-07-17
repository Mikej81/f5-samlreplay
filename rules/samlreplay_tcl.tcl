################################################################################
#  SAMLReplay
#  Verify SAMLReponse Signature and Replay to SP
#  Michael Coleman, Michael@f5.com
#  https://github.com/Mikej81/f5-samlreplay
#
#  HTTP-REDIRECT seems to be set.  Currently ignoring SigAlg and RelayState.
#
#  HTTP-POST seems to be almost there.  Using a 307 now instead of all the 
#  overhead.
#
#  Signature Status: 0 = Good, 1 = Error, 2 = Not Signed / undefined
#
#  Setup:
#  -Create Datagroup (type:string)
#  -Add config item for app/cookie: name:host_cookie,value:cookiename, 
#    i.e., domain.com:=sessioncookie
#  -Add config item for app/ssourl: name:host_ssourl,value:https://domain.com/
#    i.e., domain.com:=https://domain.com/sso
#    static::ssoURL is for fallback
#  -Import IDP Public Key to cert.pem and ensure index.js:signaturePubKey points
#   to that file.
#
####################################################################################
when RULE_INIT {
    set static::genAuthNRequest "0"
    set static::configDG "samlreplayconfig"
    set static::defaultRedir "https://domain.com/?"
    set static::keyName "replayToken"
    set static::MRH "MRHSession"
}

when CLIENT_ACCEPTED {
    ## Create a HASH for the session table key for this user
    set client [IP::client_addr][TCP::remote_port][IP::local_addr][TCP::local_port]
    set client_hash [sha512 $client]
    set tableName $client_hash
}

when HTTP_REQUEST {
    ## Dynamic Config via Datagroup
    #  Cookie Name
    if { [class match "[string tolower [HTTP::host]]_cookie" eq $static::configDG ] } {
     set appCookie [class match -value "[string tolower [HTTP::host]]_cookie" eq $static::configDG]
     #log local0. "$appCookie"
    } else {
     set appCookie "MRHSession"
    }
    # SSO Redirect URL
    if { [class match "[string tolower [HTTP::host]]_ssourl" eq $static::configDG ] } {
     set ssoURL [class match -value "[string tolower [HTTP::host]]_ssourl" eq $static::configDG]
     #log local0. "$ssoURL"
    } else {
     set ssoURL $static::defaultRedir
    }    

    ## Check if MRHSession Exists and/or replayStatus entry set
    set apm_cookie [HTTP::cookie exists $static::MRH]

    ## Create RPC Handler, Plugin name needs to match the plugin below.
    ## ILX::init <PLUGIN NAME> <EXTENSION NAME>
    set samlReplay_Handle [ILX::init samlreplay_plugin samlreplay_ext]

    if {$apm_cookie == 0} {
    ## Start Switch METHOD
    ## GET:     HTTP-REDIRECT BINDGING
    ## POST:    HTTP-POST BINDING
    switch [HTTP::method] {
        GET {
            ## Start Switch QueryString
            ## SAMLResponse:    Incoming SAMLResponse, currently ignoring RelayState and SigAlg
            ## default(/):               Incoming NULL session, SP-Initiate AuthNRequest
            switch -glob [string tolower [URI::query [HTTP::uri]]] {
                "*samlresponse*" {
                    #log local0. "samlresponse"
                    set encodedQuery "[URI::query [HTTP::uri] SAMLResponse]"
                    set decodedURI "[URI::decode [HTTP::uri] ]"
                    set currentHost [HTTP::host]
                    set samlResponse $encodedQuery

                    if { ($samlResponse ne "") } {
                        ## We make a table entry for the SAMLResponse so we can hold it
                        ## till after the MRHSession is established,
                        ## then we can replay it to the backend.

                        set saml_verify [ILX::call $samlReplay_Handle saml-validate $encodedQuery true]
                        ## log local0. "status: $saml_verify"
                        
                        set signature_status [lindex $saml_verify 0]
                        set attributes [lindex $saml_verify 1]
                        
                        ##  If attributes are returned they are in JSON
                        ##  FindStr should work, or split, not sure most
                        ##  efficient method yet...
                        ##  If APM integrating, these should be inserted into a table
                        ##  Then start the access session and insert into
                        ##  ACCESS::session data set session.x.x.x...
                        ##  Unsure which ID value to use so wont hard code this now
                        
                        if { ($signature_status eq "1") } {
                            # Invalid Signature
                            set html $signature_status
                            HTTP::respond 200 $html
                        }
            }
                }
                default {
                ## If no SAMLRequest/SAMLResponse, MRHSession or POST:
                ## Generate AuthNRequest
                ## Config details for IDP and SP in index.js
                ## Currently only coded for 302 right now...
                    set callbackURI ""
                    ## usage: saml-request [method] [callbackURI] [sign true/false]
                    if { $static::genAuthNRequest eq "1" } {
                        log local0. "Generate AuthNRequest"
                        set AuthNRequest [ILX::call $samlReplay_Handle saml-request [HTTP::method] [HTTP::host][HTTP::uri] false]
                        if { [lindex $AuthNRequest 0] eq "OK"} {
                            HTTP::redirect [lindex $AuthNRequest 1]
                        }
                    }
                    if { !([HTTP::cookie exists $static::appCookie]) } {
                      ##AppCookie does not exist
                      HTTP::redirect $ssoURL
                    }
                }
            }

        }
        POST {
            ## HTTP-POST BINDING
            ## We only need to collect here, then process
            ## under HTTP_REQUEST_DATA.
            log local0. "POST: Replay $replaystatus"
            if { ($replaystatus eq "") || ($replaystatus eq "0")} {
                HTTP::collect [HTTP::header Content-Length]
            }
        }
    }
    ##End Switch METHOD
    #
    }
}
when HTTP_REQUEST_DATA {
    ## Process the POST Data here.

    set postReplay_Handle [ILX::init samlreplay_plugin samlreplay_ext]

    set SAMLResponse ""
    set relayState ""

    #  You may need to change samlresponse to SAMLResponse here
    #  my test environment used lower.  I could do a string tolower on the payload
    #  but that screws up the encoding.

    foreach x [split [HTTP::payload] &] {
        if {$x starts_with "samlresponse="} {
            append SAMLResponse [lindex [split $x "="] 1]
            }
        if {$x starts_with "relaystate="} {
            append relayState [lindex [split $x "="] 1]
        }
    }

    set saml_verify [ILX::call $postReplay_Handle saml-validate $SAMLResponse true]
    set signature_status [lindex $saml_verify 0]
    set attributes [lindex $saml_verify 1]

    log local0. "Signature Status:  $signature_status"

    if { $signature_status eq "1" } {
        reject
    }
}


