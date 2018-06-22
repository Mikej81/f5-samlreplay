#####################################################################################
#  SAMLReplay
#  Verify SAMLReponse Signature and Replay to SP
#  Michael Coleman, Michael@f5.com
#
#  HTTP-REDIRECT seems to be set.  Currently ignoring SigAlg and RelayState.
#
#  HTTP-POST seems to be almost there.  Using a 307 now instead of all the overhead.
#
####################################################################################
when RULE_INIT {
    set static::action_url "https://192.168.2.60/test.post"
}
when CLIENT_ACCEPTED {
    ## Create a HASH for the session table key for this user
    set client [IP::client_addr][TCP::remote_port][IP::local_addr][TCP::local_port]
    set client_hash [sha512 $client]
    set tableName $client_hash
    set keyName "Token"
}

when HTTP_REQUEST {
    ## Check if MRHSession Exists and/or replayStatus entry set
    set apm_cookie [HTTP::cookie exists MRHSession]
    set replaystatus [table lookup -subtable $tableName replayStatus]

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
                "*samlresponse*" { log local0. "samlresponse"
                    set encodedQuery "[URI::query [HTTP::uri] SAMLResponse]"
                    set decodedURI "[URI::decode [HTTP::uri] ]"
                    set currentHost [HTTP::host]
                    set samlResponse $encodedQuery

                    if { ($samlResponse ne "") } {
                        ## We make a table entry for the SAMLResponse so we can hold it
                        ## till after the MRHSession is established,
                        ## then we can replay it to the backend.
                        log local0. "SAMLResponse exists, creating table entry"
                        if { ([table keys -subtable $tableName -count] == 0) } {
                        set tblcreate [table set -subtable $tableName $keyName $samlResponse 30]
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
                        table set -subtable $tableName verified $signature_status 30
                        if { ($signature_status contains "Invalid") } {
                            # Invalid Signature
                            set html $signature_status
                            HTTP::respond 200 $html
                        }
                        if { ($signature_status contains "Not Signed") } {
                            # SAMLResponse not signed, what do?
                        }
              }
            }
                }
                default {
                ## If no SAMLRequest/SAMLResponse, MRHSession or POST:
                ## Generate AuthNRequest
                ## Config details for IDP and SP in index.js
                ## Currently only coded for 302 right now...
                    set callbackURI ""
                    log local0. "No MRHSession Cookie, no Querystring, generate AuthNRequest"
                    ## usage: saml-request [method] [callbackURI] [sign true/false]
                    set AuthNRequest [ILX::call $samlReplay_Handle saml-request [HTTP::method] [HTTP::host][HTTP::uri] false]
                    if { [lindex $AuthNRequest 0] eq "OK"} {
                        HTTP::redirect [lindex $AuthNRequest 1]
                    }
                }
            }

        }
        POST {
            ## HTTP-POST BINDING
            ## We only need to collect here, then process
            ## under HTTP_REQUEST_DATA.
            if { ($replaystatus eq "0")} {
                log local0. "len = [HTTP::header Content-Length]"
                log local0. "req = [HTTP::request]"
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

    ## Get MRHSession yes/no
    set apm_cookie [HTTP::cookie exists MRHSession]
    set replaystatus [table lookup -subtable $tableName replayStatus]

    set postReplay_Handle [ILX::init samlreplay_plugin samlreplay_ext]

    log local0. "APM: $apm_cookie, Replay: $replaystatus"

    set SAMLResponse ""

    foreach x [split [HTTP::payload] &] {
        set name [string tolower [URI::decode [getfield $x = 1]]]

        if {$name starts_with "samlresponse="} {
            append SAMLResponse [lindex [split $x "="] 1]
            ## log local0. "SAMLResponse:  $SAMLResponse"
            }
    }
## this is not used, but if we wanted to add/modify content, it would be done here
#    set content "<HTML><HEAD>< script type=text/javascript language=javascript> \
#        function s(){ document.f.submit(); } </script></HEAD><BODY onload=s(); > \
#        <FORM name=f action='$static::ext_url' method=post>"
#
#    foreach p [split [HTTP::payload] &] {
#        set name  [URI::decode [getfield $p = 1]]
#        set value [URI::decode [getfield $p = 2]]
#        set content "${content}<INPUT type=hidden name='$name' value='$value'>"
#    }
#    set content "${content}<INPUT type=submit value=Send></FORM></BODY></HTML>"
#
#    HTTP::respond 200 content $content
## end example
    set saml_verify [ILX::call $postReplay_Handle saml-validate $SAMLResponse true]
    set signature_status [lindex $saml_verify 0]
    set attributes [lindex $saml_verify 1]

    table set -subtable $tableName verified $signature_status 30
    table set -subtable $tableName attributes $attributes 30
    table set -subtable $tableName samlResponse $SAMLResponse 30
    table set -subtable $tableName relayState $relayState 30
    table set -subtable $tableName replayStatus 0 30

    if {(($apm_cookie == 0) && ($replaystatus eq "0"))} {
        table set -subtable $tableName replayStatus 1 30
        HTTP::respond 307 $static::action_url
    }
}

#when HTTP_RESPONSE {
    ## Get samlresponse/relaystate/replaystatus from session table
#    set samlresponse [table lookup -subtable $tableName samlResponse]
#    set relaystate [table lookup -subtable $tableName relayState]
#    set replaystatus [table lookup -subtable $tableName replayStatus]
    ## Get MRHSession yes/no
#    set apm_cookie [HTTP::cookie exists MRHSession]

#    log local0. "APM: $apm_cookie, Replay: $replaystatus"

#    if {(($apm_cookie == 0) && ($replaystatus eq "0"))} {
#    table set -subtable $tableName replayStatus 1 30
#    set post_header "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">"
#    append post_header "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\"><body>"
#    append post_header "<script type='text/javascript'>window.onload=function(){ window.setTimeout(document.SAMLReplay.submit.bind(document.SAMLReplay), 500);};</script>"
#    append post_header "<noscript><p><strong>Note:</strong> Since your browser does not support JavaScript,you must press the Continue button once to proceed.</p></noscript>"

#    set post_footer "<noscript><input type=\"submit\" value=\"Continue\"/></noscript></form></body></html>"

#    set post_form "<form name=\"SAMLReplay\" action=\"$static::action_url\" method=\"post\"><input type=\"hidden\" name=\"RelayState\" value=\"$relayState\"/>"
#    append post_form "<input type=\"hidden\" name=\"SAMLRequest\" value=\"$SAMLResponse\"/>"
#    set content $post_header$post_form$post_footer
#    HTTP::respond 200 $content
#    }
#}
#
## APM Integration
## for 302
## when ACCESS_ACL_ALLOWED {
##   ACCESS::respond 302 "Location" sessiontable entry
## }
## For POST HTTP_RESPONSE should work as well...  If MRHSession.
