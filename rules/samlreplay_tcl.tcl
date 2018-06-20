#  SAMLReplay
#  Verify SAMLReponse Signature and Replay to SP
#  Michael Coleman, Michael@f5.com
#
#  HTTP-REDIRECT seems to be set.  Currently ignoring SigAlg and RelayState.
#
#  HTTP-POST needs some work.
#
################################################################################

when CLIENT_ACCEPTED {
    ## Create a HASH for the session table key for this user
    set client [IP::client_addr][TCP::remote_port][IP::local_addr][TCP::local_port]
    set client_hash [sha512 $client]
    set tableName $client_hash
    set keyName "Token"
}

when HTTP_REQUEST {
    ## Check if MRHSession Exists
    set apm_cookie [HTTP::cookie exists MRHSession]

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
            log local0. "len = [HTTP::header Content-Length]"
            log local0. "req = [HTTP::request]"
            HTTP::collect [HTTP::header Content-Length]
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
    foreach x [split [string tolower [HTTP::payload]] "&"] {
        if {$x starts_with "samlresponse="} {
            append SAMLResponse [lindex [split $x "="] 1]
        }
        if {$x starts_with "relaystate="} {
            append relayState [lindex [split $x "="] 1]
        }
    }
    set saml_verify [ILX::call $postReplay_Handle saml-validate $x true]
    set signature_status [lindex $saml_verify 0]
    set attributes [lindex $saml_verify 1]
    ## log local0. "status: $saml_verify"
    table set -subtable $tableName verified $signature_status 30
    table set -subtable $tableName attributes $attributes 30
    table set -subtable $tableName samlResponse $SAMLResponse 30
    table set -subtable $tableName relayState $relayState 30
    table set -subtable $tableName replayStatus 0 30
    
    ## Insert samlresponse/relaystate in session table to use on HTTP_RESPONSE
    ## Also add a bool for replaystatus so we no to replay or not
}

when HTTP_RESPONSE {
    ## Get samlresponse/relaystate/replaystatus from session table
    set samlresponse [table lookup -subtable $tableName samlResponse]
    set relaystate [table lookup -subtable $tableNmae relayState]
    set replaystatus [table lookup -subtable $tableName replayStatus]
    ## Get MRHSession yes/no
    set apm_cookie [HTTP::cookie exists MRHSession]
    
    ## Set Form Post Action
    set formAction "https://formposturl.domain.com/login"
    
    if {(($apm_cookie == 0) && ($replaystatus eq "0"))} {
    table set -subtable $tableName replayStatus 1 30
    set post_header "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">"
    append post_header "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\"><body>"
    append post_header "<script type='text/javascript'>window.onload=function(){ window.setTimeout(document.SAMLReplay.submit.bind(document.SAMLReplay), 500);};</script>"
    append post_header "<noscript><p><strong>Note:</strong> Since your browser does not support JavaScript,you must press the Continue button once to proceed.</p></noscript>"

    set post_footer "<noscript><input type=\"submit\" value=\"Continue\"/></noscript></form></body></html>"

    set post_form "<form name=\"SAMLReplay\" action=\"$formAction\" method=\"post\"><input type=\"hidden\" name=\"RelayState\" value=\"$relayState\"/>"
    append post_form "<input type=\"hidden\" name=\"SAMLRequest\" value=\"$SAMLResponse\"/>"
    set content $post_header$post_form$post_footer
    HTTP::respond 200 $content
    }
}
## APM Integration 
## for 302
## when ACCESS_ACL_ALLOWED {
##   ACCESS::respond 302 "Location" sessiontable entry
## }
## For POST HTTP_RESPONSE should work as well...  If MRHSession.

