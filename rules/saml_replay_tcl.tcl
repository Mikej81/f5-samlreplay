#  SAMLReplay
#  Verify SAMLReponse Signature and Replay to SP
#  Michael Coleman, Michael@f5.com

when HTTP_REQUEST {
    set client [IP::client_addr][TCP::remote_port][IP::local_addr][TCP::local_port]
    set client_hash [sha512 $client]
    set tableName $client_hash
    set keyName "Token"
    
    set samlReplay_Handle [ILX::init saml_replay_plugin saml_replay_ext]

    switch [HTTP::method] {
        GET {
            set encodedQuery "[URI::query [HTTP::uri] SAMLResponse]"
            set decodedURI "[URI::decode [HTTP::uri] ]"
            #set decodedQuery "[URI::query $decodedURI SAMLResponse]"
      
            #log local0. "encodedQ: $encodedQuery"
            #log local0. "decodedQ: $decodedQuery"
            #log local0. "decodedU: $decodedURI"
            
            set currentHost [HTTP::host]
            
            set samlResponse $encodedQuery
            
            if { ($samlResponse ne "") } {
                log local0. "SAMLResponse exists, creating table entry"
              if { ([table keys -subtable $tableName -count] == 0) } {
                set tblcreate [table set -subtable $tableName $keyName $samlResponse 30]              
                set saml_verify [ILX::call $samlReplay_Handle saml-validate $encodedQuery true]
                log local0. "status: $saml_verify"
                set signature_status [lindex $saml_verify 0]
                set attributes [lindex $saml_verify 1]
                set who_is_king [lindex $saml_verify 2]
                table set -subtable $tableName verified $signature_status 30
                if { ($signature_status == "1") } {
                    HTTP::respond 302 Location "https://$currentHost&SAMLResponse=$samlResponse"
                } elseif { $signature_status contains "Invalid" } {
                # Invalid Signature
                set html $signature_status
                HTTP::respond 200 $html
                }
              } else {
              # This whole else can be removed if there is a pool
              # this is just for testing
              if { ([table lookup -subtable $tableName verified] == "1" ) } {
                  log local0. "verified, on redirect"
                  HTTP::respond 200 "<HTML><BODY>YOU ARE GOOD!</BODY></HTML>"
                  } else {
                    log local0. "not verified"
                  }
              }
            } else {
                # Request was a GET, but no SAMLResponse so...
                log local0. "No"
                HTTP::respond 200 "No"
            }
        }
        POST {
            log local0. "len = [HTTP::header Content-Length]"
            log local0. "req = [HTTP::request]"
            # collect POST data
            HTTP::collect [HTTP::header Content-Length]
        }
    }
}
when HTTP_REQUEST_DATA {
    set samlReplay_Handle [ILX::init saml_replay_plugin saml_replay_ext]

    set POST_SAML_Response ""
    foreach x [split [string tolower [HTTP::payload]] "&"] {
        if {$x starts_with "samlresponse="} {
            set POST_SAML_Response [lindex [split $x "="] 1]
            set saml_verify [ILX::call $samlReplay_Handle saml-validate $encodedQuery true]
                log local0. "status: $saml_verify"
        }
    }
    

}

when CLIENT_CLOSED {
    #table delete -subtable
}



