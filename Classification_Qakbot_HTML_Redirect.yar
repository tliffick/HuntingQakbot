rule Classification_Qakbot_HTML_Redirect: Mitre_T1204_001 T1566_002  
{
    meta:
        tlp = "green"
        author = "Jeremy Humble"
        date = "2022-09-28"
        description = "Qakbot"
        hashes = "8424274429dd76ad4ecc88885bb96ae9,c599c4a0c436b5c55acba4cd9196c6cb"
        scope = "detection"
        platform = "ICET"

    strings:
        /* Phishing links go to an html page with the following content: and a redirect to a zip download:
            <span id="DJtK" data-DJtK="/ue/G873885943.zip
            <span id="lAiLyQ" data-lAiLyQ="/eprl/G2180864135.zip
        */
        $high_redirect = /<span id="[a-zA-Z]{3,}" data-[a-zA-Z]{3,}="\/[a-zA-Z]{3,}\/[a-zA-Z0-9_]{4,}\.zip/ 

        $high_decrypt_embedded_zip = /String\.fromCharCode\([a-zA-Z][+-][0-9]{1,3}\)/
             
        $high_var0 = "abc123qqq"
        $high_var1 = "bebe7755qq"
        $high_var2 = "encoded_payload"

        $high_msg0 = "The file is not displayed correctly" nocase
        $high_msg1 = "Use local downloaded file" nocase
        $low_msg2 = ">Document password:" nocase

        $high_obf0 = "&#102;ile" nocase
        $high_obf1 = "f&#105le" nocase
        $high_obf2 = "fi&#108e" nocase
        $high_obf3 = "fil&#101" nocase

        $high_obf4 = "&#80;assword"

        // script is embedded in base64 form inside an svg
        $low_base64_javascript = "<script type=\"text/javascript\">" base64 base64wide
        $high_base64_attachment = "attachment.zip" base64 base64wide
        $high_base64_blob = "b64toBlob" base64 base64wide

    condition:
        any of ($high*) or
        2 of ($low*)
}