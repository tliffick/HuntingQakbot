rule HTML_Payload_Smuggling: Phishing T1027_006
{
    meta:
        tlp = "amber"
        author = "emaiwald"
        date = "2022-09-29"
        scope = "detection"
        platform = "icet"
        full_path = "sub:crawlphish"
        description = "Fires on links possibly showing techinques of payload smuggling.."

    strings:
        $s01 = "data:image" nocase
        $s02 = "base64" nocase
        $s11 = "body onload" nocase
        $s12 = "document.body.appendChild" nocase
        $a1 = "window.atob" nocase
        $a2 = "charCodeAt" nocase
        $a3 = /<script type="text\/javascript">/ nocase
        $a4 = /window\.addEventListener\("mousemove"/ nocase
        $a5 = "MimeTypeArray.prototype" nocase
        $b1 = /\.reverse\(.{0,40}\)\.join/ nocase //condition b added as qakbot began reversing the base64 encoded string
        $c1 = /\<div.{,10}id\=\"image.{,50}\".{,50}style\=\"display\:none\;\"\>.{,20}\=\=/
        $d1 = /<div id\=\".{1,20}\"\>\=\=/ nocase

    condition:
          all of ($s0*) and any of ($s1*) and (all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*))
}
