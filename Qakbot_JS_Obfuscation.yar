rule Technique_JS_Obfuscation: T1059_007 T1140
{
    meta:
        tlp = "green"
        date = "2023-03-13"
        author = "@imp0rtp3, Jeremy Humble"
        description = "Detect JS obfuscation done by the js obfuscator (often malicious). Observed being used to obfuscate Griffon Aug 2021. See Classification_Fin7_Griffon_Packed for a more specific version intended to collect those. Also used by Qakbot Feb-March 2023"
        reference = "https://obfuscator.io"
        hashes = "01982695fb63ba197891932b1b06219a,706b9cff3e402fc436dc73989b3d325b,4f1e24394449a16b39e3ca7e4de56e2e"
        platform = "icet,FDR"
        fdr_scope = "script"

    strings:

        // Begining of the script
        $a1 = "var a0_0x" wide ascii
        $a2 = /var _0x[a-f0-9]{4}/ wide ascii
        $a3 = "function a0_0x" wide ascii
        $a4 = /function _0x[a-f0-9A-F]{4}/ wide ascii

        // Strings to search By number of occurences
        $b1 = /a0_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)/ wide ascii
        $b2 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)[^\w\d]/ wide ascii
        $b3 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\['push'\]\(_0x([a-f0-9]{2}){2,4}\['shift'\]\(\)[^\w\d]/ wide ascii
        $b4 = /!0x1[^\d\w]/ wide ascii
        $b5 = /[^\w\d]function\((_0x([a-f0-9]{2}){2,4},)+_0x([a-f0-9]{2}){2,4}\)\s?\{/ wide ascii
        $b6 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\s?=\s?_0x([a-f0-9]{2}){2,4}[^\w\d]/ wide ascii

        // generic strings often used by the obfuscator
        $c1 = "))),function(){try{var _0x" wide ascii
        $c2 = "=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(\\x20)'+');');" wide ascii
        $c3 = "['atob']=function(" wide ascii
        $c4 = ")['replace'](/=+$/,'');var" wide ascii
        $c5 = "return!![]" wide ascii
        $c6 = "'{}.constructor(\\x22return\\\x20this\\x22)(\\x20)'" wide ascii
        $c7 = "{}.constructor(\x22return\x20this\x22)(\x20)" base64 wide ascii
        $c8 = "while(!![])" wide ascii
        $c9 = "while (!![])" wide ascii
        // (0x165b)+'S04gPSAxNzYxOw0KD'+eaduptsidneare(0xd4c)
        $c10 = /(\(0x[0-9a-f]{2,}.{,32}){3,}/ nocase wide ascii

        // Strong strings
        $d1 = /(parseInt\(_0x([a-f0-9]{2}){2,4}\(0x[a-f0-9]{1,5}\)\)\/0x[a-f0-9]{1,2}\)?(\+|\*\()\-?){6}/ wide ascii
        // (0x165b)+'S04gPSAxNzYxOw0KD'+eaduptsidneare(0xd4c)
        $d2 = /(\(0x[0-9a-f]{2,}.{,32}){5,}/ nocase wide ascii
        // var est=document[a0anadmmseg(0x133)](a0anadmmseg(0x129));est[a0anadmmseg(0x124)]='https://spoar.org'+a0anadmmseg(0x126)+'768',document[a0anadmmseg(0x131)][a0anadmmseg(0x12f)](est)
        $d3 = /document\s{,16}\[\s{,16}a0.{,24}\s{,16}\(\s{,16}a0/ nocase wide ascii
        $d4 = /document\s{,16}.{,32}0x[0-9a-f]{2,}.{,128}document\s{,16}.{,32}0x[0-9a-f]{2,}/ nocase wide ascii

        // FPs
        $fp_1 = /LinkedIn','\(+\.(\+\))+\+\$/ wide ascii

    condition:
        not any of ($fp*) and
        (
        $a1 at 0 or
        $a2 at 0 or
            $a3 at 0 or
            $a4 at 0 or
        (
            filesize < 10MB and
            (
                (#b1 + #b2) > (filesize \ 200) or
                #b3 > 1 or
                #b4 > 10 or
                #b5 > (filesize \ 2000) or
                #b6 > (filesize \ 200) or
                3 of ($c*) or
                any of ($d*)
            )
        ))
}
