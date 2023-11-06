rule JS_Atob_Function: Phish T1566 {
        meta:
        tlp = "amber"
        author = "Joe Wert"
        date = "2023-04-12"
        description = ""
        scope = "detection"
        platform = "icet"
        hashes = ""
        file_ext = "txt,html,js,htm"
        reference = "https://ice.info53.com/ace/events/analysis?direct=6822"

        strings:
        $s1 = "atob" ascii
        $s2 = /<html>/ nocase ascii
        $s3 = /<script>/ nocase ascii

        condition:
        all of them
}
