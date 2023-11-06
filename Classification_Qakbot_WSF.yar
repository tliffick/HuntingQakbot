rule Classification_Qakbot_WSF: T1059_007
{
    meta:
        tlp = "amber"
        date = "2032-04-28"
        author = "Jeremy Humble"
        Description = "Detects WSF loader that Qakbot has been using early 2023"
        scope = "detection"
        platform = "icet"
        hashes = "9e37c7701907a6541ca62e9985a974b5"

    strings:
        $sleep0 = /var\s{1,8}[a-zA-Z_][a-zA-Z0-9_]{1,24}\s{,8}=\s{,8}new\s{1,8}Date\s{,8}\(\s{,8}\)/
        $sleep1 = /[^a-zA-Z0-9_][a-zA-Z_][a-zA-Z0-9_]{1,24}\s{,8}=\s{,8}new\s{1,8}Date\s{,8}\(\s{,8}\)/
        $sleep2 = /[^a-zA-Z0-9_][a-zA-Z_][a-zA-Z0-9_]{1,24} - [a-zA-Z_][a-zA-Z0-9_]{1,24} < [a-zA-Z_][a-zA-Z0-9_]{1,24}/

        $cluster0_000 = "\r\n</script>\r\n<script language=\"javascript\">\r\n" ascii // 100.0%"
        $cluster0_001 = "\r\n</script>\r\n<script language=\"vbscript\">\r\n" ascii // 100.0%"
        $cluster0_002 = " -->\r\n<script language=\"javascript\">\r\n" ascii // 100.0%"
        $cluster0_003 = "\r\n</script>\r\n</job>\r\n</package>\r\n" ascii // 100.0%"
        $cluster0_004 = "\r\n<package>\r\n<job id=\"a" ascii // 100.0%"
        $cluster0_005 = ".toUpperCase();\r\nvar au" ascii // 100.0%"
        $cluster0_006 = ".toLowerCase();\r\nvar a" ascii // 100.0%"
        $cluster0_007 = ".toUpperCase();\r\nvar a" ascii // 100.0%"
        $cluster0_008 = " = true;\r\n\r\n\r\n\r\nvar a" ascii // 100.0%"
        $cluster0_009 = ".toLowerCase();\r\n\r\n\r\n" ascii // 100.0%"
        $cluster0_010 = " = new Date();\r\nvar " ascii // 100.0%"
        $cluster0_011 = ".toString();\r\nvar a" ascii // 100.0%"
        $cluster0_012 = ".toString();\r\n\r\n\r\n\r\n" ascii // 100.0%"
        $cluster0_013 = ".toString();\r\nvar a" ascii // 100.0%"
        $cluster0_014 = ".toLowerCase();\r\na" ascii // 100.0%"
        $cluster0_015 = ".toUpperCase();\r\na" ascii // 100.0%"
        $cluster0_016 = ".length;\r\n\r\n\r\n\r\n\r\n" ascii // 100.0%"
        $cluster0_017 = " = false;\r\nvar a" ascii // 100.0%"

        $cluster1_000 = " = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';\r\n                var " ascii // 100.0%"
        $cluster1_001 = "));\r\n                }\r\n                return decodeURIComponent(" ascii // 100.0%"
        $cluster1_002 = "\r\n    while (!![]) {\r\n        try {\r\n            var " ascii // 100.0%"
        $cluster1_003 = "['shift']());\r\n            }\r\n        } catch (" ascii // 100.0%"
        $cluster1_004 = "\">\r\n\t<script language=\"jscript\">\r\n        " ascii // 100.0%"
        $cluster1_005 = "'] === undefined) {\r\n            var " ascii // 100.0%"
        $cluster1_006 = "['shift']());\r\n        }\r\n    }\r\n}(" ascii // 100.0%"
        $cluster1_007 = "'] = !![];\r\n        }\r\n        var " ascii // 100.0%"
        $cluster1_008 = " = function () {\r\n        return " ascii // 100.0%"
        $cluster1_009 = "'] === undefined) {\r\n            " ascii // 100.0%"
        $cluster1_010 = ");\r\n        }\r\n        function " ascii // 100.0%"
        $cluster1_011 = " function () {\r\n        return " ascii // 100.0%"
        $cluster1_012 = " = arguments;\r\n            " ascii // 100.0%"
        $cluster1_013 = " += String['fromCharCode'](" ascii // 100.0%"
        $cluster1_014 = "ing) {\r\n            return " ascii // 100.0%"
        $cluster1_015 = "ly) {\r\n            return " ascii // 100.0%"
        $cluster1_016 = "': function () {\r\n        " ascii // 100.0%"
        $cluster1_017 = " = {};\r\n        function " ascii // 100.0%"
        $cluster1_018 = ");\r\n    }\r\n    function " ascii // 100.0%"
        $cluster1_019 = "['shift']());\r\n        " ascii // 100.0%"
        $cluster1_020 = " = function () {\r\n};\r\n" ascii // 100.0%"
        
    condition:
        for any i in (0..#sleep1):
        (
            $sleep0 in (@sleep1[i]-120..@sleep1[i]-8) and
            $sleep2 in (@sleep1[i]+8..@sleep1[i]+120)
        ) or
        8 of ($cluster0*) or
        8 of ($cluster1*)

}