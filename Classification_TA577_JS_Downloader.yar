rule Classification_TA577_JS_Downloader : T1059_007 {
    meta:
        tlp = "amber"
        date = "2032-03-06"
        author = "Manny"
        description = "Detects the obfuscation of the JavaScript code seen downloading TA577 paylaoads. (Historically, these have led to Qakbot, Pikabot, RansomRight and DarkGate.)"
        scope = "detection"
        platform = "icet"
        references = "https://wiki.idr.nube.53.com/display/IDR/Qakbot"
        references = "https://github.info53.com/orgs/Fifth-Third/projects/10#card-21274"
        references = "fd82aabebd4b206d46ba0d6f3cbdcb9ea620086dba75851c03fd618a3c96b439"
        references = "https://github.com/pr0xylife/Qakbot/blob/main/Qakbot_BB18_06.03.2023.txt"
        references = "85d8a235314c371d4891baeb0d05116854dabda2aa562a93e51aa22914c2487f"
        references = "https://github.info53.com/orgs/Fifth-Third/projects/10#card-21356"
        references = "195b29e6cf73f2cf663b588df69eff43a1e7f27c1dbbd119cf816c99aa556fa1"
    strings:
        /*
        'yGTGD': function (i, j) {
                return i + j;
            },
            'BAKYy': function (i, j) {
                return i + j;
            },
            'DfTyr': function (i, j) {
                return i / j;
            },
            'Qvhwt': function (i, j) {
                return i(j);
            },
            'KznuE': function (i, j) {
                return i + j;
            },
            'nqlRe': function (i, j) {
                return i / j;
            },
        */
        $obf_val_is_def = /('|")[a-zA-Z]{3,10}('|"): function \(( )?[a-zA-Z]( )?,( )?[a-zA-Z]( )?\)/ ascii nocase


        /*
        var c = {
            'pHwwu': b(0xbd),
            'iCzKs': b(0xbe),
            'Kdadx': b(0xbf),
            'ZPohE': b(0xc0),
            'fOzxl': b(0xc1),
            'seTkP': b(0xc2),
            'MTaNW': b(0xc3),
            'HiBqi': b(0xc4),
            'ZrpwC': b(0xc5),
            'rVTva': b(0xc6),
            'KDIRJ': b(0xc7),
            'XbkNY': b(0xc8),
            'EOrfG': b(0xc9),
            'CJMLE': b(0xca),
        */
        $obf_val_is_call = /('|")[a-zA-Z]{3,10}('|"): [a-zA-Z]\(.{2,10}\),\s/ ascii nocase


        /*
        f = _0x41a5, g = {
            'FrWzq': function (i, j) {
                return e[b(0x3a7)](i, j);
            },
            'OOdcB': function (i, j) {
                return e[b(0x3a8)](i, j);
            },
            'XSLED': function (i, j) {
                return e[b(0x3a8)](i, j);
            },
            'EHjwC': function (i, j) {
                return e[b(0x3a9)](i, j);
            },
            'wJpPG': function (i) {
                return e[b(0x3aa)](i);
            },
            'mVnGc': function (i, j, k) {
                return e[b(0x3ab)](i, j, k);
            }
        */
        $obf_ret_elem = /return [a-zA-Z]\[[a-zA-Z]\(0x[a-zA-Z0-9]{2,5}\)\]/ ascii nocase


        /*
            baalite(0x52e, 0x7b6, 0x601, 0x5e6, '0x62e')
            crankumbellicism(0x7ed, 0x7a4, 0x4d2, 'E2IL', '0x6f4')
            spleneticalempestic(0x5d1, 0x620, 0x576, '0x5ef', '0x61b')
            shirtiness(0x483, 0x52d, 0x409, '0x46b', '0x4f2')

            There are some variants where the element is actually a string. But there are a plethora of strings that use the actual hex values, so I think this regex string is good.
            (I dont want to account for the hex values stored as strings to avoid costly regex.)
        */
        $obf_dumb_params = /\(0x[a-zA-Z0-9]{1,5},( )?0x[a-zA-Z0-9]{1,5},( )?0x[a-zA-Z0-9]{1,5}/ ascii nocase

        $anon_func = "(function"

        $obf_true = "!![]"

        $func_parseInt = "parseInt"
        $func_decodeURI = "decodeURIComponent"
        $func_fromCharCode = /('|")fromCharCode('|")/
        $func_charCodeAt = /('|")charCodeAt('|")/
        $func_toString = /('|")toString('|")/

        $sus_run = /('|")Run('|")/ ascii nocase
        $sus_slice = /('|")Slice('|")/ ascii nocase
        $sus_push = /('|")Push('|")/ ascii nocase
        $sus_split = /('|")Split('|")/ ascii nocase
        $sus_shift = /('|")Shift('|")/ ascii nocase

        $keyword_ActiveXObject = "ActiveXObject"
        $keyword_OneDrive = "OneDrive"
        $keyword_setTimeout = "setTimeout"

        $inserted_long_mal_js_line = /\nfunction [^\x0a]{4000,}/
        $split_rev_join = /split.{,8}\.reverse.{,8}\.join/

        $low_int_array = / = \[\s?([0-9]{1,4}, ){50,}/ wide ascii
        $low_is_str = /return\(typeof\([a-zA-Z_]{4,50}\) == "string"/ wide ascii
        $low_interleave_arrays = /var [A-Za-z_][A-Za-z_0-9]{2,50}\s{,4}=\s{,4}new\s{1,4}Function\s{,4}\(\s{,4}"[A-Za-z_][A-Za-z_0-9]{2,50}"\s{,4},\s{,4}[A-Za-z_][A-Za-z_0-9]{2,50}/ wide ascii
        $low_msxml = "msxml2.xmlhttp" wide ascii
        $low_WScript = /Wscript\s{,4}\.\s{,4}createobject/ nocase wide ascii
        $low_response = ".responseText" wide ascii


    condition:
        //@inserted_long_mal_js_line > 10000 or
        (#inserted_long_mal_js_line == 1 and @inserted_long_mal_js_line > 10000) or
        4 of ($low*) or
        $split_rev_join or
        $anon_func and (
            (
                //JS v1
                (3 of ($obf_*)) and (1 of ($keyword_*)) and (1 of ($sus_*))
            ) or (
                //JS v1
                (3 of ($obf_*)) and (4 of ($sus_*))
            ) or (
                //JS v1
                (2 of ($obf_*)) and (2 of ($keyword_*)) and (1 of ($sus_*))
            ) or (
                //JS v2
                (2 of ($obf_*)) and (3 of ($func_*)) and (2 of ($sus_*))
            )
        )
}
