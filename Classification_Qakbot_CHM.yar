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
