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
