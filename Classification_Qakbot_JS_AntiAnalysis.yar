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
