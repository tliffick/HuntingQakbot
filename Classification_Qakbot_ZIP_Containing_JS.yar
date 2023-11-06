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