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