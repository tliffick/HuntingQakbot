import "pe"

rule Classification_Qakbot: T1055
{
    meta:
        tlp = "green"
        author = "Jeremy Humble"
        date = "2021-10-22"
        description = "Qakbot"
        references = ""
        hashes = "98140e5672de3f7c9239b112d0a2bf63"
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
