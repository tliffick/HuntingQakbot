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
