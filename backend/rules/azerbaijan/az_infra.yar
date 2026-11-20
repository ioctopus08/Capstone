rule AZ_Lookalike_Bank_Domain_Strings
{
    meta:
        description = "Strings resembling look-alike domains of major Azerbaijani bank/government infrastructure"
        severity = "high"
        tags = "az-context"
    strings:
        $gov1 = ".gov.az" ascii wide nocase
        $gov2 = "e-gov.az" ascii wide nocase
        $bank1 = "kapitalbank" ascii wide nocase
        $bank2 = "pashabank" ascii wide nocase
        $bank3 = "abb-bank" ascii wide nocase
        $bank4 = "aiibank" ascii wide nocase
        // Typosquat-style separators often inserted into look-alike domains
        $typo1 = "-gov-az" ascii wide nocase
        $typo2 = "gov-az-" ascii wide nocase
    condition:
        any of them
}
