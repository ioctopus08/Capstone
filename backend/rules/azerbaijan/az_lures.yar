rule AZ_Lure_Keywords_Finance
{
    meta:
        description = "Azerbaijani-language financial/salary lure keywords (common phishing/dropper theme)"
        severity = "medium"
        tags = "az-context"
    strings:
        $maas = "maas" ascii wide nocase
        $maasaz = "maaş" ascii nocase
        $faktura = "faktura" ascii wide nocase
        $odenis = "ödəniş" ascii nocase
        $odenis2 = "odenis" ascii wide nocase
        $bank_az = "bank" ascii wide nocase
    condition:
        2 of them
}

rule AZ_Lure_Keywords_Government
{
    meta:
        description = "Government / ministry themed lure keywords targeting Azerbaijani institutions"
        severity = "medium"
        tags = "az-context"
    strings:
        $nazirlik = "nazirlik" ascii wide nocase
        $dovlet = "dövlət" ascii nocase
        $dovlet2 = "dovlet" ascii wide nocase
        $vergi = "vergi" ascii wide nocase
        $mygov = "e-gov" ascii wide nocase
        $gov_az = ".gov.az" ascii wide nocase
    condition:
        1 of them
}

rule AZ_Lure_Keywords_Invoice_English
{
    meta:
        description = "English invoice/payment lure keywords commonly paired with AZ-targeted campaigns"
        severity = "low"
        tags = "az-context"
    strings:
        $inv1 = "invoice" ascii wide nocase
        $inv2 = "payment confirmation" ascii wide nocase
        $inv3 = "salary" ascii wide nocase
        $inv4 = "urgent transfer" ascii wide nocase
    condition:
        1 of them
}
