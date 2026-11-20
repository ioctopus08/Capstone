rule UPX_Packed_Binary
{
    meta:
        description = "UPX packer signature strings present in binary"
        severity = "medium"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
    condition:
        any of them
}

rule High_Entropy_Hint_Strings
{
    meta:
        description = "Strings suggesting the sample is self-aware of packing/protection"
        severity = "low"
    strings:
        $b = ".packed" ascii nocase
        $c = "VMProtect" ascii
        $d = "Themida" ascii
    condition:
        1 of ($b, $c, $d)
}
