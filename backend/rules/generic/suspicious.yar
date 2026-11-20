rule Suspicious_Process_Injection_Imports
{
    meta:
        description = "Imports commonly used together for process injection (T1055)"
        severity = "high"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
    condition:
        all of them
}

rule Suspicious_Downloader
{
    meta:
        description = "Imports typical of a simple HTTP downloader dropper"
        severity = "medium"
    strings:
        $url_api1 = "URLDownloadToFileA" ascii
        $url_api2 = "InternetOpenUrlA" ascii
        $url_api3 = "WinHttpOpen" ascii
        $exec1 = "WinExec" ascii
        $exec2 = "ShellExecuteA" ascii
    condition:
        1 of ($url_api*) and 1 of ($exec*)
}

rule Contains_EICAR_Test_String
{
    meta:
        description = "Contains the industry-standard EICAR antivirus test string"
        severity = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_Keylogger_Imports
{
    meta:
        description = "Imports typical of a keystroke logger (T1056)"
        severity = "high"
    strings:
        $a = "GetAsyncKeyState" ascii
        $b = "SetWindowsHookExA" ascii
        $c = "SetWindowsHookExW" ascii
    condition:
        $a and 1 of ($b, $c)
}
