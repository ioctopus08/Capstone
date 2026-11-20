/*
 * Safe synthetic test sample for the IOCtopus static triage demo.
 *
 * This program imports process-injection APIs WITHOUT EVER CALLING THEM
 * (they are referenced only to appear in the import table, then the
 * pointers are deliberately never invoked), embeds decoy IOC strings,
 * and contains the EICAR test string. It does nothing malicious at
 * runtime - it only prints a message and exits. This gives the demo a
 * repeatable, controlled "suspicious-looking" sample instead of handling
 * live malware on a laptop.
 *
 * Build (MinGW):
 *   gcc make_test_sample.c -o suspicious_sample.exe -lkernel32
 *
 * Then make a packed copy for the entropy/UPX anomaly demo:
 *   upx -9 -o suspicious_sample_packed.exe suspicious_sample.exe
 */
#include <windows.h>
#include <stdio.h>

/* Decoy strings for IOC extraction - these are NOT real infrastructure. */
static const char *decoy_strings[] = {
    "http://evil-example-c2.test/beacon",
    "185.199.108.153",
    "update-portal-gov-az.test",
    "faktura odenis tesdiqi",
    "nazirlik elaqe formu",
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
};

/* Wide (UTF-16LE) decoy string - many teams miss these during string extraction. */
static const wchar_t *wide_decoy = L"wide-string-indicator-update-portal-gov-az.test";

int main(void) {
    /* Reference injection-style APIs so they show up in the import table,
       but never call them - this sample performs no real injection. */
    volatile void *fn1 = (void *)VirtualAllocEx;
    volatile void *fn2 = (void *)WriteProcessMemory;
    volatile void *fn3 = (void *)CreateRemoteThread;
    (void)fn1; (void)fn2; (void)fn3;

    for (int i = 0; i < (int)(sizeof(decoy_strings) / sizeof(decoy_strings[0])); i++) {
        printf("%s\n", decoy_strings[i]);
    }
    wprintf(L"%ls\n", wide_decoy);

    printf("This is a harmless demo binary for the IOCtopus hackathon demo.\n");
    return 0;
}
