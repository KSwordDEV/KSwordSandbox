rule KSwordSandbox_Placeholder_Static_Executable
{
    meta:
        description = "Placeholder static rule file for future host-side YARA scanning"
        scope = "benign scaffold"
    condition:
        uint16(0) == 0x5A4D
}
