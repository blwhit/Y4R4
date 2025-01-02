rule AntimalwareStrings
{
    strings:
        $string1 = /Antimalware\s+Core\s+Service/i wide
        $string2 = /Antimalware\s+Service\s+Executable/i wide
        $string3 = test

    condition:
        $string1 or $string2 or $string3
}
