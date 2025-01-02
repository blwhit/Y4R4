rule AntimalwareStrings
{
    strings:
        $string1 = /Antimalware\s+Core\s+Service/i wide
        $string2 = /Antimalware\s+Service\s+Executable/i wide

    condition:
        $string1 or $string2
}
