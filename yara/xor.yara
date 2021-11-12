rule XorExample4
{
    strings:
        $xor_string = "\x63\x69\x78\x69\x63\x69\x78\x69\x28\xb2\xb2" xor
    condition:
        $xor_string
}
