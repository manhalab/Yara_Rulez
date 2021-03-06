rule PHP_Obfuscator {
    meta:
        description = "PHP Obfuscated Malware"
        author = "Manhal Basheer"
        date = "2021/07/01"
        reference = "not set"
        score = 21
        strings:
        $s0 = "$AD9" 
        $s1 = "$ADE" 
        $s3 = "$AE9" 
        $s4 = "$A9E" 
        $s5 = "$AEE" 
        $s6 = "$A9D"

condition:
    all of ($s*) and #s1 > 100
}