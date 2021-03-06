rule Suspected_PHP_shell_Malware {
    meta:
        description = "Suspected Array Malware"
        author = "Manhal Basheer"
        date = "2021/08/14"
        reference = "not set"
        score = 25
        strings:
        $s0 = "eval"
        $s1 = "base64_decode"
        $s2 = "shell" nocase
        $s3 = "<?php" nocase
        $f4 = "composer.phar" nocase

condition:
        (not $f4) and all of ($s*) and #s1 > 2
}