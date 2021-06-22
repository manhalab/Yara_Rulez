rule Manhal_crapware {
    meta:
        description = "Manhal Crapware find"
        author = "Manhal Basheer"
        date = "2021/06/22"
        reference = "not set"
        score = 5
        strings:
        $s0 = "basename"
        $s3 = "preg_replace"
        $s4 = "rawurldecode"
        $s5 = "_wsfbktr"

condition:
          $s0 and $s3 and $s4 or $s5
}