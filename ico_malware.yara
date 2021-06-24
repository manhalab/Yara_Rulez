rule Suspected_Malware {
    meta:
        description = "Find Suspected Malware"
        author = "Manhal Basheer"
        date = "2021/06/22"
        reference = "not set"
        score = 5
        strings:
        $s0 = "basename"
        $s1 = "__FILE__"
        $s3 = "preg_replace"
        $s4 = "rawurldecode"

condition:
       all of them and  filesize < 32KB
}