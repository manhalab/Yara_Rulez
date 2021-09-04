rule Image_Contains_eval
{
    meta:
        
        author = "Manhal Basheer"
        date = "2021/04/08"
        description = "Detect eval function inside JPG EXIF header "
        method = "Detect image file and  eval function"
   strings:
      $png = {89 50 4E 47}
      $jpeg = {FF D8 FF}
      $gif = "GIF"
      $eval = "eval("
      $JFIF = {ff d8 ff e0 00 10 4a 46  49 46}
      $s1 = { 3c 3f 70 68 70 } // finds  Hex of <?php
   condition:
      (($png at 0) or ($jpeg at 0) or ($JFIF at 0) or ($gif at 0)) and $eval or $s1
}