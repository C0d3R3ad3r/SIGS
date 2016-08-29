rule chm:chm
{
   strings:
       $STR1 = "/#IDXHDR"
       $STR2 = "/#ITBITS"
       $STR3 = "/#STRINGS"
       $STR4 = "/#SYSTEM"
       $STR5 = "/#TOPICS"
       $STR6 = "/#URLSTR"
       $STR7 = "/#URLTBL"
       $STR8 = "/$FlftiMain"
       $STR9 = "/$OBJINST"
       $STR10 = "/$WWWAssociativeLinks/"
       $STR11 = "/$WWWAssociativeLinks/Property"
       $STR12 = "/$WWWKeywordLinks"
       $STR13 = "/$WWWKeywordLinks/Property"
       $STR14 = "/1.htm"
       $STR15 = "/main.html"
       $STR16 = "/xml.htm"
   condition:
       (uint32(0) == 0x46535449) and all of them
}
