可输入99 个目标

0024| 0xffa28814 ("AAAAAAA\001")
0028| 0xffa28818 --> 0x1414141
0032| 0xffa2881c --> 0x20beeb00   canary 
0036| 0xffa28820 --> 0xf77293dc  
0040| 0xffa28824 --> 0xffa28840  
0044| 0xffa28828 --> 0x0
0048| 0xffa2882c --> 0xf758f637 (<__libc_start_main+247>:    


0x7e4cac00

100        0
101        -84      
102        76       0x4c
103        126      0x7e



0xffdbce58  v13[0]
0xffdbcedc  ret

gdb-peda$ p 0xffdbcedc - 0xffdbce58
$12 = 0x84

0x804859b hackhere


没有 /bin/bash ??

布置 sh 到0x804a100

设置返回地址 system_plt aaaa  0x804a100



泄露libc地址




    '108\t\t-32\n'
    '109\t\t-44\n'
    '110\t\t-14\n'




