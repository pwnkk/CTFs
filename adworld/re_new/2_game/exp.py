v2 = [ 0x7B,  0x20,  0x12,  98,  119,  108,  65,  41,  124,  80,  125,  38,  124,  111,  74,  49,  83,  108,  94,  108,  84,  6,  96,  83,  44,  121,  104,  110,  32,  95,  117,  101,  99,  123,  127,  119,  96,  48,  107,  71,  92,  29,  81,  107,  90,  85,  64,  12,  43,  76,  86,  13,  114,  1,  117,  126,  0,]
v59 = [18,  64,   98,   5,   2,   4,   6,   3,   6,   48,   49,   65,   32,   12,   48,   65,   31,   78,   62,   32,   49,   32,   1,   57,   96,   3,   21,   9,   4,   62,   3,   5,   4,   1,   2,   3,   44,   65,   78,   32,   16,   97,   54,   16,   44,   52,   32,   64,   89,   45,   32,   65,   15,   34,   18,   16,   0,]

print len(v2)
print len(v59)
for i in range(56):
    v2[i]=v2[i]^v59[i]
    #print chr(v2[i])
    v2[i]=v2[i]^0x13

res=""
for i in v2:
    res+=chr(i)
    print i
print res

