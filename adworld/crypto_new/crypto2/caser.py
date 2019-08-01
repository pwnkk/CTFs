def encryptor(key, message):
    lower=ord('a')
    upper=ord('A')
    res=''
    for i in range(0,len(message)):
        if message[i].islower():
            offset = (ord(message[i])-lower+key)%26
            res+=chr(lower+offset)
        elif message[i].isupper():
            offset = (ord(message[i])-upper+key)%26
            res+=chr(upper+offset)
        else:
            res+=message[i]
    return res

def enc(key,message):
    for i in range(len(message)):
        print message[i]+"  "+str(ord(message[i]))


for i in range(25):
    print encryptor(i,"oknqdbqmoq{kag_tmhq_xqmdzqp_omqemd_qzodkbfuaz}")
