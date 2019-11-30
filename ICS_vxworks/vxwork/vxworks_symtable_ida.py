from idaapi import *
import time

# loadaddress = 0xf2004000
loadaddress = 0x10000
eaStart = 0x301e64 + loadaddress
eaEnd = 0x3293a4 + loadaddress

ea = eaStart
eaEnd = eaEnd
while ea < eaEnd:
    offset = 0
    MakeStr(Dword(ea - offset), BADADDR)
    sName = GetString(Dword(ea - offset), -1, ASCSTR_C)
    print sName
    if sName:
        eaFunc = Dword(ea - offset + 4)
        MakeName(eaFunc, sName)
        MakeCode(eaFunc)
        MakeFunction(eaFunc, BADADDR)
    ea = ea + 16
    #if eaStart + 50 < ea:
    #    break
    # time.sleep(1)

