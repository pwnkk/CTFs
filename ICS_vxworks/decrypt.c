
undefined4 loginDefaultEncrypt(int iParm1,byte *pbParm2)
{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  byte *pbVar6;
  uVar1 = strlen();
  iVar5 = 0;
  if ((uVar1 < 8) || (uVar1 = strlen(iParm1), 0x28 < uVar1)) {
    errnoSet(&DAT_00360003);
    uVar2 = 0xffffffff;
  }
  else {
    uVar1 = 0;
    while (uVar3 = strlen(iParm1), uVar1 < uVar3) {
      pbVar6 = (byte *)(iParm1 + uVar1);
      iVar4 = uVar1 + 2;
      uVar1 = uVar1 + 1;
      iVar5 = iVar5 + ((uint)*pbVar6 * iVar4 ^ uVar1);
    }
    uVar1 = 0;
    sprintf(pbParm2,&DAT_0022cc0c,iVar5 * 0x1e3a1d5);
    pbVar6 = pbParm2;
    while (uVar3 = strlen(pbParm2), uVar1 < uVar3) {
      if (*pbVar6 < 0x33) {
        *pbVar6 = *pbVar6 + 0x21;
      }
      if (*pbVar6 < 0x36) {
        *pbVar6 = *pbVar6 + 0x2f;
      }
      if (*pbVar6 < 0x39) {
        *pbVar6 = *pbVar6 + 0x41;
      }
      pbVar6 = pbVar6 + 1;
      uVar1 = uVar1 + 1;
    }
    uVar2 = 0;
  }
  return uVar2;
}

