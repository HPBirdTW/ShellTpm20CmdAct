/*
 * Copyright (C) 2019 HPBirdChen (hpbirdtw@gmail.com)
 * All rights reserved.
 * The License file locate on:
 * https://github.com/HPBirdTW/ShellTpm20CmdAct/license.txt
 * */

VOID PrintBufMixChar(
    UINTN   unBufSize,
    UINT8*  _buf
);

VOID WStrCat ( CHAR16   *Destination, CHAR16   *Source );

CHAR16* WStrCopy(CHAR16 *string1, CHAR16* string2);

UINTN WStrlen(CHAR16 *string) ;
