/*
 * Copyright (C) 2019 HPBirdChen (hpbirdtw@gmail.com)
 * All rights reserved.
 * The License file locate on:
 * https://github.com/HPBirdTW/ShellTpm20CmdAct/license.txt
 * */

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include "ShellTpm20CmdAct.h"

VOID PrintBufMixChar(
    UINTN   unBufSize,
    UINT8*  _buf
)
{
    UINTN           unIdx;
    UINT8           LineBuf[0x10];
    UINT8           charLineBuf[0x11];
    UINTN           Remainder;

    DEBUG(( DEBUG_INFO, "\n"));
    SetMem(&charLineBuf[0], sizeof(charLineBuf), 0);
    SetMem(&LineBuf[0], sizeof(LineBuf), 0);

    for( unIdx = 0; unIdx<unBufSize; ++unIdx )
    {
        LineBuf[ unIdx%0x10 ] = _buf[unIdx];

        if( _buf[unIdx] > 0x1F && _buf[unIdx] < 0x7F )
            charLineBuf[ unIdx%0x10 ] = _buf[unIdx];
        else
            charLineBuf[ unIdx%0x10 ] = '.';

        if( 0x0F == unIdx % 0x10 )
        {
            DEBUG(( DEBUG_INFO, " "));
            for( Remainder=0; Remainder < 0x10; ++Remainder )
            {
                DEBUG(( DEBUG_INFO, " %02x", (UINTN)LineBuf[Remainder] ));
            }
            DEBUG(( DEBUG_INFO, " | " ));
            for( Remainder=0; Remainder < 0x10; ++Remainder )
            {
                DEBUG(( DEBUG_INFO, "%c", (UINTN)charLineBuf[Remainder] ));
            }
            DEBUG(( DEBUG_INFO, "\n"));
            SetMem(&charLineBuf[0], sizeof(charLineBuf), 0);
        }
    }

    Remainder = unIdx % 0x10;

    if( Remainder )
    {
        DEBUG(( DEBUG_INFO, " "));
        for( unIdx=0; unIdx<Remainder; ++unIdx)
        {
            DEBUG(( DEBUG_INFO, " %02x", (UINTN)LineBuf[unIdx] ));
        }
        for( ; unIdx%0x10; ++unIdx )
        {
            DEBUG(( DEBUG_INFO, "   "));
        }
        DEBUG(( DEBUG_INFO, " | " ));
        for( unIdx=0; unIdx<Remainder; ++unIdx)
        {
            DEBUG(( DEBUG_INFO, "%c", (UINTN)charLineBuf[unIdx] ));
        }
        DEBUG(( DEBUG_INFO, "\n"));
    }
}

UINTN WStrlen(CHAR16 *string)
{
    UINTN length=0;
    while(*string++) length++;
    return length;
}

CHAR16* WStrCopy(CHAR16 *string1, CHAR16* string2)
{
    CHAR16 *dest = string1;
    while(*string1++=*string2++);
    return dest;
}

VOID
WStrCat (
  IN CHAR16   *Destination,
  IN CHAR16   *Source
  )
{
  WStrCopy (Destination + WStrlen (Destination) * sizeof(CHAR16), Source);
}
