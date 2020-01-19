/*
 * Copyright (C) 2019 HPBirdChen (hpbirdtw@gmail.com)
 * All rights reserved.
 * The License file locate on:
 * https://github.com/HPBirdTW/ShellTpm20CmdAct/license.txt
 * */

#ifndef __SHELL_TPM20_CMDACT_H__
#define __SHELL_TPM20_CMDACT_H__

#include <Protocol/TrEEProtocol.h>
#include <Protocol/TcgService.h>
#include <Tpm20CommLib/Tpm2Capability.h>
#include "AuxFunc.h"

/*
// {D5C7A518-BA07-42b1-AE41-DC62BD4F9E99}
static const GUID <<name>> =
{ 0xd5c7a518, 0xba07, 0x42b1, { 0xae, 0x41, 0xdc, 0x62, 0xbd, 0x4f, 0x9e, 0x99 } };
*/



#define VESION_SHELL_TPM20_CMDACT     L"1.0"

#if defined(SMDBG_SUPPORT_LIB) && SMDBG_SUPPORT_LIB
#undef DEBUG
    #define DEBUG(Arguments) SMDbgTrace Arguments
    #undef  ASSERT_EFI_ERROR
    #undef  ASSERT
    #define ASSERT(Condition) if(!(Condition)) { \
        SMDbgTrace((UINTN)-1,(CHAR8*)"ASSERT in %s on %i: %s\n",__FILE__, __LINE__, #Condition);\
        }
    #define ASSERT_EFI_ERROR(Status) ASSERT(!EFI_ERROR(Status))
#endif


#ifdef __cplusplus
extern "C" {
#endif



/****** DO NOT WRITE BELOW THIS LINE *******/
#ifdef __cplusplus
}
#endif
#endif

