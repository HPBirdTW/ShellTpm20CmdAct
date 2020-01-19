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

EFI_STATUS ShowPermanentProperty()
{
    EFI_STATUS              Status;
    TPMS_CAPABILITY_DATA    TpmCap;
    TPMI_YES_NO             MoreData;
    TPMA_PERMANENT          AttrPermanent;

    Status = Tpm2GetCapability(
            TPM_CAP_TPM_PROPERTIES,
            TPM_PT_PERMANENT,
            1,
            &MoreData,
            &TpmCap
            );
    SPrintf(L"  Tpm2GetCapability(CAP_TPM_PROPERTIES, PT_PERMANENT) -%r\n\r", Status);
    if( !EFI_ERROR(Status) )
    {
        *(UINT32*)&AttrPermanent = SwapBytes32( *(UINT32*)&TpmCap.data.tpmProperties.tpmProperty[0].value );
        SPrintf(L"    ownerAuthSet           [%02x].\r\n", AttrPermanent.ownerAuthSet ? 1 : 0 );
        SPrintf(L"    endorsementAuthSet     [%02x].\r\n", AttrPermanent.endorsementAuthSet ? 1 : 0 );
        SPrintf(L"    lockoutAuthSet         [%02x].\r\n", AttrPermanent.lockoutAuthSet ? 1 : 0 );
        SPrintf(L"    disableClear           [%02x].\r\n", AttrPermanent.disableClear ? 1 : 0 );
        SPrintf(L"    inLockout              [%02x].\r\n", AttrPermanent.inLockout ? 1 : 0 );
        SPrintf(L"    tpmGeneratedEPS        [%02x].\r\n", AttrPermanent.tpmGeneratedEPS ? 1 : 0 );
    }

    return Status;
}

EFI_STATUS Tpm2GetCapabilityCapPCRS (
    UINT32  *pSupportedPcrBitMap,
    UINT32  *pActivePcrBitMap
)
{
    TPMS_CAPABILITY_DATA        TpmCap;
    TPMI_YES_NO                 MoreData;
    EFI_STATUS                  Status;
    TPMS_PCR_SELECTION          *PcrSelect;
    UINTN                       unIdx;
    UINT32                      SupportedPcrBitMap=0;
    UINT16                      u16HashAlg;

    UINT32                      ActivePcrBitMap = 0;
    UINT32                      u32PcrSelectCount = 0;

    do
    {
        SupportedPcrBitMap  = 0;
        ActivePcrBitMap     = 0;

        Status  = Tpm2GetCapability (
                        TPM_CAP_PCRS,
                        0,
                        MAX_PCR_PROPERTIES,
                        &MoreData,
                        &TpmCap);

        if(EFI_ERROR(Status))
        {
            DEBUG(( -1, "[%d]: Err. Tpm2GetCapability(TPM_CAP_PCRS)\n", __LINE__));
            break;
        }

        u32PcrSelectCount = SwapBytes32(TpmCap.data.assignedPCR.count);
        for( unIdx=0; unIdx<u32PcrSelectCount ; ++unIdx )
        {
            PcrSelect = &TpmCap.data.assignedPCR.pcrSelections[unIdx];
            u16HashAlg = SwapBytes16(PcrSelect->hash);
            switch(u16HashAlg)
            {
                case TPM_ALG_SHA1:
                    SupportedPcrBitMap |= 1;
                    if( PcrSelect->pcrSelect[0] & 0xFF ) // Check the PCR0~7
                    {
                        ActivePcrBitMap |= 1;
                    }
                    break;
                case TPM_ALG_SHA256:
                    SupportedPcrBitMap |= 2;
                    if( PcrSelect->pcrSelect[0] & 0xFF )
                    {
                        ActivePcrBitMap |= 2;
                    }
                    break;
                case TPM_ALG_SHA384:
                    SupportedPcrBitMap |= 4;
                    if( PcrSelect->pcrSelect[0] & 0xFF )
                    {
                        ActivePcrBitMap |= 4;
                    }
                    break;
                case TPM_ALG_SHA512:
                    SupportedPcrBitMap |= 8;
                    if( PcrSelect->pcrSelect[0] & 0xFF )
                    {
                        ActivePcrBitMap |= 8;
                    }
                    break;
                case TPM_ALG_SM3_256:
                    SupportedPcrBitMap |= 0x10;
                    if( PcrSelect->pcrSelect[0] & 0xFF )
                    {
                        ActivePcrBitMap |= 0x10;
                    }
                    break;
              default:
                  DEBUG(( -1, "[%d]: Error for parsing \n", __LINE__));
                  Status = EFI_DEVICE_ERROR;
                  break;
            }
        }
    } while( FALSE );

    if( !EFI_ERROR(Status) )
    {
        DEBUG(( -1," SupportedPcrBitMap = %x \n", SupportedPcrBitMap));
        DEBUG(( -1," ActivePcrBitMap = %x \n", ActivePcrBitMap));

        *pSupportedPcrBitMap = SupportedPcrBitMap;
        *pActivePcrBitMap = ActivePcrBitMap;
    }

  return Status;
}

enum {
    NONE_ID,
    IFX_TPM,
    NTC_TPM,
    ST_TPM,
    NTZ_TPM
} gTpmDevType = NONE_ID;

/**
 * Function for Identify the current platform is Infineon TPM
 *
 * @retval EFI_SUCCESS          Identify the Infineon TPM Chip
 */
EFI_STATUS EFIAPI GetTpmDevType( )
{
    EFI_STATUS  Status = EFI_NOT_FOUND;
    UINT32      Size;

    do
    {
        UINT8 Send20TpmVender[22] = {
                0x80,0x01,
                0x00,0x00,0x00,0x16,
                0x00,0x00,0x01,0x7a,
                0x00,0x00,0x00,0x06,
                0x00,0x00,0x01,0x05,
                0x00,0x00,0x00,0x01};
        UINT8 Recv[0x100];

        gTpmDevType = NONE_ID;

        Size = sizeof(Recv);
        Status =  Tpm2SubmitCommand(sizeof(Send20TpmVender), Send20TpmVender, &Size, Recv );
        if (Status != EFI_SUCCESS)
        {
            break;
        }

        // IFX TPM?
        if( 0x00584649 == *(UINT32*)(Recv + 23))
        {
            Status = EFI_SUCCESS;
            gTpmDevType = IFX_TPM;
            break;
        }
        // NTC TPM?
        if( 0x0043544e == *(UINT32*)(Recv + 23))
        {
            Status = EFI_SUCCESS;
            gTpmDevType = NTC_TPM;
            break;
        }
        // NTZ TPM?
        if( 0x4e545a00 == SwapBytes32 ( *(UINT32*)(Recv + 23)) )
        {
            Status = EFI_SUCCESS;
            gTpmDevType = NTZ_TPM;
            break;
        }
        // ST TPM?
        if( 0x204d5453 == *(UINT32*)(Recv + 23))
        {
            Status = EFI_SUCCESS;
            gTpmDevType = ST_TPM;
            break;
        }

        // VENDER IFX?
        if( 0x15D1 == *(UINT16*)0xfed40f00 )
        {
            Status = EFI_SUCCESS;
            gTpmDevType = IFX_TPM;
            break;
        }
        // VENDER NTC?
        if( 0x1050 == *(UINT16*)0xfed40f00 )
        {
            Status = EFI_SUCCESS;
            gTpmDevType = NTC_TPM;
            break;
        }
        // VENDER NTZ?
        if( 0x1B4E == *(UINT16*)0xfed40f00 )
        {
            Status = EFI_SUCCESS;
            gTpmDevType = NTZ_TPM;
            break;
        }
        // VENDER ST?
        if( 0x104A == *(UINT16*)0xfed40f00 )
        {
            Status = EFI_SUCCESS;
            gTpmDevType = ST_TPM;
            break;
        }
    } while (FALSE);

    return Status;
}

/**
 * The function get the Tpm Version for ESRT Report
 *
 * @param   ShortVersion            Return the current TPM device version for ESRT Table
 *
 * @retval  EFI_SUCCESS             Function Success.
 * @retval  EFI_DEVICE_ERROR        TPM communication fail.
 * @retval  others                  Status of function { TpmTisSubmitCommand() }
 */
EFI_STATUS EFIAPI GetTpmVersion(
    IN OUT  UINT32     *ShortVersion
)
{
    EFI_STATUS  Status = EFI_UNSUPPORTED;

    UINT8   Send20_0[22] = {
                0x80,0x01,
                0x00,0x00,0x00,0x16,
                0x00,0x00,0x01,0x7a,
                0x00,0x00,0x00,0x06,
                0x00,0x00,0x01,0x0b,
                0x00,0x00,0x00,0x01};
    UINT8   Send20_1[22] = {
                0x80,0x01,
                0x00,0x00,0x00,0x16,
                0x00,0x00,0x01,0x7a,
                0x00,0x00,0x00,0x06,
                0x00,0x00,0x01,0x0c,
                0x00,0x00,0x00,0x01};

    UINT8   Recv[0x40];
    UINT32  u32IfxTpm20Version;
    UINT32   TmpVal;

    do
    {
        Status = GetTpmDevType ();
        if (EFI_ERROR (Status))
        {
            break;
        }

        TmpVal = sizeof(Recv);
        // Send TPM_GetCapability (with TPM_PT_VERSION_1) command to TPM2.0
        Status =  Tpm2SubmitCommand(sizeof(Send20_0), Send20_0, &TmpVal, Recv );
        if (Status != EFI_SUCCESS)
        {
            break;
        }

        if (IFX_TPM == gTpmDevType)
        {
            u32IfxTpm20Version = SwapBytes32( *(UINT32*)(Recv+23) );
            u32IfxTpm20Version &= 0xFF;
            u32IfxTpm20Version <<= 24;
        }
        else if (NTC_TPM == gTpmDevType)
        {
            ((UINT8*)ShortVersion)[3] = Recv[24];
            ((UINT8*)ShortVersion)[2] = Recv[26];
        }
        else if (NTZ_TPM == gTpmDevType)
        {
            *ShortVersion = SwapBytes32( *(UINT32*)(Recv+23) );
        }
        else if (ST_TPM == gTpmDevType)
        {
            *ShortVersion = SwapBytes32( *(UINT32*)(Recv+23));
        }

        TmpVal = sizeof(Recv);
        // Send TPM_GetCapability (with TPM_PT_VERSION_2) command.
        Status =  Tpm2SubmitCommand(sizeof(Send20_1), Send20_1, &TmpVal, Recv );
        if (Status != EFI_SUCCESS)
        {
            break;
        }

        if (IFX_TPM == gTpmDevType)
        {
            u32IfxTpm20Version |= (SwapBytes32 (*(UINT32*)(Recv+23)) & 0x00FFFFFF);
            *ShortVersion = u32IfxTpm20Version;
        }
        else if (NTC_TPM == gTpmDevType)
        {
            ((UINT8*)ShortVersion)[1] = Recv[24];
            ((UINT8*)ShortVersion)[0] = Recv[26];
        }
    } while (FALSE);

    return Status;
}

EFI_STATUS ShowAmiTpmFmpVersion(
)
{
    EFI_STATUS      Status = EFI_UNSUPPORTED;
    UINT32          TpmVersion = 0;

    do
    {
        Status = GetTpmVersion (&TpmVersion);
        if (EFI_ERROR (Status))
        {
            break;
        }

        if (IFX_TPM == gTpmDevType)
        {
            SPrintf(L"Infineon Version: [0x%08x]\n\r", TpmVersion);
        }
        else if (NTC_TPM == gTpmDevType)
        {
            SPrintf(L"Nuvuton Version: [0x%08x]\n\r", TpmVersion);
        }
        else if (NTZ_TPM == gTpmDevType)
        {
            SPrintf(L"NationZ Version: [0x%08x]\n\r", TpmVersion);
        }
        else if (ST_TPM == gTpmDevType)
        {
            SPrintf(L"ST Version: [0x%08x]\n\r", TpmVersion);
        }
    } while (FALSE);

    return Status;
}

EFI_STATUS ShowPcrReadValue(
    UINT32      u32PcrIndex
)
{
    EFI_STATUS      Status;
    UINT32          SupportedPcrBitMap;
    UINT32          ActivePcrBitMap;
    UINT8           PcrDigest[SHA512_DIGEST_SIZE];

    do
    {
        Status = Tpm2GetCapabilityCapPCRS( &SupportedPcrBitMap, &ActivePcrBitMap);
        SPrintf(L"  Tpm2GetCapabilityCapPCRS( SupportedPcrBitMap, ActivePcrBitMap ) - %r\n\r", Status);
        if( EFI_ERROR(Status) )
        {
            break;
        }

        if( ActivePcrBitMap & 0x01)
        {
            Status = Tpm2Sha1PCRRead( u32PcrIndex, &PcrDigest[0] );
            if( EFI_ERROR (Status))
            {
                SPrintf(L"  Tpm2Sha1PCRRead( PcrIndex[%d] ) - %r\n\r", u32PcrIndex, Status);
                break;
            }
            SPrintf(L"SHA1 PCRIndex[%d]:", u32PcrIndex);
            SPrintBufToCon( SHA1_DIGEST_SIZE, PcrDigest );
        }

        if( ActivePcrBitMap & 0x02)
        {
            Status = Tpm2Sha256PCRRead( u32PcrIndex, &PcrDigest[0] );
            if( EFI_ERROR (Status))
            {
                SPrintf(L"  Tpm2Sha256PCRRead( PcrIndex[%d] ) - %r\n\r", u32PcrIndex, Status);
                break;
            }
            SPrintf(L"SHA256 PCRIndex[%d]:", u32PcrIndex);
            SPrintBufToCon( SHA256_DIGEST_SIZE, PcrDigest );
        }
    } while (FALSE);

    return Status;
}

#pragma pack(1)

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_PLATFORM          AuthHandle;
  UINT32                    AuthSessionSize;
  TPMS_AUTH_COMMAND         AuthSession;
  TPML_PCR_SELECTION        PcrAllocation;
} TPM2_PCR_ALLOCATE_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     AuthSessionSize;
  TPMI_YES_NO                AllocationSuccess;
  UINT32                     MaxPCR;
  UINT32                     SizeNeeded;
  UINT32                     SizeAvailable;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_PCR_ALLOCATE_RESPONSE;

#pragma pack()

// HashBitMap:
//    0x01: SHA1
//    0x02: SHA256
//    0x04: SHA384
//    0x08: SHA512
//    0x10: SM3
EFI_STATUS Tpm2PcrAllocate
(
    UINTN       HashBitMap
)
{
    EFI_STATUS                  Status = EFI_SUCCESS;
    TPM2_PCR_ALLOCATE_COMMAND   Cmd;
    TPM2_PCR_ALLOCATE_RESPONSE  Res;
    UINT32                      CmdSize;
    UINT8                       *Buffer;
    UINT8                       *ResultBuf;
    UINT32                      ResultBufSize;
    UINTN                       Index;
    UINT32                      u32Count;
    UINT32                      *pu32Count;
    UINT32                      SupportedPcrBitMap;
    UINT32                      ActivePcrBitMap;

    do
    {

        Status = Tpm2GetCapabilityCapPCRS( &SupportedPcrBitMap, &ActivePcrBitMap);
        SPrintf(L"  Tpm2GetCapabilityCapPCRS( SupportedPcrBitMap, ActivePcrBitMap ) - %r\n\r", Status);
        if( EFI_ERROR(Status) )
        {
            break;
        }

        Cmd.Header.tag          = SwapBytes16(TPM_ST_SESSIONS);
        Cmd.Header.paramSize    = SwapBytes32(sizeof(Cmd));
        Cmd.Header.commandCode  = SwapBytes32(TPM_CC_PCR_Allocate);
        Cmd.AuthHandle          = SwapBytes32(TPM_RH_PLATFORM);

        Buffer = (UINT8 *)&Cmd.AuthSession;

        //  sessionHandle
        *(UINT32*)Buffer = SwapBytes32(TPM_RS_PW);
        Buffer += sizeof(UINT32);
        // nonce = nullNonce
        *(UINT16*)Buffer = 0;
        Buffer += sizeof(UINT16);
        // sessionAttributes = 0
        *(UINT8 *)Buffer = 0x00;
        Buffer += sizeof(UINT8);
        // hmac = nullAuth
        *(UINT16*)Buffer = 0;
        Buffer += sizeof(UINT16);
        // sessionInfoSize
        CmdSize = (UINT32)Buffer - (UINT32)&Cmd.AuthSession;
        Cmd.AuthSessionSize = SwapBytes32(CmdSize);

        // Count
        u32Count = 0;
        pu32Count = (UINT32*)Buffer;
        Buffer += sizeof(UINT32);

        if( SupportedPcrBitMap & 0x01)
        {
            ++u32Count;
            // SHA1 PCR Bank Config
            *(UINT16*)Buffer = SwapBytes16(TPM_ALG_SHA1);
            Buffer += sizeof(UINT16);
            // sizeofSelect, PCR 0~23
            *(UINT8 *)Buffer = 3;
            Buffer++;
            // PcrSelect
            if( HashBitMap & 0x01 )
                Index = 0xFFFFFFFF;     // TPM_ALG_SHA1 Enable
            else
                Index = 0x00000000;     // TPM_ALG_SHA1 Disable
            CopyMem( Buffer, &Index, 3);
            Buffer += 3;
        }

        if( SupportedPcrBitMap & 0x02)
        {
            ++u32Count;
            // HashAlg256  PCR Bank Config
            *(UINT16*)Buffer = SwapBytes16(TPM_ALG_SHA256);
            Buffer += sizeof(UINT16);
            // sizeofSelect, PCR 0~23
            *(UINT8 *)Buffer = 3;
            Buffer++;
            // PcrSelect
            if( HashBitMap & 0x02 )
                Index = 0xFFFFFFFF;     // HashAlg256 Enable
            else
                Index = 0x00000000;     // HashAlg256 Disable
            CopyMem( Buffer, &Index, 3);
            Buffer += 3;
        }

        if( SupportedPcrBitMap & 0x04)
        {
            ++u32Count;
            // HashAlg256  PCR Bank Config
            *(UINT16*)Buffer = SwapBytes16(TPM_ALG_SHA384);
            Buffer += sizeof(UINT16);
            // sizeofSelect, PCR 0~23
            *(UINT8 *)Buffer = 3;
            Buffer++;
            // PcrSelect
            if( HashBitMap & 0x04 )
                Index = 0xFFFFFFFF;     // HashAlg256 Enable
            else
                Index = 0x00000000;     // HashAlg256 Disable
            CopyMem( Buffer, &Index, 3);
            Buffer += 3;
        }

        if( SupportedPcrBitMap & 0x08)
        {
            ++u32Count;
            // HashAlg256  PCR Bank Config
            *(UINT16*)Buffer = SwapBytes16(TPM_ALG_SHA512);
            Buffer += sizeof(UINT16);
            // sizeofSelect, PCR 0~23
            *(UINT8 *)Buffer = 3;
            Buffer++;
            // PcrSelect
            if( HashBitMap & 0x08 )
                Index = 0xFFFFFFFF;     // HashAlg256 Enable
            else
                Index = 0x00000000;     // HashAlg256 Disable
            CopyMem( Buffer, &Index, 3);
            Buffer += 3;
        }

        if( SupportedPcrBitMap & 0x10)
        {
            ++u32Count;
            // HashAlg256  PCR Bank Config
            *(UINT16*)Buffer = SwapBytes16(TPM_ALG_SM3_256);
            Buffer += sizeof(UINT16);
            // sizeofSelect, PCR 0~23
            *(UINT8 *)Buffer = 3;
            Buffer++;
            // PcrSelect
            if( HashBitMap & 0x10 )
                Index = 0xFFFFFFFF;     // HashAlg256 Enable
            else
                Index = 0x00000000;     // HashAlg256 Disable
            CopyMem( Buffer, &Index, 3);
            Buffer += 3;
        }

        // Fill back to PCR Support Count
        *pu32Count = SwapBytes32( u32Count );

        CmdSize = (UINT32)(Buffer - (UINT8 *)&Cmd);
        Cmd.Header.paramSize = SwapBytes32(CmdSize);

        ResultBuf     = (UINT8 *) &Res;
        ResultBufSize = sizeof(Res);

        Status = Tpm2SubmitCommand (CmdSize, (UINT8 *)&Cmd, &ResultBufSize, (UINT8 *)&Res);
        SPrintf(L"  Tpm2PcrAllocate( HashBitMap[0x%04x] ) - %r\n\r", HashBitMap, Status);
        if (EFI_ERROR(Status)) {
            break;
        }

        if( TPM_RC_SUCCESS == Res.Header.responseCode )
        {
            // Command Success
        }
        else
        {
            Status = EFI_INVALID_PARAMETER;
        }

    } while( FALSE );

    return Status;
}

EFI_STATUS ShowPcrSupportAndActStatus()
{
    EFI_STATUS      Status;
    UINT32          SupportedPcrBitMap;
    UINT32          ActivePcrBitMap;

    do
    {
        Status = Tpm2GetCapabilityCapPCRS( &SupportedPcrBitMap, &ActivePcrBitMap);
        SPrintf(L"  Tpm2GetCapabilityCapPCRS( SupportedPcrBitMap, ActivePcrBitMap ) - %r\n\r", Status);
        if( EFI_ERROR(Status) )
        {
            break;
        }
        // Display the Support Pcr Bank
        SPrintf(L"  SupportPcrBank[ ");
        if( SupportedPcrBitMap & 0x01)
            SPrintf(L"SHA1 ");
        if( SupportedPcrBitMap & 0x02)
            SPrintf(L"SHA256 ");
        if( SupportedPcrBitMap & 0x04)
            SPrintf(L"SHA384 ");
        if( SupportedPcrBitMap & 0x08)
            SPrintf(L"SHA512 ");
        if( SupportedPcrBitMap & 0x10)
            SPrintf(L"SM3 ");
        SPrintf(L"]\n\r");

        // Dispaly the Activate Pcr Bank
        SPrintf(L"  ActivePcrBitMap[ ");
        if( ActivePcrBitMap & 0x01)
            SPrintf(L"SHA1 ");
        if( ActivePcrBitMap & 0x02)
            SPrintf(L"SHA256 ");
        if( ActivePcrBitMap & 0x04)
            SPrintf(L"SHA384 ");
        if( ActivePcrBitMap & 0x08)
            SPrintf(L"SHA512 ");
        if( ActivePcrBitMap & 0x10)
            SPrintf(L"SM3 ");
        SPrintf(L"]\n\r");
    } while( FALSE );

    return Status;
}


EFI_STATUS  ShellExeCmdFile(
    CHAR16      *ExeCmdFile
)
{
    EFI_STATUS FileToTpmCmd(
        UINT8   *FileBuffer,
        UINTN   BufferSize,
        UINT8   *pTpmCmdBuffer,
        UINTN   *TpmCmdBufSize
    );

    EFI_STATUS  Status = EFI_SUCCESS;
    EFI_STATUS  InnerSts;
    // Check the Open File
    UINT8       *pFileBuf = NULL;
    UINTN       FileBufSize = 0;
    UINT8       *pTpmCmdBuf = NULL;
    UINT8       *pTpmResBuf = NULL;
    UINTN       TpmCmdBufSize;
    UINT32      u32TpmResBufSize;

    TPM2_RESPONSE_HEADER*   Header = NULL;

    do
    {
        Status = pBS->AllocatePool( EfiBootServicesData, MAX_COMMAND_SIZE, &pTpmCmdBuf );
        if( EFI_ERROR(Status) )
        {
            SPrintf( L"Failed to Locate TPM Cmd Memory [0x%08x].\n\r", MAX_COMMAND_SIZE );
            break;
        }
        Status = pBS->AllocatePool( EfiBootServicesData, MAX_RESPONSE_SIZE, &pTpmResBuf );
        if( EFI_ERROR(Status) )
        {
            SPrintf( L"Failed to Locate TPM Response Memory [0x%08x].\n\r", MAX_RESPONSE_SIZE );
            break;
        }

        Status = OpenShellFile( ExeCmdFile, &pFileBuf, &FileBufSize );
        if( EFI_ERROR(Status))
        {
            SPrintf( L"Failed to Open File [%s].\n\r", ExeCmdFile );
            break;
        }

        TpmCmdBufSize = MAX_COMMAND_SIZE;
        Status = FileToTpmCmd( pFileBuf, FileBufSize, pTpmCmdBuf, &TpmCmdBufSize );
        if( EFI_ERROR(Status) )
        {
            SPrintf( L"Failed to Parsing  [%s].\n\r", ExeCmdFile );
            break;
        }

        u32TpmResBufSize = MAX_RESPONSE_SIZE;
        Status = Tpm2SubmitCommand (
                                    (UINT32)TpmCmdBufSize,
                                    pTpmCmdBuf,
                                    &u32TpmResBufSize,
                                    pTpmResBuf
                                    );
        if( EFI_ERROR(Status) )
        {
            SPrintf( L"Failed to Execute TPM Protocol -%r.\n\r", Status );
            break;
        }

        Header = (TPM2_RESPONSE_HEADER*)pTpmResBuf;

        if( Header->responseCode )
        {
            SPrintf( L"TPM Err. ReturnCode [%08x].\n\r", SwapBytes32 (Header->responseCode) );
            break;
        }

    } while (FALSE);

    if( pFileBuf )
    {
        InnerSts = pBS->FreePool( pFileBuf );
        ASSERT_EFI_ERROR( InnerSts );
        pFileBuf = NULL;
    }

    if( pTpmCmdBuf )
    {
        InnerSts = pBS->FreePool( pTpmCmdBuf );
        ASSERT_EFI_ERROR( InnerSts );
        pTpmCmdBuf = NULL;
    }

    if( pTpmResBuf )
    {
        InnerSts = pBS->FreePool( pTpmResBuf );
        ASSERT_EFI_ERROR( InnerSts );
        pTpmResBuf = NULL;
    }

    return Status;
}

EFI_STATUS ShellTpm20WriteNvIndex(
    UINT32  NvIndex,
    UINT32  AuthWay,
    UINT32  AuthHandle1,
    CHAR16* AuthHdlFile1,
    CHAR16* InFile
)
{
    EFI_STATUS          Status = EFI_SUCCESS;
    UINT8               *pAuthHdlBuf = NULL;
    UINTN               AuthHdlBufSize = 0;
    TPM2B_MAX_BUFFER    WriteBuffer;
    UINT8               *Buffer;
    UINTN               BufferSize;
    TPMS_AUTH_COMMAND   AuthSession;
    TPM2B_NV_PUBLIC     NvPublic;
    TPM2B_NAME          NvName;

    SetMem( &WriteBuffer, sizeof(WriteBuffer), 0);
    SetMem( &AuthSession, sizeof(AuthSession), 0);
    SetMem( &NvPublic, sizeof(NvPublic), 0);
    SetMem( &NvName, sizeof(NvName), 0);

    // Check the Input Parameter and process
    do
    {
        // We only support the Password Auth.
        if (0 != AuthWay)
        {
            if (Aux_AuthByPws != AuthWay )
            {
                Status = EFI_INVALID_PARAMETER;
                SPrintf(L"Only support -AuthByPws\n\r");
                break;
            }

            if( NULL != AuthHdlFile1 && WStrlen(AuthHdlFile1) )
            {
                Status = OpenShellFile( AuthHdlFile1, &pAuthHdlBuf, &AuthHdlBufSize );
                if (EFI_ERROR (Status))
                {
                    SPrintf(L"Failed to Open File [%s]\n\r", AuthHdlFile1 );
                    break;
                }

                if( AuthHdlBufSize > SHA256_DIGEST_SIZE )
                {
                    Status = EFI_INVALID_PARAMETER;
                    SPrintf(L"File [%s] size is large 0x%x\n\r", AuthHdlFile1, SHA256_DIGEST_SIZE );
                    break;
                }
            }
        }

        Status = Tpm2NvReadPublic( NvIndex, &NvPublic, &NvName );
        if (EFI_ERROR (Status))
        {
            SPrintf(L"Fail on Tpm2NvReadPublic(...) - 0x%x\n\r", Status );
            break;
        }

        if ( NULL != InFile && 0 == WStrlen (InFile))
        {
            Status = EFI_INVALID_PARAMETER;
            SPrintf(L"Loss -InFile File\n\r");
            break;
        }

        if( NULL != InFile && WStrlen(InFile) )
        {
            Status = OpenShellFile( InFile, &Buffer, &BufferSize );
            if (EFI_ERROR (Status))
            {
                SPrintf(L"Failed to Open File [%s]\n\r", Buffer );
                break;
            }

            if( BufferSize > (UINTN)NvPublic.nvPublic.dataSize )
            {
                Status = EFI_INVALID_PARAMETER;
                SPrintf(L"File [%s] size is large 0x%x\n\r", InFile, (UINTN)NvPublic.nvPublic.dataSize );
                break;
            }

            CopyMem ( WriteBuffer.buffer, Buffer, BufferSize);
            WriteBuffer.size = (UINT16)BufferSize;
        }

    } while (FALSE);

    if (EFI_ERROR (Status))
    {
        return Status;
    }

    // Process the Pws Handle session
    if( Aux_AuthByPws == AuthWay || 0 == AuthWay )
    {
        do
        {
            if( pAuthHdlBuf )
            {
                AuthSession.sessionHandle = TPM_RS_PW;
                AuthSession.hmac.size = (UINT16)AuthHdlBufSize;
                CopyMem (AuthSession.hmac.buffer, pAuthHdlBuf, (UINTN)AuthSession.hmac.size);
            }

            Status = Tpm2NvWrite(
                            AuthHandle1,
                            NvIndex,
                            NULL == pAuthHdlBuf ? NULL : &AuthSession,
                            &WriteBuffer,
                            0
                            );

            if (EFI_ERROR (Status))
            {
                SPrintf(L"Fail on Tpm2NvWrite(...) - 0x%x\n\r", Status );
                break;
            }
        } while (FALSE);
    }

    return Status;
}

EFI_STATUS ShellTpm20UndefineSpace(
    UINT32  NvIndex,
    UINT32  AuthWay,
    UINT32  AuthHandle1,
    CHAR16* AuthHdlFile1
)
{
    EFI_STATUS          Status = EFI_SUCCESS;
    UINT8               *pAuthHdlBuf = NULL;
    UINTN               AuthHdlBufSize = 0;
    TPMS_AUTH_COMMAND   AuthSession;

    SetMem( &AuthSession, sizeof(AuthSession), 0);

    do
    {
        // We only support the Password Auth.
        if (0 != AuthWay)
        {
            if (Aux_AuthByPws != AuthWay)
            {
                Status = EFI_INVALID_PARAMETER;
                SPrintf(L"Only support -AuthByPws\n\r");
                break;
            }

            if( NULL != AuthHdlFile1 && WStrlen(AuthHdlFile1) )
            {
                Status = OpenShellFile( AuthHdlFile1, &pAuthHdlBuf, &AuthHdlBufSize );
                if (EFI_ERROR (Status))
                {
                    SPrintf(L"Failed to Open File [%s]\n\r", AuthHdlFile1 );
                    break;
                }

                if( AuthHdlBufSize > SHA256_DIGEST_SIZE )
                {
                    Status = EFI_INVALID_PARAMETER;
                    SPrintf(L"File [%s] size is large 0x%x\n\r", AuthHdlFile1, SHA256_DIGEST_SIZE );
                    break;
                }
            }
        }
    } while (FALSE);

    if (EFI_ERROR (Status))
    {
        return Status;
    }

    // Process the Pws Handle session
    if( Aux_AuthByPws == AuthWay || 0 == AuthWay )
    {
        do
        {
            if( pAuthHdlBuf )
            {
                AuthSession.sessionHandle = TPM_RS_PW;
                AuthSession.hmac.size = (UINT16)AuthHdlBufSize;
                CopyMem (AuthSession.hmac.buffer, pAuthHdlBuf, (UINTN)AuthSession.hmac.size);
            }
            //            Status = Tpm2NvUndefineSpace( TPM_RH_PLATFORM, paramNVIdx.u32 , NULL );
            Status = Tpm2NvUndefineSpace(
                            AuthHandle1,
                            NvIndex,
                            NULL == pAuthHdlBuf ? NULL : &AuthSession
                            );

            if (EFI_ERROR (Status))
            {
                SPrintf(L"Fail on Tpm2NvUndefineSpace(...) - 0x%x\n\r", Status );
                break;
            }
        } while (FALSE);
    }

    return Status;
}

EFI_STATUS ShellTpm20ReadNvIndex(
    UINT32  NvIndex,
    UINT32  AuthWay,
    UINT32  AuthHandle1,
    CHAR16* AuthHdlFile1,
    CHAR16* OutFile
)
{
    EFI_STATUS          Status = EFI_SUCCESS;
    UINT8               *pAuthHdlBuf = NULL;
    UINTN               AuthHdlBufSize = 0;
    TPM2B_MAX_BUFFER    Buffer;
    TPMS_AUTH_COMMAND   AuthSession;
    TPM2B_NV_PUBLIC     NvPublic;
    TPM2B_NAME          NvName;

    SetMem( &Buffer, sizeof(Buffer), 0);
    SetMem( &AuthSession, sizeof(AuthSession), 0);
    SetMem( &NvPublic, sizeof(NvPublic), 0);
    SetMem( &NvName, sizeof(NvName), 0);

    // Check the Input Parameter and process
    do
    {
        // We only support the Password Auth.
        if (0 != AuthWay)
        {
            if (Aux_AuthByPws != AuthWay )
            {
                Status = EFI_INVALID_PARAMETER;
                SPrintf(L"Only support -AuthByPws\n\r");
                break;
            }

            if( NULL != AuthHdlFile1 && WStrlen(AuthHdlFile1) )
            {
                Status = OpenShellFile( AuthHdlFile1, &pAuthHdlBuf, &AuthHdlBufSize );
                if (EFI_ERROR (Status))
                {
                    SPrintf(L"Failed to Open File [%s]\n\r", AuthHdlFile1 );
                    break;
                }

                if( AuthHdlBufSize > SHA256_DIGEST_SIZE )
                {
                    Status = EFI_INVALID_PARAMETER;
                    SPrintf(L"File [%s] size is large 0x%x\n\r", AuthHdlFile1, SHA256_DIGEST_SIZE );
                    break;
                }
            }
        }

        Status = Tpm2NvReadPublic( NvIndex, &NvPublic, &NvName );
        if (EFI_ERROR (Status))
        {
            SPrintf(L"Fail on Tpm2NvReadPublic(...) - 0x%x\n\r", Status );
            break;
        }

    } while (FALSE);

    if (EFI_ERROR (Status))
    {
        return Status;
    }

    // Process the Pws Handle session
    if( Aux_AuthByPws == AuthWay || 0 == AuthWay )
    {
        do
        {
            if( pAuthHdlBuf )
            {
                AuthSession.sessionHandle = TPM_RS_PW;
                AuthSession.hmac.size = (UINT16)AuthHdlBufSize;
                CopyMem (AuthSession.hmac.buffer, pAuthHdlBuf, (UINTN)AuthSession.hmac.size);
            }

            Status = Tpm2NvRead(
                            AuthHandle1,
                            NvIndex,
                            NULL == pAuthHdlBuf ? NULL : &AuthSession,
                            NvPublic.nvPublic.dataSize,
                            0,
                            &Buffer
                            );

            if (EFI_ERROR (Status))
            {
                SPrintf(L"Fail on Tpm2NvRead(...) - 0x%x\n\r", Status );
                break;
            }
        } while (FALSE);
    }

    if (!EFI_ERROR (Status))
    {
        SPrintBufToCon( (UINTN)Buffer.size, Buffer.buffer );
    }

    if( NULL != OutFile && WStrlen(OutFile) )
    {
        Status = OuputShellFile (OutFile, (UINTN)Buffer.size, Buffer.buffer );
        if (EFI_ERROR (Status))
        {
            SPrintf(L"Fail on WriteFile[%s] - 0x%x\n\r", OutFile, Status );
        }
    }

    return Status;
}

EFI_STATUS ShellTpm20DefineSpae(
    UINT32  NvIndex,
    UINT32  NvSize,
    UINT32  NvAttr,
    UINT16  AuthWay,
    UINT16  HashAlg,
    UINT32  AuthHandle1,
    CHAR16* AuthHdlFile1,
    CHAR16* NvAuthFile
)
{
    EFI_STATUS      Status = EFI_SUCCESS;
    UINT8           *pNvAuthFileBuf = NULL;
    UINTN           NvAuthFileBufSize = 0;
    UINT8           *pAuthHdlBuf = NULL;
    UINTN           AuthHdlBufSize = 0;
    UINT32              unTmpVal = 0;
    TPMS_AUTH_COMMAND   AuthSession;
    TPM2B_NV_PUBLIC     NvPublic;
    TPM2B_AUTH          NvAuthVal;

    SetMem (&NvPublic, sizeof(NvPublic), 0);
    SetMem (&AuthSession, sizeof(AuthSession), 0);
    SetMem (&NvAuthVal, sizeof(NvAuthVal), 0);

    // Check the Input Parameter
    do
    {
        // We only support the Password Auth.
        if (0 != AuthWay)
        {
            if (Aux_AuthByPws != AuthWay)
            {
                Status = EFI_INVALID_PARAMETER;
                SPrintf(L"DefineSpace only support -AuthByPws\n\r");
                break;
            }

        }

        // Check the Handle must be TPM_RH_OWNER or TPM_RH_PLATFORM
        if ( AuthHandle1 != TPM_RH_OWNER && AuthHandle1 != TPM_RH_PLATFORM )
        {
            SPrintf(L"Auth handle must be TPM_RH_OWNER or TPM_RH_PLATFORM\n\r");
            Status = EFI_INVALID_PARAMETER;
            break;
        }
        // The NV Attribute must not be 0
        if( 0 == NvAttr )
        {
            SPrintf(L"Error define NvIndex attribute\n\r");
            Status = EFI_INVALID_PARAMETER;
            break;
        }

        if( 0 == NvSize)
        {
            Status = EFI_INVALID_PARAMETER;
            SPrintf(L"Error define NvIndex Size\n\r");
            break;
        }

        if( TPM_ALG_SHA256 != HashAlg && TPM_ALG_SHA1 != HashAlg )
        {
            Status = EFI_INVALID_PARAMETER;
            SPrintf(L"Error define Hash Alg (-Sha1 or -Sha256).\n\r");
            break;
        }
    } while (FALSE);

    if (EFI_ERROR (Status))
    {
        return Status;
    }

    do
    {
        if( NULL != AuthHdlFile1 && WStrlen(AuthHdlFile1) )
        {
            Status = OpenShellFile( AuthHdlFile1, &pAuthHdlBuf, &AuthHdlBufSize );
            if (EFI_ERROR (Status))
            {
                SPrintf(L"Failed to Open File [%s]\n\r", AuthHdlFile1 );
                break;
            }

            if( AuthHdlBufSize > SHA256_DIGEST_SIZE )
            {
                Status = EFI_INVALID_PARAMETER;
                SPrintf(L"File [%s] size is large 0x%x\n\r", AuthHdlFile1, SHA256_DIGEST_SIZE );
                break;
            }
        }

        if( NULL != NvAuthFile && WStrlen(NvAuthFile) )
        {
            Status = OpenShellFile( NvAuthFile, &pNvAuthFileBuf, &NvAuthFileBufSize );
            if (EFI_ERROR (Status))
            {
                SPrintf(L"Failed to Open File [%s]\n\r", NvAuthFile );
                break;
            }

            if( AuthHdlBufSize > SHA256_DIGEST_SIZE )
            {
                Status = EFI_INVALID_PARAMETER;
                SPrintf(L"File [%s] size is large 0x%x\n\r", NvAuthFile, SHA256_DIGEST_SIZE );
                break;
            }
        }

        if( pAuthHdlBuf )
        {
            AuthSession.sessionHandle = TPM_RS_PW;
            AuthSession.hmac.size = (UINT16)AuthHdlBufSize;
            CopyMem (AuthSession.hmac.buffer, pAuthHdlBuf, (UINTN)AuthSession.hmac.size);
        }

        if( pNvAuthFileBuf )
        {
            NvAuthVal.size = (UINT16)NvAuthFileBufSize;
            CopyMem (NvAuthVal.buffer, pNvAuthFileBuf, (UINTN)NvAuthVal.size);
        }

        NvPublic.nvPublic.attributes    = *(TPMA_NV*)&NvAttr;
        NvPublic.nvPublic.dataSize      = (UINT16)NvSize;
        NvPublic.nvPublic.nameAlg       = HashAlg;
        NvPublic.nvPublic.nvIndex       = NvIndex;

        unTmpVal =
                    sizeof(NvPublic.nvPublic.nvIndex) +
                    sizeof(NvPublic.nvPublic.nameAlg) +
                    sizeof(NvPublic.nvPublic.attributes) +
                    sizeof(NvPublic.nvPublic.authPolicy.size) +
                    NvPublic.nvPublic.authPolicy.size +
                    sizeof(NvPublic.nvPublic.dataSize);
        NvPublic.size = (UINT16)unTmpVal;

        PrintBufMixChar (sizeof(NvPublic), (UINT8*)&NvPublic);

        Status = Tpm2NvDefineSpace(
                            AuthHandle1,
                            pAuthHdlBuf ? &AuthSession : NULL,
                            &NvAuthVal,
                            &NvPublic
                            );
        if (EFI_ERROR (Status))
        {
            SPrintf(L"Error Tpm2NvDefineSpace(...). 0x%x\n\r", Status );
            break;
        }

    } while (FALSE);

    if (pNvAuthFileBuf)
    {
        pBS->FreePool (pNvAuthFileBuf);
        pNvAuthFileBuf = NULL;
    }

    if (pAuthHdlBuf)
    {
        pBS->FreePool (pAuthHdlBuf);
        pAuthHdlBuf = NULL;
    }

    return Status;
}

EFI_STATUS ShowTpm20NvPublic(
    UINT32      un32Index
)
{
    EFI_STATUS                      Status;
    TPM2B_NV_PUBLIC                 NvPublic;
    TPM2B_NAME                      NvName;

    do
    {
        Status = Tpm2NvReadPublic( un32Index, &NvPublic, &NvName );
        SPrintf(L"  Tpm2NvReadPublic(NvIdx[0x%08x]) -%r\n\r", un32Index, Status);
        if( EFI_ERROR(Status) )
        {
            break;
        }

        SPrintf(L"    nvIndex               [%08x].\r\n", (UINTN)NvPublic.nvPublic.nvIndex );
        SPrintf(L"    nameAlg               [%04x].\r\n", (UINTN)NvPublic.nvPublic.nameAlg );
        SPrintf(L"    attributes            [%08x].\r\n", (UINTN)(*(UINT32*)(&NvPublic.nvPublic.attributes)) );
        SPrintf(L"      TPMA_NV_PPWRITE         [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_PPWRITE ? 1 : 0 );
        SPrintf(L"      TPMA_NV_OWNERWRITE      [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_OWNERWRITE ? 1 : 0 );
        SPrintf(L"      TPMA_NV_AUTHWRITE       [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_AUTHWRITE ? 1 : 0 );
        SPrintf(L"      TPMA_NV_POLICYWRITE     [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_POLICYWRITE ? 1 : 0 );
        SPrintf(L"      TPMA_NV_COUNTER         [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_COUNTER ? 1 : 0 );
        SPrintf(L"      TPMA_NV_BITS            [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_BITS ? 1 : 0 );
        SPrintf(L"      TPMA_NV_EXTEND          [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_EXTEND ? 1 : 0 );
        SPrintf(L"      TPMA_NV_POLICY_DELETE   [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_POLICY_DELETE ? 1 : 0 );
        SPrintf(L"      TPMA_NV_WRITELOCKED     [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_WRITELOCKED ? 1 : 0 );
        SPrintf(L"      TPMA_NV_WRITEALL        [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_WRITEALL ? 1 : 0 );
        SPrintf(L"      TPMA_NV_WRITEDEFINE     [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_WRITEDEFINE ? 1 : 0 );
        SPrintf(L"      TPMA_NV_WRITE_STCLEAR   [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_WRITE_STCLEAR ? 1 : 0 );
        SPrintf(L"      TPMA_NV_GLOBALLOCK      [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_GLOBALLOCK ? 1 : 0 );
        SPrintf(L"      TPMA_NV_PPREAD          [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_PPREAD ? 1 : 0 );
        SPrintf(L"      TPMA_NV_OWNERREAD       [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_OWNERREAD ? 1 : 0 );
        SPrintf(L"      TPMA_NV_AUTHREAD        [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_AUTHREAD ? 1 : 0 );
        SPrintf(L"      TPMA_NV_POLICYREAD      [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_POLICYREAD ? 1 : 0 );
        SPrintf(L"      TPMA_NV_NO_DA           [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_NO_DA ? 1 : 0 );
        SPrintf(L"      TPMA_NV_ORDERLY         [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_ORDERLY ? 1 : 0 );
        SPrintf(L"      TPMA_NV_CLEAR_STCLEAR   [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_CLEAR_STCLEAR ? 1 : 0 );
        SPrintf(L"      TPMA_NV_READLOCKED      [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_READLOCKED ? 1 : 0 );
        SPrintf(L"      TPMA_NV_WRITTEN         [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_WRITTEN ? 1 : 0 );
        SPrintf(L"      TPMA_NV_WRITEALL        [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_WRITEALL ? 1 : 0 );
        SPrintf(L"      TPMA_NV_PLATFORMCREATE  [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_PLATFORMCREATE ? 1 : 0 );
        SPrintf(L"      TPMA_NV_READ_STCLEAR    [%02x].\r\n", NvPublic.nvPublic.attributes.TPMA_NV_READ_STCLEAR ? 1 : 0 );
        SPrintf(L"    authPolicy.size       [%04x].", (UINTN)NvPublic.nvPublic.authPolicy.size );
        if( NvPublic.nvPublic.authPolicy.size )
        {
            SPrintBufToCon( (UINT32)NvPublic.nvPublic.authPolicy.size, NvPublic.nvPublic.authPolicy.buffer );
        }
        else
        {
            SPrintf(L"\r\n");
        }

        SPrintf(L"    dataSize              [%04x].\r\n", (UINTN)NvPublic.nvPublic.dataSize );

    } while( FALSE );

    return Status;
}

EFI_STATUS ShowPlatformHierarchyProperty()
{
    EFI_STATUS              Status;
    TPMS_CAPABILITY_DATA    TpmCap;
    TPMI_YES_NO             MoreData;
    TPMA_STARTUP_CLEAR      AttrStartup;

    Status = Tpm2GetCapability(
                TPM_CAP_TPM_PROPERTIES,
                TPM_PT_STARTUP_CLEAR,
                1,
                &MoreData,
                &TpmCap
                );
    SPrintf(L"  Tpm2GetCapability(CAP_TPM_PROPERTIES, PT_STARTUP_CLEAR) -%r\n\r", Status);
    if( !EFI_ERROR(Status) )
    {
        *(UINT32*)&AttrStartup = SwapBytes32( *(UINT32*)&TpmCap.data.tpmProperties.tpmProperty[0].value );
        SPrintf(L"    Platform hierarchy    [%02x].\r\n", AttrStartup.phEnable ? 1 : 0 );
        SPrintf(L"    Storage hierarchy     [%02x].\r\n", AttrStartup.shEnable ? 1 : 0 );
        SPrintf(L"    Endorsement hierarchy [%02x].\r\n", AttrStartup.ehEnable ? 1 : 0 );
    }

    return Status;
}

struct
{
    UINT32  ManufactureId;
    CHAR16* str;
} VenderID[] = {
        {   0x414d4400,     L"AMD(fTPM)" },
        {   0x41544d4c,     L"Atmel"     },
        {   0x4252434d,     L"Broadcom"  },
        {   0x49424d00,     L"IBM"       },
        {   0x49465800,     L"Infineon"  },
        {   0x494e5443,     L"Intel(fTPM)"   },
        {   0x4c454e00,     L"Lenovo"    },
        {   0x4e534d20,     L"National Semi" },
        {   0x4e545a00,     L"Nationz"   },
        {   0x4e544300,     L"Nuvoton Technology"    },
        {   0x51434f4d,     L"Qualcomm"  },
        {   0x534d5343,     L"SMSC"      },
        {   0x53544d20,     L"STMicroelectronics"    },
        {   0x534d534e,     L"Samsung"   },
        {   0x534e5300,     L"Sinosun"   },
        {   0x54584e00,     L"Texas Instruments" },
        {   0x57454300,     L"Winbond"   },
        {   0x524f4343,     L"Fuzhou Rockchip"   }
};

EFI_STATUS ShowTpmVenderVersion()
{
    EFI_STATUS                      Status;
    UINT32                          ManufactureId = 0;
    UINT32                          FirmwareVersion1 = 0;
    UINT32                          FirmwareVersion2 = 0;
    UINT32                          TpmRevision = 0;
    UINTN                           unIdx;
    UINT8                           *u8Version;

    do
    {
        Status = Tpm2GetCapabilityManufactureID( &ManufactureId );
        SPrintf(L"  Tpm2GetCapabilityManufactureID -%r\n\r", Status);
        if( EFI_ERROR(Status) ) break;

        Status = Tpm2GetCapabilityFirmwareVersion( &FirmwareVersion1, &FirmwareVersion2);
        SPrintf(L"  Tpm2GetCapabilityFirmwareVersion -%r\n\r", Status);
        if( EFI_ERROR(Status) ) break;

        Status = Tpm2GetCapabilityTpmRevision( &TpmRevision );
        SPrintf(L"  Tpm2GetCapabilityTpmRevision -%r\n\r", Status);
        if( EFI_ERROR(Status) ) break;

        for( unIdx = 0; unIdx < sizeof(VenderID)/sizeof(VenderID[0]); ++unIdx)
        {
            if( ManufactureId == VenderID[unIdx].ManufactureId )
            {
                SPrintf(L"  ManufactureId[0x%08x]:    %s\n\r", VenderID[unIdx].ManufactureId, VenderID[unIdx].str);
                break;
            }
        }
        if( unIdx == sizeof(VenderID)/sizeof(VenderID[0]) )
        {
            SPrintf(L"  ManufactureId[0x%08x]\n\r", ManufactureId );
        }

        u8Version = (UINT8*)&FirmwareVersion1;
        SPrintf(L"  FirmwareVersion1[0x%08x]: %02d.%02d.%02d.%02d \n\r",
                        FirmwareVersion1, u8Version[3], u8Version[2], u8Version[1], u8Version[0] );

        u8Version = (UINT8*)&FirmwareVersion2;
        SPrintf(L"  FirmwareVersion2[0x%08x]: %02d.%02d.%02d.%02d \n\r",
                        FirmwareVersion2,  u8Version[3], u8Version[2], u8Version[1], u8Version[0] );

        u8Version = (UINT8*)&TpmRevision;
        SPrintf(L"  TpmRevision[0x%08x]:      %02d.%02d.%02d.%02d \n\r",
                        TpmRevision,  u8Version[3], u8Version[2], u8Version[1], u8Version[0] );
    } while( FALSE );

    return Status;
}
