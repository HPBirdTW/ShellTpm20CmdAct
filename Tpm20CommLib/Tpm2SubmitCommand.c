
#include <EFI.h>
#include <AmiDxeLib.h>
#include "Tpm2CommLib.h"

#define TPM_Command_DBG 0

#pragma pack (push)
#pragma pack (1)

typedef struct _TPM_1_2_CMD_HEADER
{
    UINT16          Tag;
    UINT32          ParamSize;
    UINT32          Ordinal;
} TPM_1_2_CMD_HEADER;

typedef struct _TPM_1_2_RET_HEADER
{
    UINT16          Tag;
    UINT32          ParamSize;
    UINT32          RetCode;
} TPM_1_2_RET_HEADER;

#pragma pack (pop)

#define EFI_TREE_PROTOCOL_GUID \
    {0x607f766c, 0x7455, 0x42be, 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f}

typedef
EFI_STATUS
(EFIAPI * EFI_TPM_PASS_THROUGH_TO_TPM)(
    IN VOID             *This,
    IN UINT32           TpmInputParamterBlockSize,
    IN UINT8            *TpmInputParamterBlock,
    IN UINT32           TpmOutputParameterBlockSize,
    IN UINT8            *TpmOutputParameterBlock
);

typedef struct _EFI_TPMx_PROTOCOL
{
    VOID                            *Dummy1;
    VOID                            *Dummy2;
    VOID                            *Dummy3;
    EFI_TPM_PASS_THROUGH_TO_TPM     PassThroughToTpm12_20;
    VOID*                           Dummy5;
} EFI_TPMx_PROTOCOL;

UINT32  u32LastTpmErr = 0;
UINTN   unLastTpmCmdSize=0;
UINT8   pLastTpmCmd[MAX_COMMAND_SIZE];
UINTN   unLastTpmRspSize=0;
UINT8   pLastTpmRsp[MAX_RESPONSE_SIZE];

TPM2_SUB_CMD_CALLBACK Tpm2SubCmdExternCallBack = NULL;

extern BOOLEAN                  UseTpmHwLib;

EFI_STATUS
EFIAPI
Tpm2SubmitCommand (
    IN  UINT32              InputParameterBlockSize,
    IN  UINT8               *InputParameterBlock,
    IN  OUT UINT32          *OutputParameterBlockSize,
    IN  UINT8               *OutputParameterBlock
)
{
    EFI_STATUS                  Status = EFI_SUCCESS;
    EFI_TPMx_PROTOCOL           *TpmXProtocol = NULL;
    EFI_GUID                    gEfiTrEEProtocolGuid = EFI_TREE_PROTOCOL_GUID;
//    TPM_1_2_RET_HEADER          *pRetHdr = NULL;
    TPM_OEM_SUBMIT_CMD_PROTOCOL *OemTpmSubmitCmdProtocol = NULL;
    EFI_GUID                    OemTpmSumbitCmdGuid = TPM_OEM_SUBMIT_COMMAND_GUID;
    UINT32                      u32TmpVal;

#if defined(TPM_Command_DBG) && TPM_Command_DBG
    {
        TPM_1_2_CMD_HEADER      *pTpmCommonHdr = (TPM_1_2_CMD_HEADER*)InputParameterBlock;

        DEBUG(( DEBUG_INFO, "TPM Command Buffer:" ));
        PrintBufMixChar( SwapBytes32(pTpmCommonHdr->ParamSize), InputParameterBlock );
    }
#endif

    u32TmpVal = SwapBytes32 (((TPM_1_2_CMD_HEADER*)InputParameterBlock)->ParamSize);
    CopyMem( pLastTpmCmd, InputParameterBlock, u32TmpVal );
    unLastTpmCmdSize = (UINTN)u32TmpVal;

    do
    {
        if (TRUE == UseTpmHwLib)
        {
            EFI_STATUS IsTpmTis (
                UINTN               TpmReg
            );
            EFI_STATUS IsTpmCrb (
                UINTN               TpmReg
            );

//            SMDbgPrint("Use TPM20 HW Library\n");
            Status = IsTpmTis (0xFED40000);
            if (!EFI_ERROR (Status))
            {
                EFI_STATUS
                TpmTisSubmitCommand (
                    IN VOID*          This,
                    IN UINT32         InputParameterBlockSize,
                    IN UINT8          *InputParameterBlock,
                    IN UINT32         OutputParameterBlockSize,
                    IN UINT8          *OutputParameterBlock
                );
                Status = TpmTisSubmitCommand (
                                    NULL,
                                    InputParameterBlockSize,
                                    InputParameterBlock,
                                    *OutputParameterBlockSize,
                                    OutputParameterBlock
                                    );
                break;
            }

            Status = IsTpmCrb (0xFED40000);
            if (!EFI_ERROR (Status))
            {
                EFI_STATUS
                EFIAPI
                TpmPTPSubmitCommand(
                  IN VOID*          This,
                  IN UINT32         InputParameterBlockSize,
                  IN UINT8          *InputParameterBlock,
                  IN UINT32         OutputParameterBlockSize,
                  IN UINT8          *OutputParameterBlock
                  );

                Status = TpmPTPSubmitCommand (
                                    NULL,
                                    InputParameterBlockSize,
                                    InputParameterBlock,
                                    *OutputParameterBlockSize,
                                    OutputParameterBlock
                                    );
                break;
            }
            break;
        }

        Status = pBS->LocateProtocol( &gEfiTrEEProtocolGuid, NULL, &TpmXProtocol);
        if( !EFI_ERROR(Status) )
        {
            Status = TpmXProtocol->PassThroughToTpm12_20(
                                TpmXProtocol,
                                InputParameterBlockSize,
                                InputParameterBlock,
                                *OutputParameterBlockSize,
                                OutputParameterBlock );
            break;
        }

        Status = pBS->LocateProtocol (&OemTpmSumbitCmdGuid, NULL, (VOID **) &OemTpmSubmitCmdProtocol);
        if( !EFI_ERROR(Status) )
        {
            Status = OemTpmSubmitCmdProtocol->SubmitCommand(
                                OemTpmSubmitCmdProtocol,
                                InputParameterBlockSize,
                                InputParameterBlock,
                                *OutputParameterBlockSize,
                                OutputParameterBlock );
            break;
        }

        Status = EFI_DEVICE_ERROR;
        break;

    } while( FALSE );

    do
    {
        if( EFI_ERROR(Status) )
        {
            DEBUG(( DEBUG_INFO, "TPMx Transcat/Communicate Err - %r", Status));
            break;
        }

        *OutputParameterBlockSize = SwapBytes32( ((TPM_1_2_RET_HEADER *)OutputParameterBlock)->ParamSize );
    } while(FALSE);

#if defined(TPM_Command_DBG) && TPM_Command_DBG
    {
        TPM_1_2_CMD_HEADER      *pTpmCommonHdr = (TPM_1_2_CMD_HEADER*)OutputParameterBlock;

        if( EFI_ERROR(Status) )
        {
            DEBUG(( DEBUG_INFO, "TPM Execute Command Err - %r", Status));
            return Status;
        }

        DEBUG(( DEBUG_INFO, "TPM Response Buffer:" ));
        PrintBufMixChar( SwapBytes32(pTpmCommonHdr->ParamSize), OutputParameterBlock );
    }
#endif

    u32TmpVal = SwapBytes32 ( ((TPM_1_2_RET_HEADER *)OutputParameterBlock)->ParamSize );

    CopyMem( pLastTpmRsp, OutputParameterBlock, u32TmpVal );
    unLastTpmRspSize = (UINTN)u32TmpVal;

    if( Tpm2SubCmdExternCallBack )
    {
        (*Tpm2SubCmdExternCallBack)();
    }

    return Status;
}
