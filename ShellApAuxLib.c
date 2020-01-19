#include <EFI.h>
#include <AmiLib.h>
#include <AmiDxeLib.h>
#include <Token.h>
#include <Protocol/SimpleTextOut.h>
#include "Protocol/SimpleTextIn.h"
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/DevicePath.h>
#include "ShellEnv.h"
#include "ShellTpm20CmdAct.h"

#define         StrBufLen 0x100
CHAR16          u16StrBuf[StrBufLen];

COMMAND_INPUT           Tpm20SuType;
COMMAND_INPUT           paramHashAlgBitMap;
COMMAND_INPUT           paramOpenFile;
COMMAND_INPUT           paramSelPcrIdx;
COMMAND_INPUT           paramNVIdx;
COMMAND_INPUT           paramOpenAuthFile;
COMMAND_INPUT           paramOpenAuthHdlFile1;
COMMAND_INPUT           paramDefNvAttr;
COMMAND_INPUT           paramSize;
COMMAND_INPUT           paramOutFile;
COMMAND_INPUT           paramInFile;
COMMAND_INPUT           paramAuthHandle1;
COMMAND_INPUT           paramSessionAuthWay;
COMMAND_INPUT           paramAuthHashAlg;

EFI_GUID                            ShellInterfaceProtocol = SHELL_INTERFACE_PROTOCOL;
EFI_SHELL_INTERFACE                 *SI = NULL;
EFI_GUID                            ShellInterfaceProtocol2 = EFI_SHELL_PARAMETERS_PROTOCOL_GUID;
EFI_SHELL_PARAMETERS_PROTOCOL       *SI2 = NULL;
//EFI_GUID                            Shell2ProtcolGuid = EFI_SHELL_PROTOCOL_GUID;
//EFI_SHELL_PROTOCOL                  *Shell2Protocol = NULL;
EFI_LOADED_IMAGE_PROTOCOL           *ImageProtocol = NULL;
EFI_GUID                            ImageProtocolGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;

BOOLEAN                             UseTpmHwLib = FALSE;


enSHELL_ACTION_ITEM     CmdActItem;
UINTN                   CmdActItemCount = 0;

CONST   stCommandSet    CommandSet[] = \
{
    // Command Input
    {   Act_showHelp,           L"-help"                },
    {   Act_showHelp,           L"-h"                   },
    {   Act_Startup,            L"-startUp"             },
    {   Act_Shutdown,           L"-shutDown"            },
    {   Act_GetNVList,          L"-getNvList"           },
    {   Act_GetNvPublic,        L"-readNvPublic"        },
    {   Act_DefineSpace,        L"-defineSpace"         },
    {   Act_DelNVIndex,         L"-delNvIndex"          },
    {   Act_ReadNvIndex,        L"-readNvIndex"         },
    {   Act_WriteNvIndex,       L"-writeNvIndex"        },
    {   Act_CapVndr,            L"-capVndr"             },
    {   Act_CapPhProperty,      L"-phCap"               },
    {   Act_PermanentProperty,  L"-permanentCap"        },
    {   Act_GetPcrCap,          L"-getPcrCap"           },
    {   Act_ReadPcr,            L"-readPcr"             },
    {   Act_SetPcrBank,         L"-setPcrBank"          },
    {   Act_ExeCmdFile,         L"-exeCmdFile"          },
    {   Act_ExeCmdFileHelp,     L"-exeCmdFileHelp"      },
    {   Act_ShowTpmNvHelp,      L"-showNvHelp"       	},
    {   Act_TpmFmpFwVer,        L"-getFmpFwVer"        },

    // AuxCmd Param
    {   Aux_Tpm20StartupSuClear,    L"SU_CLEAR"                 },
    {   Aux_Tpm20StartupSuState,    L"SU_STATE"                 },
    // NV Attribute
    {   Aux_NvPpWrite,          L"NvPpWrite"            },
    {   Aux_NvOwnerWrite,       L"NvOwnerWrite"         },
    {   Aux_NvAuthWrite,        L"NvAuthWrite"          },
    {   Aux_NvPolicyWrite,      L"NvPolicyWrite"        },
    {   Aux_NvCounter,          L"NvCounter"            },
    {   Aux_NvBits,             L"NvBits"               },
    {   Aux_NvExtend,           L"NvExtend"             },
    {   Aux_NvPolicyDelete,     L"NvPolicyDelete"       },
    {   Aux_NvWriteLocked,      L"NvWriteLocked"        },
    {   Aux_NvWriteAll,         L"NvWriteAll"           },
    {   Aux_NvWriteDefine,      L"NvWriteDefine"        },
    {   Aux_NvWriteStClear,     L"NvWriteStClear"       },
    {   Aux_NvGlobalLock,       L"NvGlobalLock"         },
    {   Aux_NvPpRead,           L"NvPpRead"             },
    {   Aux_NvOwnerRead,        L"NvOwnerRead"          },
    {   Aux_NvAuthRead,         L"NvAuthRead"           },
    {   Aux_NvPolicyRead,       L"NvPolicyRead"         },
    {   Aux_NvNoDa,             L"NvNoDa"               },
    {   Aux_NvOrderly,          L"NvOrderly"            },
    {   Aux_NvClearStclear,     L"NvClearStclear"       },
    {   Aux_NvReadLocked,       L"NvReadLocked"         },
    {   Aux_NvWritten,          L"NvWritten"            },
    {   Aux_NvPlatformCreate,   L"NvPlatformCreate"     },
    {   Aux_NvReadStclear,      L"NvReadStclear"        },

    {   Aux_AuthFile,               L"-AuthFile"                },
    {   Aux_AuthHandle1,            L"-AuthHandle1"             },
    {   Aux_AuthHandleFile1,        L"-AuthHdlFile1"            },
    {   Aux_AuthByPws,              L"-AuthByPws"               },
    {   Aux_AuthByHmac,             L"-AuthByHmac"              },
    {   Aux_AuthHashSha1,           L"-Sha1"                    },
    {   Aux_AuthHashSha256,         L"-Sha256"                  },
    {   Aux_Tpm20Size,              L"-Size"                    },
    {   Aux_OutputFile,             L"-OutFile"                 },
    {   Aux_InputFile,              L"-InFile"                  },
    {   Aux_TpmHwLib,               L"-tpmHwLib"                },
    {   Aux_showTpmCmd,             L"-showTpmCmd"              },
};

CONST CHAR16*   cnHelpMsg[] = \
{
    L"============================================================================\n\r",
    L"ShellTpm20CmdAct.efi [CommandAct]              Ver: 0.12, Done by HPBirdChen\n\r",
    L"[Caution]: All input is case sensitive                                    \n\r",
    L"CommandAct:                                                               \n\r",
    L"  -startUp            Execute TPM20 Startup, [SU_CLEAR / SU_STATE]        \n\r",
    L"      ShellTpm20CmdAct.efi -startUp SU_CLEAR, TPM2_Startup(SU_CLEAR)      \n\r",
    L"  -shutDown           Execute TPM20 Shutdown, [SU_CLEAR / SU_STATE]       \n\r",
    L"  -capVndr            Show the TPM20 Chip Info                            \n\r",
    L"  -phCap              Show TPM20 Platform Hierarchy Enable/Disable status:\n\r",
    L"  -permanentCap       Show TPM20 Permanent flag.(ownerAuthSet, inLockout,..)\n\r",
    L"  -getPcrCap          Show TPM20 PCR Support/Activate Banks.              \n\r",
    L"  -setPcrBank         Set TPM20 PCR Banks Bitmap [4..0] Hex               \n\r",
    L"                      Bitmap[4..0]:[SM3, SHA512, SHA384, SHA256, SHA1]    \n\r",
    L"      ShellTpm20CmdAct.efi -setPcrBank 12, Set SHA256+SM3                 \n\r",
    L"  -readPcr            Read PCR Index [Hex] value                          \n\r",
    L"      ShellTpm20CmdAct.efi -readPcr 0, Read PCR[0] value                  \n\r",
    L"  -exeCmdFile         Execute the ASCII Command File                      \n\r",
    L"      ShellTpm20CmdAct.efi -exeCmdFileHelp, Get more File format and Input\n\r",
    L"  -getFmpFwVer        Get the TPM Vender define FMP(ESRT) UINT32 Version  \n\r",
    L"                                                                          \n\r",
    L"  [TPM NVRAM]         Use -showNvHelp to display TPM20 NVRAM Help         \n\r",
    L"  -tpmHwLib           Force communication TPM via Internal HW protocol    \n\r",
    L"  -showTpmCmd:        Show the period TPM Command, this is for Auxiliary  \n\r",
    L"============================================================================\n\r",
};

CONST CHAR16*   cnShowTpm20NvHelp[] = \
{
    L"============================================================================\n\r",
    L"  -getNvList          Show the TPM20 NVList                               \n\r",
    L"  -readNvPublic       Show the TPM20 NVIndex [Hex] Public attribute       \n\r",
    L"      ShellTpm20CmdAct.efi -readNvPublic 01801001                         \n\r",
    L"  -delNvIndex         Delete the indicate NVIndex [Hex]                   \n\r",
    L"      -AuthHandle1    (Optional )Auth Handle, Default is TPM_RH_PLATFORM  \n\r",
    L"                      TPM_RH_PLATFORM or TPM_RH_OWNER                     \n\r",
    L"      -AuthHdlFile1   (Optional), the input of Auth Handle1 Secret File   \n\r",
    L"      Ex 1:                                                               \n\r",
    L"      ShellTpm20CmdAct.efi -delNvIndex 01801001, delete NVIdx [0x1801001] \n\r",
    L"  -defineSpace        Define the NVIndex, [HEX]                           \n\r",
    L"      -Size           NVIndex Size, [Hex]                                 \n\r",
    L"      -AuthHandle1    (Optional )Auth Handle, Default is TPM_RH_PLATFORM  \n\r",
    L"                      Only TPM_RH_PLATFORM or TPM_RH_OWNER                \n\r",
    L"                      TPM_RH_PLATFORM [4000000C], TPM_RH_OWNER [40000001] \n\r",
    L"      -AuthHdlFile1   (Optional), the input of Auth Handle1 Secret File   \n\r",
    L"      [NV Attribute]: NvPpWrite, NvOwnerWrite, NvAuthWrite, NvWriteLocked,\n\r",
    L"                      NvWriteAll, NvWriteDefine, NvWriteStClear,          \n\r",
    L"                      NvGlobalLock, NvPpRead, NvOwnerRead, NvAuthRead,    \n\r",
    L"                      NvNoDa, NvOrderly, NvClearStclear, NvReadLocked,    \n\r",
    L"                      NvWritten, NvPlatformCreate, NvReadStclear          \n\r",
    L"      -[NV Hash Alg]: -Sha1 or -Sha256                                    \n\r",
    L"      -AuthFile       (Optional)Input of NV Define Auth Secret            \n\r",
    L"      Ex 1:                                                               \n\r",
    L"      ShellTpm20CmdAct.efi -defineSpace 01802005 -Size 40 NvAuthWrite     \n\r",
    L"              NvAuthRead NvPlatformCreate NvNoDa NvPpPread NvPpWrite      \n\r",
    L"              -Sha256 -AuthFile NvAuth.bin -showTpmCmd                    \n\r",
    L"      Ex 2:                                                               \n\r",
    L"      ShellTpm20CmdAct.efi -defineSpace 01802006 -Size 40 -Sha256         \n\r",
    L"              NvPlatformCreate NvPpRead NvPpWrite NvNoDa                  \n\r",
    L"  -readNvIndex        Read the TPM NV Index [Hex]                         \n\r",
    L"      -AuthHandle1    (Optional )Auth Handle, Default is TPM_RH_PLATFORM  \n\r",
    L"                      TPM_RH_PLATFORM or TPM_RH_OWNER or [NVIndex]        \n\r",
    L"      -AuthHdlFile1   (Optional), the input of Auth Handle1 Secret File   \n\r",
    L"      -OutFile        (Optional), output the NVIndex data into File       \n\r",
    L"      Ex 1:                                                               \n\r",
    L"      ShellTpm20CmdAct.efi -readNvIndex 01802006                          \n\r",
    L"      Ex 2:                                                               \n\r",
    L"      ShellTpm20CmdAct.efi -readNvIndex 01802005 -AuthHandle1 01802005    \n\r",
    L"              -AuthHdlFile1 NvAuth.bin -OutFile Nv01802005.dat -showTpmCmd\n\r",
    L"  -writeNvIndex       Write Data to TPM NV Index [Hex]                    \n\r",
    L"      -AuthHandle1    (Optional )Auth Handle, Default is TPM_RH_PLATFORM  \n\r",
    L"                      TPM_RH_PLATFORM or TPM_RH_OWNER or [NVIndex]        \n\r",
    L"      -AuthHdlFile1   (Optional), the input of Auth Handle1 Secret File   \n\r",
    L"      -InFile         The Input Write Data, write from NvIndex offset 0   \n\r",
    L"      Ex 1:                                                               \n\r",
    L"      ShellTpm20CmdAct.efi -writeNvIndex 01802005 -AuthHandle1 01802005   \n\r",
    L"              -AuthHdlFile1 NvAuth.bin -InFile Nv2005Data.dat -showTpmCmd \n\r",
    L"      Ex 2:                                                               \n\r",
    L"      ShellTpm20CmdAct.efi -writeNvIndex 01802005 -InFile Nv01802006.dat  \n\r",
    L"============================================================================\n\r",
};

CONST CHAR16*   cnExeCmdFileHelpMsg[] = \
{
    L"============================================================================\n\r",
    L"  Example:                                                                \n\r",
    L"    ShellTpm20CmdAct.efi -exeCmdFile Tpm20Ex.log                          \n\r",
    L"    ShellTpm20CmdAct.efi -exeCmdFile Tpm20Ex.log -showTpmCmd              \n\r",
    L"    ShellTpm20CmdAct.efi -exeCmdFile Tpm20Ex.log -showTpmCmd > Tpm20ExRst.log\n\r",
    L"      it will redirect output console to Tpm20ExRst.log files             \n\r"
    L"                                                                          \n\r",
    L"  File Format:                                                            \n\r",
    L"      #: Starting of the Comment. until to end of line                    \n\r",
    L"      Only accept the byte ascii number, ex: 80 01 ...                    \n\r",
    L"  File example:                                                           \n\r",
    L"  # tag                                                                   \n\r",
    L"  80 01                                                                   \n\r",
    L"  # commandSize                                                           \n\r",
    L"  00 00 00 16                                                             \n\r",
    L"  # commandCode                                                           \n\r",
    L"  00 00 01 7a     #TPM_CC_GetCapability                                   \n\r",
    L"  # capability                                                            \n\r",
    L"  00 00 00 06     #TPM_CAP_TPM_PROPERTIES                                 \n\r",
    L"  # property                                                              \n\r",
    L"  00 00 01 05     #TPM_PT_MANUFACTURER                                    \n\r",
    L"  # propertyCount                                                         \n\r",
    L"  00 00 00 01                                                             \n\r",
    L"                                                                          \n\r",
    L"============================================================================\n\r",
};

EFI_STATUS  PString(CHAR16* _str)
{
    EFI_STATUS  Status = EFI_SUCCESS;
    TRACE(( -1, "%S", u16StrBuf));

    Status =  pST->ConOut->OutputString ( pST->ConOut, _str);

    return Status;
}

VOID BufSPrint( CHAR16 *_buf, CHAR16* _str, ... )
{
    va_list Marker;

    va_start(Marker, _str);
    Swprintf_s_va_list( _buf, StrBufLen*sizeof(CHAR16), _str, Marker );
}

EFI_STATUS SPrintf( CHAR16* _str, ... )
{
    va_list Marker;

    va_start(Marker, _str);
    Swprintf_s_va_list( u16StrBuf, StrBufLen*sizeof(CHAR16), _str, Marker );

    return PString( u16StrBuf );
}

VOID SPrintBufToCon(
    UINTN   unBufSize,
    UINT8*  _buf
)
{
    UINTN   unIdx;
    for( unIdx = 0; unIdx<unBufSize; ++unIdx )
    {
        if( unIdx % 0x10 == 0 )
            SPrintf( L"\n\r" );

        SPrintf( L" %02x", (UINTN)_buf[unIdx] );
    }


    SPrintf( L"\n\r" );
}

VOID PrintTpmCmdCallBack()
{
    if( unLastTpmCmdSize )
    {
        SPrintf( L"TPM Command Buffer:" );
        SPrintBufToCon( unLastTpmCmdSize, pLastTpmCmd );
        SPrintf( L"TPM Response Buffer:" );
        SPrintBufToCon( unLastTpmRspSize, pLastTpmRsp );
    }
}

EFI_STATUS  GetCmdAction(
    CHAR16*                 IdentifyCmd,
    enSHELL_ACTION_ITEM     *enCmdActItem
)
{
    EFI_STATUS      Status = EFI_NOT_FOUND;
    UINTN           unIdx;

    for( unIdx = 0; unIdx < sizeof(CommandSet)/sizeof(CommandSet[0]); ++unIdx )
    {
        if( 0 == StrCmp( CommandSet[unIdx].ActStr, IdentifyCmd ) )
        {
            *enCmdActItem = CommandSet[unIdx].ActItem;
            TRACE(( -1, "[%d]: find the command code %S:[%x]\n", __LINE__, \
                         CommandSet[unIdx].ActStr, CommandSet[unIdx].ActItem));
            Status = EFI_SUCCESS;
            break;
        }
    }

    return Status;
}

EFI_STATUS InitParamUnion()
{
    SetMem( &Tpm20SuType, sizeof(Tpm20SuType), 0 );
    SetMem( &paramHashAlgBitMap, sizeof(paramHashAlgBitMap), 0 );
    SetMem( &paramOpenFile, sizeof(paramOpenFile), 0 );
    SetMem( &paramSelPcrIdx, sizeof(paramSelPcrIdx), 0 );
    SetMem( &paramNVIdx, sizeof(paramNVIdx), 0 );
    SetMem( &paramOpenAuthFile, sizeof(paramOpenAuthFile), 0 );
    SetMem( &paramOpenAuthHdlFile1, sizeof(paramOpenAuthHdlFile1), 0);
    SetMem( &paramDefNvAttr, sizeof(paramDefNvAttr), 0 );
    SetMem( &paramSize, sizeof(paramSize), 0 );
    SetMem( &paramOutFile, sizeof(paramOutFile), 0 );
    SetMem( &paramInFile, sizeof(paramInFile), 0 );
    SetMem( &paramAuthHandle1, sizeof(paramAuthHandle1), 0);
    SetMem( &paramSessionAuthWay, sizeof(paramSessionAuthWay), 0);
    SetMem( &paramAuthHashAlg, sizeof(paramAuthHashAlg), 0);

    // Initial the Default value
    Tpm20SuType.u16         = TPM_SU_CLEAR;
    paramAuthHandle1.u32    = TPM_RH_PLATFORM;
    paramSessionAuthWay.u16 = Aux_AuthByPws;

    UseTpmHwLib = FALSE;

    return EFI_SUCCESS;
}

CHAR16*  GetCmdActionString(
    enSHELL_ACTION_ITEM     enCmdActItem
)
{
    EFI_STATUS      Status = EFI_NOT_FOUND;
    UINTN           unIdx;
    static CHAR16   ErrStr[] = L"FakeCommand" ;

    for( unIdx = 0; unIdx < sizeof(CommandSet)/sizeof(CommandSet[0]); ++unIdx )
    {
        if( CommandSet[unIdx].ActItem == enCmdActItem )
        {
            Status = EFI_SUCCESS;
            return CommandSet[unIdx].ActStr;
        }
    }

    return ErrStr;
}

EFI_STATUS  ParsingCmdAction(
    CHAR16*     Arglist[],
    UINTN       ArgCount,
    CHAR16**    ErrMsg
)
{
    EFI_STATUS              Status = EFI_SUCCESS;
    UINTN                   unIdx;
    static CHAR16           u16ErrStr[StrBufLen];
    BOOLEAN                 bCmdActInit = FALSE;
    enSHELL_ACTION_ITEM     CurParamItem;

    CmdActItem = Act_none;

    Status = InitParamUnion();
    if( EFI_ERROR(Status) )
    {
    }

    // unIdx begin from 1, since first is the command name.
    for( unIdx = 1; unIdx < ArgCount; ++unIdx )
    {
        Status = GetCmdAction( Arglist[unIdx], &CurParamItem );
        if( EFI_ERROR(Status) )
        {
            BufSPrint( u16ErrStr, L"Command Parsing Error [%s]\n\r", Arglist[unIdx] );
            *ErrMsg = u16ErrStr;
            break;
        }
        // Check Multi-Command Action.
        if( Act_CmdBitFlag == (CurParamItem & Act_CmdBitFlag) )
        {
            if( TRUE == bCmdActInit )
            {
                Status = EFI_INVALID_PARAMETER;
                BufSPrint( u16ErrStr, L"Error for more than one action [%s]\n\r", Arglist[unIdx] );
                *ErrMsg = u16ErrStr;
                break;
            }
            bCmdActInit = TRUE;
            CmdActItem = CurParamItem;
        }

        // CMD for TPM Startup/Shutdown Execution
        if( Act_Startup == CurParamItem )
        {
            Tpm20SuType.u16 = TPM_SU_CLEAR;
        }
        if( Act_Shutdown == CurParamItem )
        {
            Tpm20SuType.u16 = TPM_SU_CLEAR;
        }
        if( Aux_Tpm20StartupSuClear == CurParamItem )
        {
            Tpm20SuType.u16 = TPM_SU_CLEAR;
        }
        if( Aux_Tpm20StartupSuState == CurParamItem )
        {
            Tpm20SuType.u16 = TPM_SU_STATE;
        }

        // CMD for DelNVIndex, and check the NVIndex Input parameter


        if( Act_GetNvPublic == CurParamItem ||
                Act_DefineSpace == CurParamItem ||
                Act_DelNVIndex == CurParamItem ||
                Act_ReadNvIndex == CurParamItem ||
                Act_WriteNvIndex == CurParamItem )
        {
            unIdx += 1;
            // check exist a valid password?
            if( 0 == (ArgCount - unIdx) )
            {
                // last argument
                Status = EFI_INVALID_PARAMETER;
                break;
            }

            Status = StrToHexUint32( Arglist[unIdx], &paramNVIdx.u32 );
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Error for Input [%s]\n\r", Arglist[unIdx] );
                *ErrMsg = u16ErrStr;
                break;
            }
            TRACE(( -1, "SelNVIdx[%x]\n", paramNVIdx.u32 ));
        }

        if( Act_GetNVList == CurParamItem )
        {
            // Nothing for extra parameter Input ...
        }

        if( Act_CapVndr == CurParamItem )
        {
            // Nothing for extra parameter Input ...
        }

        if( Act_CapPhProperty == CurParamItem )
        {
            // Nothing for extra parameter Input ...
        }

        if( Act_PermanentProperty == CurParamItem )
        {
            // Nothing for extra parameter Input ...
        }

        if( Act_GetPcrCap == CurParamItem )
        {
            // Nothing for extra parameter Input ...
        }

        if( Act_ReadPcr == CurParamItem )
        {
            unIdx += 1;
            // check exist a valid password?
            if( 0 == (ArgCount - unIdx) )
            {
                // last argument
                Status = EFI_INVALID_PARAMETER;
                break;
            }

            Status = StrToHexUint32( Arglist[unIdx], &paramSelPcrIdx.u32 );
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Error for Input [%s]\n\r", Arglist[unIdx] );
                *ErrMsg = u16ErrStr;
                break;
            }
            TRACE(( -1, "Read PCR, PcrIndex[%x]\n", paramSelPcrIdx.u32 ));
        }

        if( Act_SetPcrBank == CurParamItem)
        {
            unIdx += 1;
            // check exist a valid password?
            if( 0 == (ArgCount - unIdx) )
            {
                // last argument
                Status = EFI_INVALID_PARAMETER;
                break;
            }

            Status = StrToHexUint32( Arglist[unIdx], &paramHashAlgBitMap.u32 );
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Error for Input [%s]\n\r", Arglist[unIdx] );
                *ErrMsg = u16ErrStr;
                break;
            }
            TRACE(( -1, "SetPcrBank Bitmap[%x]\n", paramHashAlgBitMap.u32 ));
        }

        if( Aux_NvPpWrite == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_PPWRITE = 1;
        }

        if( Aux_NvOwnerWrite == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_OWNERWRITE = 1;
        }

        if( Aux_NvAuthWrite == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_AUTHWRITE = 1;
        }

        if( Aux_NvPolicyWrite == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_POLICYWRITE = 1;
        }

        if( Aux_NvCounter == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_COUNTER = 1;
        }

        if( Aux_NvBits == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_BITS = 1;
        }

        if( Aux_NvExtend == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_EXTEND = 1;
        }

        if( Aux_NvPolicyDelete == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_POLICY_DELETE = 1;
        }

        if( Aux_NvWriteLocked == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_WRITELOCKED = 1;
        }

        if( Aux_NvWriteAll == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_WRITEALL = 1;
        }

        if( Aux_NvWriteDefine == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_WRITEDEFINE = 1;
        }

        if( Aux_NvWriteStClear == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_WRITE_STCLEAR = 1;
        }

        if( Aux_NvGlobalLock == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_GLOBALLOCK = 1;
        }

        if( Aux_NvPpRead == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_PPREAD = 1;
        }

        if( Aux_NvOwnerRead == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_OWNERREAD = 1;
        }

        if( Aux_NvAuthRead == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_AUTHREAD = 1;
        }

        if( Aux_NvPolicyRead == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_POLICYREAD = 1;
        }

        if( Aux_NvNoDa == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_NO_DA = 1;
        }

        if( Aux_NvOrderly == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_ORDERLY = 1;
        }

        if( Aux_NvClearStclear == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_CLEAR_STCLEAR = 1;
        }

        if( Aux_NvReadLocked == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_READLOCKED = 1;
        }

        if( Aux_NvWritten == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_WRITTEN = 1;
        }

        if( Aux_NvPlatformCreate == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_PLATFORMCREATE = 1;
        }

        if( Aux_NvReadStclear == CurParamItem )
        {
            paramDefNvAttr.Tpm20NvAttr.TPMA_NV_READ_STCLEAR = 1;
        }

        if( Aux_AuthFile == CurParamItem )
        {
            unIdx += 1;
            // check exist a valid password?
            if( 0 == (ArgCount - unIdx) )
            {
                // last argument
                Status = EFI_INVALID_PARAMETER;
                break;
            }

            // Copy the File name
            WStrCopy( paramOpenAuthFile.StrBuffer, Arglist[unIdx] );
        }

        if( Aux_AuthHandleFile1 == CurParamItem )
        {
            unIdx += 1;
            // check exist a valid password?
            if( 0 == (ArgCount - unIdx) )
            {
                // last argument
                Status = EFI_INVALID_PARAMETER;
                break;
            }

            // Copy the File name
            WStrCopy( paramOpenAuthHdlFile1.StrBuffer, Arglist[unIdx] );
        }

        if( Aux_AuthHandle1 == CurParamItem )
        {
            unIdx += 1;
            // check exist a valid password?
            if( 0 == (ArgCount - unIdx) )
            {
                // last argument
                Status = EFI_INVALID_PARAMETER;
                break;
            }

            Status = StrToHexUint32( Arglist[unIdx], &paramAuthHandle1.u32 );
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Error for Input [%s]\n\r", Arglist[unIdx] );
                *ErrMsg = u16ErrStr;
                break;
            }
            TRACE(( -1, "AuthHandle1[%x]\n", paramAuthHandle1.u32 ));
        }

        if( Aux_AuthByPws == CurParamItem )
        {
            paramSessionAuthWay.u16 = Aux_AuthByPws;
            TRACE(( -1, "Auth By Password way\n", paramSize.u16 ));
        }

        if( Aux_AuthByHmac == CurParamItem )
        {
            paramSessionAuthWay.u16 = Aux_AuthByHmac;
            TRACE(( -1, "Auth By Hmac way\n", paramSize.u16 ));
        }

        if( Aux_AuthHashSha1 == CurParamItem )
        {
            paramAuthHashAlg.u16 = TPM_ALG_SHA1;
        }

        if( Aux_AuthHashSha256 == CurParamItem )
        {
            paramAuthHashAlg.u16 = TPM_ALG_SHA256;
        }

        if( Aux_Tpm20Size == CurParamItem )
        {
            unIdx += 1;
            // check exist a valid password?
            if( 0 == (ArgCount - unIdx) )
            {
                // last argument
                Status = EFI_INVALID_PARAMETER;
                break;
            }

            Status = StrToHexUint32( Arglist[unIdx], &paramSize.u32 );
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Error for Input [%s]\n\r", Arglist[unIdx] );
                *ErrMsg = u16ErrStr;
                break;
            }
            TRACE(( -1, "Size[%x]\n", paramSize.u32 ));
        }

        if( Aux_OutputFile == CurParamItem ||
            Aux_InputFile == CurParamItem )
        {
            unIdx += 1;
            // check exist a valid password?
            if( 0 == (ArgCount - unIdx) )
            {
                // last argument
                Status = EFI_INVALID_PARAMETER;
                break;
            }

            if( Aux_OutputFile == CurParamItem )
            {
                // Copy the File name
                WStrCopy( paramOutFile.StrBuffer, Arglist[unIdx] );
            }
            else
            {
                WStrCopy( paramInFile.StrBuffer, Arglist[unIdx] );
            }
        }

        if( Act_ExeCmdFile == CurParamItem )
        {
            unIdx += 1;
            // check exist a valid password?
            if( 0 == (ArgCount - unIdx) )
            {
                // last argument
                Status = EFI_INVALID_PARAMETER;
                break;
            }

            // Copy the File name
            WStrCopy( paramOpenFile.StrBuffer, Arglist[unIdx] );
        }

        if( Act_ExeCmdFileHelp == CurParamItem )
        {
            // Nothing for extra parameter Input ...
        }

        if ( Aux_TpmHwLib == CurParamItem )
        {
            UseTpmHwLib = TRUE;
        }

        if( Aux_showTpmCmd == CurParamItem )
        {
            Tpm2SubCmdExternCallBack = PrintTpmCmdCallBack;
        }
    }

    // no command, show help
    if( Act_none == CmdActItem || EFI_ERROR(Status) )
    {
        CmdActItem = Act_showHelp;
    }

    return Status;
}

EFI_STATUS  ExeCmdAction(
    CHAR16**    ErrMsg
)
{
    EFI_STATUS      Status = EFI_SUCCESS;
    UINTN           unIdx;
    static CHAR16   u16ErrStr[StrBufLen];

//    TRACE(( -1, "[%d]: Current CmdActItem:[%x]\n", __LINE__, CmdActItem ));

    do
    {

        if( Act_Startup == CmdActItem )
        {
            Status = Tpm2Startup( Tpm20SuType.u16 );
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Failed to Tpm2Startup(%s) - %r\n\r", TPM_SU_CLEAR == Tpm20SuType.u16 ? L"SU_CLEAR" : L"SU_STATE", Status );
                *ErrMsg = u16ErrStr;
                break;
            }
            break;
        }

        if( Act_Shutdown == CmdActItem )
        {
            Status = Tpm2Shutdown( Tpm20SuType.u16 );
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Failed to Tpm2Shutdown(%s) - %r\n\r", TPM_SU_CLEAR == Tpm20SuType.u16 ? L"SU_CLEAR" : L"SU_STATE", Status );
                *ErrMsg = u16ErrStr;
                break;
            }
            break;
        }

        if( Act_GetNVList == CmdActItem )
        {
            TPML_HANDLE     ChkNvList;

            Status = Tpm2GetCapabilityNVList( &ChkNvList );
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Failed to Tpm2GetCapabilityNVList(...) - %r\n\r", Status );
                *ErrMsg = u16ErrStr;
                break;
            }
            // Print the NVList
            for( unIdx=0; unIdx < ChkNvList.count; ++unIdx )
            {
                BufSPrint( u16ErrStr, L"[%02d]: 0x%08x\n\r", unIdx, ChkNvList.handle[unIdx] );
                SPrintf( L"%s", u16ErrStr );
            }

            break;
        }

        if( Act_DelNVIndex == CmdActItem )
        {
            EFI_STATUS ShellTpm20UndefineSpace(
                UINT32  NvIndex,
                UINT32  AuthWay,
                UINT32  AuthHandle1,
                CHAR16* AuthHdlFile1
            );

            Status = ShellTpm20UndefineSpace (
                                paramNVIdx.u32,
                                paramSessionAuthWay.u32,
                                paramAuthHandle1.u32,
                                paramOpenAuthHdlFile1.StrBuffer
                                );
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Failed on ShellTpm20UndefineSpace(...) -%x\n\r", Status );
                *ErrMsg = u16ErrStr;
                break;
            }
            break;
        }

        if( Act_GetNvPublic == CmdActItem )
        {
            EFI_STATUS ShowTpm20NvPublic(
                UINT32      un32Index
            );

            Status = ShowTpm20NvPublic (paramNVIdx.u32);
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Failed on ShowTpm20NvPublic().\n\r" );
                *ErrMsg = u16ErrStr;
                break;
            }
            break;
        }

        if( Act_DefineSpace == CmdActItem )
        {
            EFI_STATUS ShellTpm20DefineSpae(
                UINT32  NvIndex,
                UINT32  NvSize,
                UINT32  NvAttr,
                UINT16  AuthWay,
                UINT16  HashAlg,
                UINT32  AuthHandle1,
                CHAR16* AuthHdlFile1,
                CHAR16* NvAuthFile
            );

            Status = ShellTpm20DefineSpae (
                                paramNVIdx.u32,
                                paramSize.u32,
                                paramDefNvAttr.u32,
                                paramSessionAuthWay.u16,
                                paramAuthHashAlg.u16,
                                paramAuthHandle1.u32,
                                paramOpenAuthHdlFile1.StrBuffer,
                                paramOpenAuthFile.StrBuffer
                                );
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Failed on ShellTpm20DefineSpae().\n\r" );
                *ErrMsg = u16ErrStr;
                break;
            }

            break;
        }

        if( Act_ReadNvIndex == CmdActItem )
        {
            EFI_STATUS ShellTpm20ReadNvIndex(
                UINT32  NvIndex,
                UINT32  AuthWay,
                UINT32  AuthHandle1,
                CHAR16* AuthHdlFile1,
                CHAR16* OutFile
            );

            Status = ShellTpm20ReadNvIndex (
                                paramNVIdx.u32,
                                paramSessionAuthWay.u32,
                                paramAuthHandle1.u32,
                                paramOpenAuthHdlFile1.StrBuffer,
                                paramOutFile.StrBuffer
                                );
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Failed on ShellTpm20ReadNvIndex().\n\r" );
                *ErrMsg = u16ErrStr;
                break;
            }
            break;
        }

        if( Act_WriteNvIndex == CmdActItem )
        {
            EFI_STATUS ShellTpm20WriteNvIndex(
                            UINT32  NvIndex,
                            UINT32  AuthWay,
                            UINT32  AuthHandle1,
                            CHAR16* AuthHdlFile1,
                            CHAR16* InFile
                        );

            Status = ShellTpm20WriteNvIndex (
                                paramNVIdx.u32,
                                paramSessionAuthWay.u32,
                                paramAuthHandle1.u32,
                                paramOpenAuthHdlFile1.StrBuffer,
                                paramInFile.StrBuffer
                                );
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Failed on ShellTpm20WriteNvIndex().\n\r" );
                *ErrMsg = u16ErrStr;
                break;
            }
        }

        if( Act_CapVndr == CmdActItem )
        {
            EFI_STATUS ShowTpmVenderVersion();

            Status = ShowTpmVenderVersion();
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Failed to Get TPM Vender Info.\n\r" );
                *ErrMsg = u16ErrStr;
                break;
            }
            break;
        }

        if( Act_CapPhProperty == CmdActItem )
        {
            EFI_STATUS ShowPlatformHierarchyProperty();

            Status = ShowPlatformHierarchyProperty();
            if( EFI_ERROR(Status) )
            {
                BufSPrint( u16ErrStr, L"Failed to Get TPM PH property Info.\n\r" );
                *ErrMsg = u16ErrStr;
                break;
            }
            break;
        }

        if( Act_PermanentProperty == CmdActItem )
        {
            EFI_STATUS ShowPermanentProperty();

            Status = ShowPermanentProperty();
            if( EFI_ERROR(Status))
            {
                BufSPrint( u16ErrStr, L"Failed to Get TPM Permanent property Info.\n\r" );
                *ErrMsg = u16ErrStr;
                break;
            }
            break;
        }

        if( Act_GetPcrCap == CmdActItem )
        {
            EFI_STATUS ShowPcrSupportAndActStatus();

            Status = ShowPcrSupportAndActStatus();
            if( EFI_ERROR(Status))
            {
                BufSPrint( u16ErrStr, L"Failed to Get TPM PCR Banks Info.\n\r" );
                *ErrMsg = u16ErrStr;
                break;
            }
            break;
        }

        if( Act_ReadPcr == CmdActItem )
        {
            EFI_STATUS ShowPcrReadValue(
                UINT32      u32PcrIndex
            );

            Status = ShowPcrReadValue(paramSelPcrIdx.u32);
            if( EFI_ERROR(Status))
            {
                BufSPrint( u16ErrStr, L"Failed to Read TPM PCR Index Info.\n\r" );
                *ErrMsg = u16ErrStr;
                break;
            }
        }

        if( Act_SetPcrBank == CmdActItem )
        {
            EFI_STATUS Tpm2PcrAllocate
            (
                UINTN       HashBitMap
            );

            Status = Tpm2PcrAllocate( paramHashAlgBitMap.u32 );
            if( EFI_ERROR(Status))
            {
                BufSPrint( u16ErrStr, L"Failed to Set PCR Bank.\n\r" );
                *ErrMsg = u16ErrStr;
                break;
            }
            break;
        }

        if( Act_ExeCmdFile == CmdActItem )
        {

            EFI_STATUS  ShellExeCmdFile(
                CHAR16      *ExeCmdFile
            );

            Status = ShellExeCmdFile( paramOpenFile.StrBuffer );
            if( EFI_ERROR(Status))
            {
                BufSPrint( u16ErrStr, L"Failed to Open File [%s].\n\r", paramOpenFile.StrBuffer );
                *ErrMsg = u16ErrStr;
                break;
            }
            break;
        }

        if (Act_TpmFmpFwVer == CmdActItem)
        {
            EFI_STATUS ShowAmiTpmFmpVersion();

            Status = ShowAmiTpmFmpVersion ();
            break;
        }

        if( Act_ExeCmdFileHelp == CmdActItem    ||
                Act_ShowTpmNvHelp == CmdActItem ||
                Act_showHelp == CmdActItem
        )
        {
            EFI_INPUT_KEY       Key;
            CONST CHAR16        **ShowMsgTbl;
            UINTN               ShowTblSize;

            switch (CmdActItem)
            {
                case Act_ExeCmdFileHelp:
                    ShowMsgTbl = cnExeCmdFileHelpMsg;
                    ShowTblSize = sizeof(cnExeCmdFileHelpMsg)/sizeof(cnExeCmdFileHelpMsg[0]);
                    break;
                    break;
                case Act_ShowTpmNvHelp:
                    ShowMsgTbl = cnShowTpm20NvHelp;
                    ShowTblSize = sizeof(cnShowTpm20NvHelp)/sizeof(cnShowTpm20NvHelp[0]);
                    break;
                default:
                    ShowMsgTbl = cnHelpMsg;
                    ShowTblSize = sizeof(cnHelpMsg)/sizeof(cnHelpMsg[0]);
                    break;
            }

            for( unIdx = 0; unIdx < ShowTblSize; ++unIdx )
            {
                if( 0 == unIdx % 20 && unIdx != 0 )
                {
                    SPrintf( L"...Press any key continue ...\r" );
                    while(1)
                    {
                        if(EFI_SUCCESS == pST->ConIn->ReadKeyStroke( pST->ConIn, &Key ))
                        {
                            break;
                        }
                    }
                }
                SPrintf( L"%s", ShowMsgTbl[unIdx] );
            }
            break;
        }

    } while( FALSE);

    return Status;
}
