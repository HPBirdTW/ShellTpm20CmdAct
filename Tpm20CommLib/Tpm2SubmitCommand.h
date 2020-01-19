
EFI_STATUS
EFIAPI
Tpm2SubmitCommand (
    IN  UINT32              InputParameterBlockSize,
    IN  UINT8               *InputParameterBlock,
    IN  OUT UINT32          *OutputParameterBlockSize,
    IN  UINT8               *OutputParameterBlock
);

typedef VOID (*TPM2_SUB_CMD_CALLBACK)();

extern  UINT32  u32LastTpmErr;
extern  UINTN   unLastTpmCmdSize;
extern  UINT8   pLastTpmCmd[];
extern  UINTN   unLastTpmRspSize;
extern  UINT8   pLastTpmRsp[];
extern TPM2_SUB_CMD_CALLBACK Tpm2SubCmdExternCallBack;
