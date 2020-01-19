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

#pragma pack(1)
typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPM_CAP                   Capability;
  UINT32                    Property;
  UINT32                    PropertyCount;
} TPM2_GET_CAPABILITY_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER      Header;
  TPMI_YES_NO               MoreData;
  TPMS_CAPABILITY_DATA      CapabilityData;
} TPM2_GET_CAPABILITY_RESPONSE;
#pragma pack()

EFI_STATUS
EFIAPI
Tpm2GetCapability (
    TPM_CAP                 Capability,
    UINT32                  Property,
    UINT32                  PropertyCount,
    TPMI_YES_NO             *MoreData,
    TPMS_CAPABILITY_DATA    *CapabilityData
)
{
  EFI_STATUS                        Status;
  TPM2_GET_CAPABILITY_COMMAND       SendBuffer;
  TPM2_GET_CAPABILITY_RESPONSE      RecvBuffer;
  UINT32                            SendBufferSize;
  UINT32                            RecvBufferSize;


  SendBuffer.Header.tag = SwapBytes16 (TPM_ST_NO_SESSIONS);
  SendBuffer.Header.commandCode = SwapBytes32 (TPM_CC_GetCapability);

  SendBuffer.Capability = SwapBytes32 (Capability);
  SendBuffer.Property = SwapBytes32 (Property);
  SendBuffer.PropertyCount = SwapBytes32 (PropertyCount);

  SendBufferSize = (UINT32) sizeof (SendBuffer);
  SendBuffer.Header.paramSize = SwapBytes32 (SendBufferSize);

  //
  // send Tpm command
  //
  RecvBufferSize = sizeof (RecvBuffer);
  Status = Tpm2SubmitCommand (SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (RecvBufferSize <= sizeof (TPM2_RESPONSE_HEADER) + sizeof (UINT8)) {
    return EFI_DEVICE_ERROR;
  }

  if( RecvBuffer.Header.responseCode )
  {
      Status = SwapBytes32 (RecvBuffer.Header.responseCode) | (RETURN_STATUS)MAX_BIT ;
      return Status;
  }

  //
  // Return the response
  //
  *MoreData = RecvBuffer.MoreData;
  //
  // Does not unpack all possiable property here, the caller should unpack it and note the byte order.
  //
  CopyMem (CapabilityData, &RecvBuffer.CapabilityData, RecvBufferSize - sizeof (TPM2_RESPONSE_HEADER) - sizeof (UINT8));

  return EFI_SUCCESS;
}
