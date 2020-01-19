
EFI_STATUS
EFIAPI
Tpm2GetCapability (
    IN  TPM_CAP                 Capability,
    IN  UINT32                  Property,
    IN  UINT32                  PropertyCount,
    OUT TPMI_YES_NO             *MoreData,
    OUT TPMS_CAPABILITY_DATA    *CapabilityData
);

EFI_STATUS
EFIAPI
Tpm2GetCapabilityManufactureID (
    OUT UINT32              *ManufactureId
);

EFI_STATUS
EFIAPI
Tpm2GetCapabilityFirmwareVersion (
    OUT UINT32                  *FirmwareVersion1,
    OUT UINT32                  *FirmwareVersion2
);

EFI_STATUS
EFIAPI
Tpm2GetCapabilityTpmRevision (
    OUT UINT32                  *TpmVersion
);

EFI_STATUS
EFIAPI
Tpm2GetCapabilityManufactureID (
    OUT UINT32              *ManufactureId
);

EFI_STATUS
EFIAPI
Tpm2GetCapabilityFirmwareVersion (
    OUT UINT32                  *FirmwareVersion1,
    OUT UINT32                  *FirmwareVersion2
);

EFI_STATUS
EFIAPI
Tpm2GetCapabilityNVList(
    OUT TPML_HANDLE     *NVList
);
