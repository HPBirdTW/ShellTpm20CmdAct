#include <EFI.h>
#include <AmiLib.h>
#include <AmiDxeLib.h>
#include <Protocol/SimpleTextOut.h>
#include "Protocol/SimpleTextIn.h"
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/DevicePath.h>
#include "ShellTpm20CmdAct.h"

EFI_STATUS HexToDec(
    IN  CHAR16  Hex,
    OUT UINT8   *OutVal
)
{
    EFI_STATUS      Status = EFI_SUCCESS;
    UINT8           u8Val;
    do
    {
        u8Val = 0xFF;
        if( '0'<= Hex && '9'>= Hex )
        {
            u8Val = Hex - '0';
            break;
        }
    } while( FALSE );

    if( 0xFF == u8Val || NULL == OutVal )
    {
        // Error format of Hex
        Status = EFI_INVALID_PARAMETER;
    }
    else
    {
        *OutVal =  u8Val;
    }

    return Status;
}

EFI_STATUS HexToNum(
    IN  CHAR16  Hex,
    OUT UINT8   *OutVal
)
{
    EFI_STATUS      Status = EFI_SUCCESS;
    UINT8           u8Val;
    do
    {
        u8Val = 0xFF;
        if( '0'<= Hex && '9'>= Hex )
        {
            u8Val = Hex - '0';
            break;
        }
        if( 'a'<= Hex && 'f'>= Hex )
        {
            u8Val = Hex - 'a' + 10;
            break;
        }
        if( 'A'<= Hex && 'F'>= Hex )
        {
            u8Val = Hex - 'A' + 10;
            break;
        }
    } while( FALSE );

    if( 0xFF == u8Val || NULL == OutVal )
    {
        // Error format of Hex
        Status = EFI_INVALID_PARAMETER;
    }
    else
    {
        *OutVal =  u8Val;
    }

    return Status;
}

EFI_STATUS StrToDecUint32(
    IN  CHAR16*     HexStrBuf,
    OUT UINT32      *pu32OutVal
)
{
    EFI_STATUS      Status = EFI_SUCCESS;
    UINTN           unIdx;
    UINTN           unMaxLen = 8;       // UINT32 have 8 Hex input.
    UINT32          u32Val;
    UINT8           u8Val;

    do
    {
        u32Val = 0;
        u8Val = 0;
        Status = EFI_SUCCESS;
        for( unIdx=0; HexStrBuf[unIdx] != '\0' && unIdx < unMaxLen; ++unIdx)
        {
            u32Val *= 10;
             Status = HexToDec( HexStrBuf[unIdx], &u8Val );
             if( EFI_ERROR(Status) )
             {
                 break;
             }
             u32Val += (UINT32)u8Val;
        }

        if( HexStrBuf[unIdx] != '\0' )
        {
            // String too long
            Status = EFI_INVALID_PARAMETER;
            break;
        }
    } while( FALSE );

    if( !EFI_ERROR(Status) )
    {
        *pu32OutVal = u32Val;
    }

    return Status;
}

EFI_STATUS StrToHexUint32(
    IN  CHAR16*     HexStrBuf,
    OUT UINT32      *pu32OutVal
)
{
    EFI_STATUS      Status = EFI_SUCCESS;
    UINTN           unIdx;
    UINTN           unMaxLen = 8;       // UINT32 have 8 Hex input.
    UINT32          u32Val;
    UINT8           u8Val;

    do
    {
        u32Val = 0;
        u8Val = 0;
        Status = EFI_SUCCESS;
        for( unIdx=0; HexStrBuf[unIdx] != '\0' && unIdx < unMaxLen; ++unIdx)
        {
            u32Val <<= 4;
             Status = HexToNum( HexStrBuf[unIdx], &u8Val );
             if( EFI_ERROR(Status) )
             {
                 break;
             }
             u32Val |= (UINT32)u8Val;
        }

        if( HexStrBuf[unIdx] != '\0' )
        {
            // String too long
            Status = EFI_INVALID_PARAMETER;
        }
    } while( FALSE );

    if( !EFI_ERROR(Status) )
    {
        *pu32OutVal = u32Val;
    }

    return Status;
}

EFI_STATUS IsHex( CHAR8 ascii, UINT8 *hex )
{
    EFI_STATUS      Status = EFI_SUCCESS;

    Status = HexToNum( (CHAR16)ascii, hex );

    return  Status;
}

EFI_STATUS StartComment( CHAR8 ascii )
{
    EFI_STATUS      Status = EFI_SUCCESS;

    do
    {
        Status = EFI_NOT_FOUND;
        if( '#' == ascii )
        {
            Status = EFI_SUCCESS;
            break;
        }
    } while ( FALSE );

    return  Status;
}

EFI_STATUS  IsEndOfLine( CHAR8 ascii )
{
    EFI_STATUS      Status = EFI_SUCCESS;

    do
    {
        Status = EFI_NOT_FOUND;
        if( '\n' == ascii )
        {
            Status = EFI_SUCCESS;
            break;
        }
    } while (FALSE);

    return  Status;
}

EFI_STATUS  IsSkipChar( CHAR8 ascii )
{
    EFI_STATUS      Status = EFI_SUCCESS;

    do
    {
        Status = EFI_NOT_FOUND;
        if ( '\r'==ascii || ' '==ascii || '\t'==ascii )
        {
            Status = EFI_SUCCESS;
            break;
        }

        Status = IsEndOfLine( ascii );
        if( !EFI_ERROR(Status) )
        {
            break;
        }

    } while (FALSE);

    return  Status;
}


EFI_STATUS FileToTpmCmd(
    UINT8   *FileBuffer,
    UINTN   BufferSize,
    UINT8   *pTpmCmdBuffer,
    UINTN   *TpmCmdBufSize
)
{
    UINTN       unIdx;
    UINTN       unTpmBufCount = 0;
    BOOLEAN     bStartComment = FALSE;
    EFI_STATUS  Status;
    UINT8       HexVal;
    UINT8       TmpVal_1, TmpVal_2;

    for( unIdx=0; unIdx<BufferSize; ++unIdx )
    {
        if( TRUE == bStartComment )
        {
            Status = IsEndOfLine( FileBuffer[unIdx] );
            if( !EFI_ERROR(Status) )
            {
                bStartComment = FALSE;
            }
            continue;
        }

        Status = IsSkipChar( FileBuffer[unIdx] );
        if( !EFI_ERROR(Status) )
        {
            continue;
        }

        Status = StartComment( FileBuffer[unIdx] );
        if( !EFI_ERROR(Status) )
        {
            bStartComment = TRUE;
            continue;
        }

        // Hex transfer, it must be two ASCII combine one UINT8
        Status = IsHex( FileBuffer[unIdx], &TmpVal_1 );
        if( !EFI_ERROR(Status) && (unIdx+1 < BufferSize) )
        {
            Status = IsHex( FileBuffer[unIdx+1], &TmpVal_2 );
            if( !EFI_ERROR(Status) )
            {
                //
                ++unIdx;
                HexVal = (TmpVal_1<<4) + TmpVal_2;
                if( unTpmBufCount <  *TpmCmdBufSize )
                {
                    pTpmCmdBuffer[unTpmBufCount++] = HexVal;
                    continue;
                }
                else
                {
                    DEBUG(( -1, "[%d]: fail to fill Tpm Cmd Buffer - %r\n", __LINE__, EFI_BUFFER_TOO_SMALL ));
                }
            }
            else
            {
                DEBUG(( -1, "[%d]: fail to identify second ascii for Hex - %r\n", __LINE__, EFI_INVALID_PARAMETER ));
            }
        }

        DEBUG(( -1, "[%d]: fail to identify parsing buffer, ascii hex[0x%02x]\n", __LINE__, FileBuffer[unIdx] ));
        // It is un-recognize ascii.
        Status = EFI_UNSUPPORTED;
        break;
    }

    if( !EFI_ERROR(Status) )
    {
        *TpmCmdBufSize = unTpmBufCount;
    }

    return Status;
}

EFI_STATUS GetDeviceFolder( EFI_DEVICE_PATH_PROTOCOL* FileDevicePath, CHAR16 **RetFolderPath )
{
    EFI_STATUS                  Status = EFI_SUCCESS;
    UINTN                       Size;
    CHAR16                      *FolderPath;
    EFI_DEVICE_PATH_PROTOCOL    *pDp;
    UINTN                       unIndex = 0;
    CHAR16                      *pStrStart = NULL;
    CHAR16                      *pStrEnd = NULL;

    do
    {
        Status = EFI_NOT_FOUND;

        // Get the First File Device Path
        for( pDp = FileDevicePath; !isEndNode(pDp); pDp = NEXT_NODE(pDp) )
        {
            if( MEDIA_DEVICE_PATH == pDp->Type || MEDIA_FILEPATH_DP == pDp->Type )
            {
                Status = EFI_SUCCESS;
                break;
            }
        }
        if( EFI_ERROR(Status) )
        {
            DEBUG(( -1, "[%d]: Did not find the File Device Path - %r\n", __LINE__, Status));
            break;
        }

        // Check the Device Path should all be File Devic Path
        for( ; !isEndNode(pDp); pDp = NEXT_NODE(pDp) )
        {
            if( MEDIA_DEVICE_PATH != pDp->Type || MEDIA_FILEPATH_DP != pDp->Type )
            {
                Status = EFI_INVALID_PARAMETER;
                DEBUG(( -1, "[%d]: Check File Device Path Failed - %r\n", __LINE__, Status));
                break;
            }
        }

        Size = DPLength(FileDevicePath);
        FolderPath = MallocZ( Size );
        if( NULL == FolderPath )
        {
            Status = EFI_INVALID_PARAMETER;
            DEBUG(( -1, "[%d]:  GetDeviceFolder, Can not locate Buffer - %r\n", __LINE__, Status));
            break;
        }

        for( pDp = FileDevicePath; !isEndNode( NEXT_NODE(pDp) ); pDp = NEXT_NODE(pDp) )
        {
            WStrCat( FolderPath, (CHAR16*)(pDp+1) );
        }

        if (SI2)
        {
            if (0 == WStrlen(FolderPath))
            {
                Status = EFI_NOT_FOUND;
                // Find the Media Device File Path
                for( pDp = FileDevicePath; !isEndNode(pDp); pDp = NEXT_NODE(pDp) )
                {
                    if( MEDIA_DEVICE_PATH == pDp->Type && MEDIA_FILEPATH_DP == pDp->SubType )
                    {
                        Status = EFI_SUCCESS;
                        break;
                    }
                }
                if (EFI_ERROR (Status))
                {
                    DEBUG(( -1, "[%d]: Did not find the File Device Path - %r\n", __LINE__, Status));
                    break;
                }

                Status = EFI_NOT_FOUND;
                // Find the Last "\" Folder-Path
                pStrStart = (CHAR16*)(pDp+1);
                Size = WStrlen (pStrStart);
                for (unIndex = 0; unIndex < Size; ++unIndex)
                {
                    if ((CHAR16)'\\' == pStrStart[Size - unIndex -1])
                    {
                        pStrEnd = pStrStart + (Size - unIndex);
                        Status = EFI_SUCCESS;
                        break;
                    }
                }
                if (EFI_ERROR (Status))
                {
                    DEBUG(( -1, "[%d]: Fail Copy File Device Path - %r\n", __LINE__, Status));
                    break;
                }

                Size = pStrEnd - pStrStart;
                for( unIndex = 0; unIndex < Size; ++unIndex)
                {
                    FolderPath[unIndex] = pStrStart[unIndex];
                }
            }
        }

        *RetFolderPath = FolderPath;
    } while( FALSE );

    return Status;
}

EFI_STATUS OuputShellFile( CHAR16 *FileName, UINTN OutFileSize, UINT8 *OutFileBuffer )
{
    EFI_STATUS                          Status;
    EFI_STATUS                          InnerSts;
    EFI_GUID                            EfiSimpleFileSystemProtocolGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL     *gVolume = NULL;
    EFI_FILE_PROTOCOL                   *FsHandle = NULL;
    EFI_FILE_PROTOCOL                   *targetFile = NULL;
    EFI_FILE_PROTOCOL                   *FolderHandle = NULL;
    EFI_GUID                            EfiFileInfoGuid = EFI_FILE_INFO_ID;
    EFI_FILE_INFO                       *pFileInfo = NULL;
    UINTN                               unFileInfoSize = 0;
    CHAR16                              *FolderPath = NULL;

    do
    {
//        PrintBufMixChar( 0x200, (UINT8*)SI->Info->FilePath );
        if( NULL == FileName || NULL == OutFileBuffer || 0 == OutFileSize )
        {
            Status = EFI_INVALID_PARAMETER;
            break;
        }

        if (SI)
        {
            Status = GetDeviceFolder( SI->Info->FilePath, &FolderPath );
            if( EFI_ERROR(Status) )
            {
                DEBUG(( -1, "[%d]: Error TRACE - %r\n", __LINE__, Status));
                break;
            }
            //DEBUG(( -1, "FolderPath[%S]\n", FolderPath));

            Status = pBS->HandleProtocol (  SI->Info->DeviceHandle, &EfiSimpleFileSystemProtocolGuid, (VOID **)&gVolume  );
            if( EFI_ERROR(Status) )
            {
                DEBUG(( -1, "[%d]: Failed to Locate File Handle - %r\n", __LINE__, Status));
                break;
            }
        }
        else if (SI2)
        {
            Status = GetDeviceFolder( ImageProtocol->FilePath, &FolderPath );
            if( EFI_ERROR(Status) )
            {
                DEBUG(( -1, "[%d]: Error TRACE - %r\n", __LINE__, Status));
                break;
            }
            //DEBUG(( -1, "FolderPath[%S]\n", FolderPath));

            Status = pBS->HandleProtocol (  ImageProtocol->DeviceHandle, &EfiSimpleFileSystemProtocolGuid, (VOID **)&gVolume  );
            if( EFI_ERROR(Status) )
            {
                DEBUG(( -1, "[%d]: Failed to Locate File Handle - %r\n", __LINE__, Status));
                break;
            }
        }

        Status = gVolume->OpenVolume ( gVolume, &FsHandle );
        if( EFI_ERROR(Status) )
        {
            DEBUG(( -1, "[%d]: Failed to Locate File Handle(OpenRoot) - %r\n", __LINE__, Status));
            break;
        }

        Status = FsHandle->Open (
                                FsHandle,
                                &FolderHandle,
                                FolderPath,
                                EFI_FILE_MODE_READ,
                                0 );
        if( EFI_ERROR(Status) )
        {
            DEBUG(( -1, "[%d]: Failed to Locate File(OpenFolder) Handle - %r\n", __LINE__, Status));
            break;
        }

        Status = FolderHandle->Open (
                                FolderHandle,
                                &targetFile,
                                FileName,
                                EFI_FILE_MODE_READ,
                                0 );
        if( !EFI_ERROR(Status) )
        {
            unFileInfoSize = sizeof(EFI_FILE_INFO) + 0x100;
            Status = pBS->AllocatePool(EfiBootServicesData,unFileInfoSize ,&pFileInfo);
            ASSERT_EFI_ERROR(Status);

            Status = targetFile->GetInfo(
                                    targetFile,
                                    &EfiFileInfoGuid,
                                    &unFileInfoSize,
                                    pFileInfo );
            if( EFI_ERROR(Status) )
            {
                DEBUG(( -1, "[%d]: Failed to Get File Info - %r\n", __LINE__, Status));
                break;
            }

            if( (pFileInfo->Attribute & EFI_FILE_DIRECTORY) == EFI_FILE_DIRECTORY )
            {
                Status = EFI_INVALID_PARAMETER;
                DEBUG(( -1, "[%d]: Open File is a Directory - %r\n", __LINE__, Status));
                break;
            }

            Status = targetFile->Delete( targetFile );
            if( EFI_ERROR(Status) )
            {
                DEBUG(( -1, "[%d]: Failed to Delete File - %r\n", __LINE__, Status));
                break;
            }

            targetFile = NULL;
        }

        Status = FolderHandle->Open (
                                FolderHandle,
                                &targetFile,
                                FileName,
                                EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                                EFI_FILE_ARCHIVE );
        if( EFI_ERROR(Status) )
        {
            DEBUG(( -1, "[%d]: Failed to Create File - %r\n", __LINE__, Status));
            break;
        }

        Status = targetFile->Write(
                                targetFile,
                                &OutFileSize,
                                OutFileBuffer );
        if( EFI_ERROR(Status) )
        {
            DEBUG(( -1, "[%d]: Failed to Write File - %r\n", __LINE__, Status));
            break;
        }

//        PrintBufMixChar( unFileInfoSize, *RetFileBuf );

    } while( FALSE );

    //
    // The File Handle Close Handle should inverse Open sequence
    // gVolume => FsHandle => FolderHandle => targetFile
    //
    if( FsHandle )
    {
        InnerSts = FsHandle->Close( FsHandle );
        ASSERT_EFI_ERROR(InnerSts);
    }

    if( FolderHandle )
    {
        InnerSts = FolderHandle->Close( FolderHandle );
        ASSERT_EFI_ERROR(InnerSts);
    }

    if( targetFile )
    {
        InnerSts = targetFile->Close( targetFile );
        ASSERT_EFI_ERROR(InnerSts);
    }

    if( pFileInfo )
    {
        InnerSts = pBS->FreePool( pFileInfo );
        ASSERT_EFI_ERROR(InnerSts);
        pFileInfo = NULL;
    }

    if( FolderPath )
    {
        InnerSts = pBS->FreePool( FolderPath );
        ASSERT_EFI_ERROR(InnerSts);
        FolderPath = NULL;
    }

    return Status;
}

EFI_STATUS OpenShellFile( CHAR16 *FileName, UINT8 **RetFileBuf, UINTN *RetFileSize )
{
    EFI_STATUS                          Status;
    EFI_STATUS                          InnerSts;
    EFI_GUID                            EfiSimpleFileSystemProtocolGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL     *gVolume = NULL;
    EFI_FILE_PROTOCOL                   *FsHandle = NULL;
    EFI_FILE_PROTOCOL                   *targetFile = NULL;
    EFI_FILE_PROTOCOL                   *FolderHandle = NULL;
    EFI_GUID                            EfiFileInfoGuid = EFI_FILE_INFO_ID;
    EFI_FILE_INFO                       *pFileInfo = NULL;
    UINTN                               unFileInfoSize = 0;
    CHAR16                              *FolderPath = NULL;

    do
    {
//        PrintBufMixChar( 0x200, (UINT8*)SI->Info->FilePath );
        if( NULL == FileName || NULL == RetFileBuf || NULL == RetFileSize )
        {
            Status = EFI_INVALID_PARAMETER;
            break;
        }

        if (SI)
        {
            Status = GetDeviceFolder( SI->Info->FilePath, &FolderPath );
            if( EFI_ERROR(Status) )
            {
                DEBUG(( -1, "[%d]: Error TRACE - %r\n", __LINE__, Status));
                break;
            }
            //DEBUG(( -1, "FolderPath[%S]\n", FolderPath));

            Status = pBS->HandleProtocol (  SI->Info->DeviceHandle, &EfiSimpleFileSystemProtocolGuid, (VOID **)&gVolume  );
            if( EFI_ERROR(Status) )
            {
                DEBUG(( -1, "[%d]: Failed to Locate File Handle - %r\n", __LINE__, Status));
                break;
            }
        }
        else if (SI2)
        {
            Status = GetDeviceFolder( ImageProtocol->FilePath, &FolderPath );
            if( EFI_ERROR(Status) )
            {
                DEBUG(( -1, "[%d]: Error TRACE - %r\n", __LINE__, Status));
                break;
            }
            //DEBUG(( -1, "FolderPath[%S]\n", FolderPath));

            Status = pBS->HandleProtocol (  ImageProtocol->DeviceHandle, &EfiSimpleFileSystemProtocolGuid, (VOID **)&gVolume  );
            if( EFI_ERROR(Status) )
            {
                DEBUG(( -1, "[%d]: Failed to Locate File Handle - %r\n", __LINE__, Status));
                break;
            }
        }

        Status = gVolume->OpenVolume ( gVolume, &FsHandle );
        if( EFI_ERROR(Status) )
        {
            DEBUG(( -1, "[%d]: Failed to Locate File(OpenRoot) Handle - %r\n", __LINE__, Status));
            break;
        }

        Status = FsHandle->Open (
                                FsHandle,
                                &FolderHandle,
                                FolderPath,
                                EFI_FILE_MODE_READ,
                                0 );
        if( EFI_ERROR(Status) )
        {
            DEBUG(( -1, "[%d]: Failed to Locate File(OpenFolder) Handle - %r\n", __LINE__, Status));
            break;
        }

        Status = FolderHandle->Open (
                                FolderHandle,
                                &targetFile,
                                FileName,
                                EFI_FILE_MODE_READ,
                                0 );
        if( EFI_ERROR(Status) )
        {
            DEBUG(( -1, "[%d]: Failed to Locate File(OpenFile) Handle - %r\n", __LINE__, Status));
            break;
        }

        unFileInfoSize = sizeof(EFI_FILE_INFO) + 0x100;
        Status = pBS->AllocatePool(EfiBootServicesData,unFileInfoSize ,&pFileInfo);
        ASSERT_EFI_ERROR(Status);

        Status = targetFile->GetInfo(
                                targetFile,
                                &EfiFileInfoGuid,
                                &unFileInfoSize,
                                pFileInfo );
        if( EFI_ERROR(Status) )
        {
            DEBUG(( -1, "[%d]: Failed to Locate File(GetFileInfo) Handle - %r\n", __LINE__, Status));
            break;
        }

        if( (pFileInfo->Attribute & EFI_FILE_DIRECTORY) == EFI_FILE_DIRECTORY )
        {
            Status = EFI_INVALID_PARAMETER;
            DEBUG(( -1, "[%d]: Open File is a Directory - %r\n", __LINE__, Status));
            break;
        }

        DEBUG(( DEBUG_INFO, "Read File Size[%x]\n", pFileInfo->FileSize));
        unFileInfoSize = (UINTN)pFileInfo->FileSize;

        *RetFileSize = unFileInfoSize;

        Status = pBS->AllocatePool( EfiBootServicesData, unFileInfoSize, RetFileBuf );
        if( EFI_ERROR(Status) )
        {
            DEBUG(( -1, "[%d]: Failed to AllocatePool() - %r\n", __LINE__, Status));
            break;
        }

        Status = targetFile->Read(
                                targetFile,
                                &unFileInfoSize,
                                *RetFileBuf );
        if( EFI_ERROR(Status) )
        {
            DEBUG(( -1, "[%d]: Failed to Read() File - %r\n", __LINE__, Status));
            break;
        }

//        PrintBufMixChar( unFileInfoSize, *RetFileBuf );

    } while( FALSE );

    //
    // The File Handle Close Handle should inverse Open sequence
    // gVolume => FsHandle => FolderHandle => targetFile
    //
    if( FsHandle )
    {
        InnerSts = FsHandle->Close( FsHandle );
        ASSERT_EFI_ERROR(InnerSts);
    }

    if( FolderHandle )
    {
        InnerSts = FolderHandle->Close( FolderHandle );
        ASSERT_EFI_ERROR(InnerSts);
    }

    if( targetFile )
    {
        InnerSts = targetFile->Close( targetFile );
        ASSERT_EFI_ERROR(InnerSts);
    }

    if( pFileInfo )
    {
        InnerSts = pBS->FreePool( pFileInfo );
        ASSERT_EFI_ERROR(InnerSts);
        pFileInfo = NULL;
    }

    if( FolderPath )
    {
        InnerSts = pBS->FreePool( FolderPath );
        ASSERT_EFI_ERROR(InnerSts);
        FolderPath = NULL;
    }

    return Status;
}
