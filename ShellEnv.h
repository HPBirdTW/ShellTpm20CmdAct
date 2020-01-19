/*
 * Copyright (C) 2019 HPBirdChen (hpbirdtw@gmail.com)
 * All rights reserved.
 * The License file locate on:
 * https://github.com/HPBirdTW/ShellTpm20CmdAct/license.txt
 * */

#ifndef _SHELLENV_H_
#define _SHELLENV_H_

#include <Protocol/LoadedImage.h>

#if defined(__cplusplus)
extern "C"
{
#endif

#define SHELL_INTERFACE_PROTOCOL \
  { \
    0x47c7b223, 0xc42a, 0x11d2, 0x8e, 0x57, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b \
  }

typedef struct _EFI_SHELL_INTERFACE {
  //
  // Handle back to original image handle & image info
  //
  EFI_HANDLE                ImageHandle;
  EFI_LOADED_IMAGE_PROTOCOL *Info;

  //
  // Parsed arg list
  //
  CHAR16                    **Argv;
  UINTN                     Argc;

  //
  // Storage for file redirection args after parsing
  //
  CHAR16                    **RedirArgv;
  UINTN                     RedirArgc;

  //
  // A file style handle for console io
  //
  VOID*                     StdIn;
  VOID*                     StdOut;
  VOID*                     StdErr;
  VOID                      *ArgInfo;
  BOOLEAN                   EchoOn;
} EFI_SHELL_INTERFACE;

#define EFI_SHELL_PARAMETERS_PROTOCOL_GUID \
  { \
  0x752f3136, 0x4e16, 0x4fdc, { 0xa2, 0x2a, 0xe5, 0xf4, 0x68, 0x12, 0xf4, 0xca } \
  }

typedef struct _EFI_SHELL_PARAMETERS_PROTOCOL {
  ///
  /// Points to an Argc-element array of points to NULL-terminated strings containing
  /// the command-line parameters. The first entry in the array is always the full file
  /// path of the executable. Any quotation marks that were used to preserve
  /// whitespace have been removed.
  ///
  CHAR16            **Argv;

  ///
  /// The number of elements in the Argv array.
  ///
  UINTN             Argc;

  ///
  /// The file handle for the standard input for this executable. This may be different
  /// from the ConInHandle in EFI_SYSTEM_TABLE.
  ///
  VOID*             StdIn;

  ///
  /// The file handle for the standard output for this executable. This may be different
  /// from the ConOutHandle in EFI_SYSTEM_TABLE.
  ///
  VOID*             StdOut;

  ///
  /// The file handle for the standard error output for this executable. This may be
  /// different from the StdErrHandle in EFI_SYSTEM_TABLE.
  ///
  VOID*             StdErr;
} EFI_SHELL_PARAMETERS_PROTOCOL;

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif // _SHELLENV_H_
