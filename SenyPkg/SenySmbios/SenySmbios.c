/** @file
  SenySmbios - a DXE driver that uses EFI_SMBIOS_PROTOCOL to do the
  canonical DXE job of *producing a platform table*.

  It demonstrates two halves of real DXE work:
    1. Consuming a service another driver published: it locates
       EFI_SMBIOS_PROTOCOL (installed by the platform's SMBIOS DXE
       driver) and enumerates every SMBIOS record already present.
    2. Producing data the OS will later consume: it adds a new
       Type 11 (OEM Strings) record of its own, then re-enumerates so
       you can see the record count grow and our handle appear.

  Run it from the Shell with 'load'. After it runs, 'smbiosview -t 11'
  shows the record we added, and an OS booted afterwards would see it
  in /sys/firmware/dmi (Linux) as an OEM string.
**/

#include <Uefi.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Protocol/Smbios.h>
#include <IndustryStandard/SmBios.h>

//
// Walk the whole SMBIOS table, printing Type/Handle/Length for each
// record. This is pure read access to a table another driver built.
//
STATIC
VOID
EnumerateSmbios (
  IN EFI_SMBIOS_PROTOCOL  *Smbios,
  IN CONST CHAR16         *When
  )
{
  EFI_STATUS               Status;
  EFI_SMBIOS_HANDLE        Handle;
  EFI_SMBIOS_TABLE_HEADER  *Record;
  EFI_HANDLE               Producer;
  UINTN                    Count;

  Print (L"--- SMBIOS records %s ---\n", When);
  Handle = SMBIOS_HANDLE_PI_RESERVED;   // start-of-iteration sentinel
  Count  = 0;
  while (TRUE) {
    Status = Smbios->GetNext (Smbios, &Handle, NULL, &Record, &Producer);
    if (EFI_ERROR (Status)) {
      break;
    }
    Count++;
    Print (
      L"  Type=%3u  Handle=0x%04x  FmtLen=%u\n",
      Record->Type, Record->Handle, Record->Length
      );
  }
  Print (L"  total records: %u\n", Count);
}

/**
  Build and install one Type 11 (OEM Strings) record carrying a single
  custom string. The record passed to Add() is the formatted area
  followed by the string set terminated by a double NUL.
**/
STATIC
EFI_STATUS
AddOemStringRecord (
  IN EFI_SMBIOS_PROTOCOL  *Smbios
  )
{
  EFI_STATUS           Status;
  EFI_SMBIOS_HANDLE    SmbiosHandle;
  SMBIOS_TABLE_TYPE11  *Type11;
  CHAR8                *OemString = "SenyPkg DXE lab: record produced by SenySmbios";
  UINTN                StrSize;
  UINTN                TotalSize;
  UINT8                *Buffer;
  UINT8                *StrDest;

  StrSize = AsciiStrSize (OemString);            // includes its own NUL
  //
  // Layout: [formatted Type11 area][string][final NUL terminator]
  //
  TotalSize = sizeof (SMBIOS_TABLE_TYPE11) + StrSize + 1;

  Buffer = AllocateZeroPool (TotalSize);
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Type11 = (SMBIOS_TABLE_TYPE11 *)Buffer;
  Type11->Hdr.Type   = EFI_SMBIOS_TYPE_OEM_STRINGS;          // 11
  Type11->Hdr.Length = (UINT8)sizeof (SMBIOS_TABLE_TYPE11);  // formatted area only
  Type11->Hdr.Handle = 0;                                    // filled in by Add()
  Type11->StringCount = 1;

  // Copy the string right after the formatted area; the trailing byte
  // left zero by AllocateZeroPool gives us the double-NUL terminator.
  StrDest = Buffer + sizeof (SMBIOS_TABLE_TYPE11);
  CopyMem (StrDest, OemString, StrSize);

  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;      // ask Add() to assign one
  Status = Smbios->Add (
                     Smbios,
                     NULL,            // no specific producer image handle
                     &SmbiosHandle,
                     (EFI_SMBIOS_TABLE_HEADER *)Type11
                     );
  if (!EFI_ERROR (Status)) {
    Print (L"[Seny] Added Type 11 OEM-strings record, assigned handle 0x%04x\n", SmbiosHandle);
    Print (L"[Seny]   string: \"%a\"\n", OemString);
  } else {
    Print (L"[Seny] Add() failed: %r\n", Status);
  }

  FreePool (Buffer);
  return Status;
}

EFI_STATUS
EFIAPI
SenySmbiosEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS           Status;
  EFI_SMBIOS_PROTOCOL  *Smbios;

  Status = gBS->LocateProtocol (&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
  if (EFI_ERROR (Status)) {
    Print (L"[Seny] EFI_SMBIOS_PROTOCOL not found: %r\n", Status);
    return Status;
  }
  Print (L"[Seny] Located EFI_SMBIOS_PROTOCOL at %p\n", Smbios);

  EnumerateSmbios (Smbios, L"BEFORE add");
  AddOemStringRecord (Smbios);
  EnumerateSmbios (Smbios, L"AFTER add");

  return EFI_SUCCESS;
}
