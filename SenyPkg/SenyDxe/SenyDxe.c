/** @file
  SenyDxe - a tier-1 DXE driver for the lab.

  What it demonstrates:
    1. The DXE dispatcher loads this image and calls its entry point.
       We emit a DEBUG line so you can watch that happen on QEMU's
       debug console (ISA debug port 0x402), even in a RELEASE build.
    2. It installs SENY_PROTOCOL on a fresh handle in the handle
       database. After this, the protocol is discoverable (Shell "dh")
       and callable by anyone in the boot environment.

  This is a plain DXE driver: it does its work in the entry point and
  then goes passive. It only runs again when someone calls one of its
  protocol functions.
**/

#include <Uefi.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Protocol/Seny.h>

//
// Function backing SENY_PROTOCOL.Greet
//
STATIC
EFI_STATUS
EFIAPI
SenyGreet (
  IN SENY_PROTOCOL  *This
  )
{
  This->CallCount++;
  //
  // gST->ConOut is the active text console. By the time a client calls
  // this, consoles are connected, so printing here is safe and visible.
  //
  Print (L"[Seny] Hello from inside the DXE protocol. Call #%u\n", This->CallCount);
  DEBUG ((DEBUG_INFO, "SenyDxe: Greet() invoked, CallCount=%u\n", This->CallCount));
  return EFI_SUCCESS;
}

//
// Function backing SENY_PROTOCOL.Add
//
STATIC
EFI_STATUS
EFIAPI
SenyAdd (
  IN  SENY_PROTOCOL  *This,
  IN  UINTN          A,
  IN  UINTN          B,
  OUT UINTN          *Result
  )
{
  if (Result == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Result = A + B;
  DEBUG ((DEBUG_INFO, "SenyDxe: Add(%lu, %lu) = %lu\n", (UINT64)A, (UINT64)B, (UINT64)*Result));
  return EFI_SUCCESS;
}

//
// The single instance of our protocol interface. Static storage: it
// lives as long as the driver stays resident, which is the whole boot.
//
STATIC SENY_PROTOCOL  mSenyProtocol = {
  0x00010000,   // Revision 1.0
  0,            // CallCount
  SenyGreet,
  SenyAdd
};

/**
  Entry point. Called once by the DXE dispatcher when this driver's
  dependency expression is satisfied.
**/
EFI_STATUS
EFIAPI
SenyDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  Handle;

  DEBUG ((DEBUG_INFO, "SenyDxe: ==== entry point reached, dispatcher loaded us ====\n"));

  //
  // Install the protocol on a NEW handle (Handle starts NULL, so the
  // boot services create a fresh one for us). This is what puts us in
  // the handle database.
  //
  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gSenyProtocolGuid, &mSenyProtocol,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "SenyDxe: install failed - %r\n", Status));
    return Status;
  }

  DEBUG ((
    DEBUG_INFO,
    "SenyDxe: SENY_PROTOCOL installed on handle %p. Find it with 'dh' in the Shell.\n",
    Handle
    ));

  //
  // Exercise our own published interface once, so loading the driver
  // visibly proves the function pointers work. An external caller would
  // reach these exactly the same way, via LocateProtocol + call.
  //
  {
    UINTN  Sum;
    mSenyProtocol.Greet (&mSenyProtocol);
    mSenyProtocol.Add (&mSenyProtocol, 40, 2, &Sum);
    Print (L"[Seny] Add(40, 2) returned %u\n", Sum);
  }

  //
  // Returning SUCCESS keeps us resident. The protocol stays live and
  // callable for the rest of the boot.
  //
  return EFI_SUCCESS;
}
