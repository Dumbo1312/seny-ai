/** @file
  Definition of the Seny demo protocol.

  This is the interface that SenyDxe publishes on a handle in the DXE
  handle database. Any other image in the boot environment (another
  driver, a UEFI Shell app, the Shell itself) can find it by GUID with
  gBS->LocateProtocol and call through these function pointers. That is
  the entire boot-time "communication" model: a GUID + a struct of
  function pointers in a shared address space.
**/

#ifndef SENY_PROTOCOL_H_
#define SENY_PROTOCOL_H_

//
// {C7431E5E-A095-457D-A06E-D7995BBEF675}
//
#define SENY_PROTOCOL_GUID \
  { 0xC7431E5E, 0xA095, 0x457D, { 0xA0, 0x6E, 0xD7, 0x99, 0x5B, 0xBE, 0xF6, 0x75 } }

typedef struct _SENY_PROTOCOL SENY_PROTOCOL;

/**
  Print a greeting plus the current call count to the active console.
**/
typedef
EFI_STATUS
(EFIAPI *SENY_GREET)(
  IN SENY_PROTOCOL  *This
  );

/**
  Add two values. A trivial function so a client has something to call
  and get a result back from.
**/
typedef
EFI_STATUS
(EFIAPI *SENY_ADD)(
  IN  SENY_PROTOCOL  *This,
  IN  UINTN          A,
  IN  UINTN          B,
  OUT UINTN          *Result
  );

struct _SENY_PROTOCOL {
  UINT32      Revision;
  UINTN       CallCount;   // bumped on each Greet, so state is observable
  SENY_GREET  Greet;
  SENY_ADD    Add;
};

extern EFI_GUID  gSenyProtocolGuid;

#endif // SENY_PROTOCOL_H_
