# fwtriage

A **read-only** static analyzer that inventories and explains the **TPM**,
**IOMMU**, and **SMBIOS** subsystems inside a UEFI/BIOS flash image.

It is an auditing / understanding tool in the spirit of CHIPSEC, UEFITool and
FwHunt. It never modifies the image or the running system.

## What it reports

- **Flash layout** — every firmware volume (`_FVH`) with offset/length.
- **Module inventory per subsystem** — each TPM/IOMMU/SMBIOS FFS module, with
  a plain-language explanation of what it does, classified by UI name *and* by
  the protocol GUIDs embedded in its PE image (so unnamed modules still get
  caught).
- **Protocol / config-table cross-reference** — who produces vs consumes
  `EFI_TCG2_PROTOCOL`, `EDKII_IOMMU_PROTOCOL`, `EFI_SMBIOS_PROTOCOL`, the
  SMBIOS config tables, etc.
- **ACPI tables** the firmware publishes for the OS (`TPM2`, `TCPA`, `IVRS`,
  `DMAR`, `WSMT`, …) with what each means.
- **SMBIOS identity decode** — parses the compiled SMBIOS static-data template
  and prints Type 0/1/2/3 including the **system UUID** (handling the SMBIOS
  2.6+ mixed-endian encoding) and every **serial / asset** field, flagging
  factory placeholders (`Default string`, `To Be Filled By O.E.M.`, zero/FF).
- **Identity summary** — what counts as a "serial" in each subsystem.

## Usage

```bash
pip install uefi_firmware                 # provides uefi-firmware-parser (dependency)

python3 fwtriage.py IMAGE.bin             # full report to stdout
python3 fwtriage.py IMAGE.bin --only tpm,smbios
python3 fwtriage.py IMAGE.bin --json out.json
python3 fwtriage.py IMAGE.bin --extract-dir ./extract   # keep/reuse the decompressed tree
python3 fwtriage.py IMAGE.bin --no-explain --quiet
```

`IMAGE.bin` is a raw SPI/BIOS dump (e.g. a 16 MB vendor update or a flashrom
dump). The tool shells out to `uefi-firmware-parser` once to decompress the
firmware volumes, then layers its own TPM/IOMMU/SMBIOS knowledge on top.

## Files

- `fwtriage.py` — the analyzer (FV map, module walk, SMBIOS decoder, ACPI scan,
  cross-reference, report + JSON).
- `knowledge.py` — the grounded knowledge base: protocol GUIDs, module-name
  classifications, ACPI signatures, SMBIOS type/placeholder tables. Extend this
  to teach the tool new modules or other vendors.

## Scope / caveats

- Validated against an AMI AptioV (AMD, B550-class) image. Intel images add a
  flash-descriptor / ME region layout the FV scan steps over; the module and
  protocol logic is vendor-neutral.
- Per-unit serial/UUID are **not** present in a downloadable BIOS update — they
  are programmed at the factory via the SMM DMI-edit path and preserved across
  flashes. Placeholders in the decode are therefore expected.
- "Classified by referenced protocol" means the module was bucketed from a GUID
  in its binary; that catches consumers (e.g. storage drivers measuring into
  the TPM) as well as producers.
