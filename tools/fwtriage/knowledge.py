"""
knowledge.py - the grounded knowledge base for fwtriage.

Everything here was verified against a real AMI AptioV (AMD) image during
development. Entries map module UI-name substrings, GUIDs and ACPI table
signatures to a (category, explanation) so the tool can *explain* what each
finding does rather than just list it.

Categories: "tpm", "iommu", "smbios", "support" (adjacent/consumer).
"""

# ---------------------------------------------------------------------------
# Protocol / config-table GUIDs, with what they mean and which subsystem.
# GUIDs are stored in canonical string form; the scanner searches for their
# 16-byte little-endian (EFI_GUID) encoding inside module PE images.
# ---------------------------------------------------------------------------
PROTOCOL_GUIDS = {
    # --- TPM / TCG ---
    "607f766c-7455-42be-930b-e4d76db2720f": (
        "tpm", "EFI_TCG2_PROTOCOL",
        "The TPM 2.0 measured-boot service. Producers implement PCR extend / "
        "event-log / HashLogExtendEvent; consumers measure data into the TPM."),
    "f541796d-a62e-4954-a775-9584f61b9cdd": (
        "tpm", "EFI_TCG_PROTOCOL",
        "The legacy TPM 1.2 TCG service (older measured-boot interface)."),
    "1e2ed096-30e2-4254-bd89-863bbef82325": (
        "tpm", "EFI_TCG2_FINAL_EVENTS_TABLE",
        "Config table handing the OS the TPM event-log entries produced after "
        "GetEventLog but before ExitBootServices."),
    # --- IOMMU / DMA protection ---
    "4e939de9-d948-4b0f-88ed-e6e1ce517c1e": (
        "iommu", "EDKII_IOMMU_PROTOCOL",
        "DXE/SMM DMA-remapping service. SetAttribute/Map/Unmap gate which "
        "physical ranges a bus-master device may DMA to (pre-boot DMA "
        "protection). Produced by the platform IOMMU driver."),
    # --- SMBIOS ---
    "03583ff6-cb36-4940-947e-b9b39f4afaf7": (
        "smbios", "EFI_SMBIOS_PROTOCOL",
        "Add/UpdateString/Remove/GetNext over the SMBIOS record set; the "
        "producer assembles the table and installs it to the config table."),
    "eb9d2d31-2d88-11d3-9a16-0090273fc14d": (
        "smbios", "SMBIOS (2.x) config table",
        "EFI configuration-table GUID whose pointer the OS follows to the "
        "32-bit SMBIOS entry point (_SM_)."),
    "f2fd1544-9794-4a2c-992e-e5bbcf20e394": (
        "smbios", "SMBIOS 3.x config table",
        "EFI configuration-table GUID for the 64-bit SMBIOS entry point "
        "(_SM3_)."),
    "0903dd14-2ca0-458a-b5eb-0c0ca30d785c": (
        "smbios", "EFI_SMBIOS_BOARD_PROTOCOL",
        "AMI board-data protocol the core SMBIOS driver consumes to get the "
        "board-specific Type 1/2/3 values."),
    "daf4bf89-ce71-4917-b522-c89d32fbc59f": (
        "smbios", "EFI_SMBIOS_STATIC_DATA",
        "Freeform file holding the compiled SMBIOS template (Type 0/1/2/3 "
        "formatted areas + string pool, with per-unit fields as placeholders)."),
}

# ---------------------------------------------------------------------------
# Module UI-name classification. Keys are lowercase substrings matched against
# a module's UI name. Order matters: first match wins, so put specific before
# generic.
# ---------------------------------------------------------------------------
MODULE_KB = [
    # ---- TPM / TCG core ----
    ("tcg2dxe", "tpm", "Core TPM 2.0 driver: produces EFI_TCG2_PROTOCOL, owns the "
                       "PCRs and the TCG event log, installs the final-events table."),
    ("tcgdxeplatform", "tpm", "AMI platform glue binding the generic TCG driver to this board."),
    ("tcgpeiplatform", "tpm", "PEI-phase AMI platform glue for TCG."),
    ("tcgdxe", "tpm", "TPM 1.2 TCG driver (legacy measured boot)."),
    ("tcgpei", "tpm", "PEI-phase measurement: measures the CRTM / early firmware into PCRs "
                      "before DXE, establishing the measured-boot chain of trust."),
    ("tpm20acpi", "tpm", "Publishes the TPM2 ACPI table that describes the TPM (interface type, "
                         "control-area address) to the OS."),
    ("tpm20platform", "tpm", "TPM 2.0 platform init: TPM2_Startup, self-test, hierarchy/PCR-bank setup."),
    ("amitpm20platform", "tpm", "AMI PEI-phase TPM 2.0 platform init."),
    ("tcgsmm", "tpm", "SMM handler for TPM Physical Presence and MOR (Memory Overwrite Request)."),
    ("tpmclearonrollbacksmm", "tpm", "SMM handler that clears the TPM if a firmware rollback is detected."),
    ("amipspftpmpei", "tpm", "AMI PEI glue for the AMD PSP firmware-TPM (fTPM)."),
    ("amdpspftpmdxe", "tpm", "AMD PSP firmware-TPM (fTPM) DXE backend: implements TPM 2.0 inside the "
                            "Platform Security Processor when no discrete TPM chip is present."),
    ("amdpspftpmpei", "tpm", "AMD PSP fTPM PEI backend (early fTPM bring-up)."),
    ("tpmsmbiosdxe", "tpm", "Bridges TPM->SMBIOS: adds the SMBIOS Type 43 (TPM Device) record."),
    ("smmtcgstoragesec", "tpm", "SMM side of TCG storage (Opal/SED) security - DMA-protected unlock path."),
    ("tcgstoragesecuritypei", "tpm", "PEI-phase TCG storage (self-encrypting drive) support."),
    ("tcgstoragesecurity", "tpm", "TCG Opal / self-encrypting-drive (SED) support (drive locking/unlock)."),
    ("tcgplatformsetuppeipolicy", "tpm", "PEI setup policy for TPM (enable state, PCR banks, PPI)."),
    ("tcgplatformsetuppolicy", "tpm", "BIOS-setup policy for TPM (enable/disable, PCR banks, physical presence)."),
    ("tcglegacy", "tpm", "Legacy INT1A/CSM TCG interface for non-UEFI OSes."),
    ("tpmnvmesupport", "tpm", "TPM measurement/handling path for NVMe devices."),
    ("amitcgnvflagsample", "tpm", "AMI TCG NV-flag sample (persisted TCG state flags)."),
    ("amitcgplatformpeibeforemem", "tpm", "AMI TCG platform init, PEI before memory is up."),
    ("amitcgplatformpeiaftermem", "tpm", "AMI TCG platform init, PEI after memory is up."),
    ("amitcgplatform", "tpm", "AMI TCG platform driver (board policy + measurement glue)."),
    ("tcg", "tpm", "TCG/TPM-related module (generic match)."),
    ("tpm", "tpm", "TPM-related module (generic match)."),

    # ---- IOMMU ----
    ("amdnbioiommurvdxe", "iommu", "AMD NBIO IOMMU driver (Raven/RV silicon): programs the IOMMU, builds IVRS."),
    ("amdnbioiommuzpdxe", "iommu", "AMD NBIO IOMMU driver (Zeppelin/ZP silicon)."),
    ("amdnbioiommurnpei", "iommu", "AMD NBIO IOMMU PEI init (Renoir/RN)."),
    ("amdnbioiommuzppei", "iommu", "AMD NBIO IOMMU PEI init (Zeppelin/ZP)."),
    ("amdnbioiommussppei", "iommu", "AMD NBIO IOMMU PEI init (Starship/SSP)."),
    ("amdnbioiommudxe", "iommu", "AMD NBIO IOMMU driver: programs the Northbridge-IO IOMMU, builds the "
                                "IVRS ACPI table, and produces EDKII_IOMMU_PROTOCOL for DMA protection."),
    ("iommu", "iommu", "IOMMU / DMA-remapping module (generic match)."),

    # ---- SMBIOS ----
    ("smbiosgetflashdata", "smbios", "Reads SMBIOS source data out of flash via FirmwareVolumeBlock2."),
    ("smbiosmeasurementdxe", "smbios", "Hashes the assembled SMBIOS table into a TPM PCR (SMBIOS<->TPM bridge)."),
    ("smbiosboard", "smbios", "Produces EFI_SMBIOS_BOARD_PROTOCOL: the board-specific Type 1/2/3 values."),
    ("smbiosdmiedit", "smbios", "SMM module that writes per-unit DMI fields (serial/UUID/asset) - the "
                               "factory/field DMI-edit path, gated behind System Management Mode."),
    ("gbtcrbsmbios", "smbios", "Gigabyte CRB SMBIOS contributor (vendor OEM records)."),
    ("crbsmbios", "smbios", "Reference-board SMBIOS contributor; carries the EFI_SMBIOS_STATIC_DATA template."),
    ("amdmemsmbiosv2", "smbios", "AGESA memory SMBIOS producer: Type 16/17 (physical memory array + DIMMs)."),
    ("amdsmbiosdxe", "smbios", "AMD AGESA SMBIOS producer (CPU/fabric records)."),
    ("smbiospeim", "smbios", "PEI-phase SMBIOS record contribution (via HOB)."),
    ("smbios", "smbios", "Core SMBIOS producer: reads the static template + board protocol and Adds records."),

    # ---- adjacent consumers worth surfacing ----
    ("smbiosdmi", "support", "DMI / SMBIOS edit-related support module."),
]

# ---------------------------------------------------------------------------
# ACPI table signatures -> meaning. Used by the raw signature scanner.
# ---------------------------------------------------------------------------
ACPI_KB = {
    "TPM2": ("tpm", "TPM 2.0 hardware description table: tells the OS the TPM interface "
                    "(CRB vs TIS/FIFO), the start method, and the control-area base."),
    "TCPA": ("tpm", "TCG 1.2 Client Platform table (legacy TPM event-log pointer)."),
    "IVRS": ("iommu", "AMD I/O Virtualization Reporting Structure: enumerates IOMMU units and "
                      "the device (BDF) -> IOMMU mappings the OS driver needs."),
    "DMAR": ("iommu", "Intel VT-d DMA Remapping table (Intel equivalent of IVRS; not expected on AMD)."),
    "WSMT": ("support", "Windows SMM Security Mitigation Table: advertises which SMM hardening "
                        "(fixed comm buffers, etc.) the firmware implements."),
    "SLIC": ("support", "OEM Windows license marker (software licensing)."),
    "MSDM": ("support", "OEM Windows product key table (digital license)."),
}

# SMBIOS type numbers -> name, for the decoder's report.
SMBIOS_TYPES = {
    0: "BIOS Information", 1: "System Information", 2: "Baseboard",
    3: "System Enclosure/Chassis", 4: "Processor", 7: "Cache",
    9: "System Slots", 11: "OEM Strings", 16: "Physical Memory Array",
    17: "Memory Device", 19: "Memory Array Mapped Address",
    32: "System Boot Information", 43: "TPM Device", 127: "End-of-Table",
}

# Values AMI uses for "field intentionally left unset".
SMBIOS_PLACEHOLDERS = {"default string", "to be filled by o.e.m.", "", "0000000000",
                       "system serial number", "system manufacturer", "system product name"}
