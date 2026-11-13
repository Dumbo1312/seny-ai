#!/usr/bin/env python3
"""
fwtriage - UEFI/BIOS firmware triage for TPM, IOMMU and SMBIOS.

A read-only static analyzer. Given a raw SPI/BIOS image it:
  * maps the flash firmware-volume layout,
  * extracts & walks every FFS module (via uefi-firmware-parser),
  * classifies modules into TPM / IOMMU / SMBIOS and explains each,
  * decodes the SMBIOS static-data template (Type 0/1/2/3) and pulls out the
    system UUID and every serial / asset field, flagging placeholders,
  * scans for the ACPI tables each subsystem publishes (TPM2, IVRS, ...),
  * cross-references which modules produce vs consume the key protocols,
  * prints a detailed report (and optional JSON).

It changes nothing. It is meant for understanding and auditing firmware.

Usage:
  fwtriage.py IMAGE [--extract-dir DIR] [--json OUT.json]
                    [--only tpm,iommu,smbios] [--no-explain] [--quiet]

Requires: uefi-firmware-parser on PATH (pip install uefi_firmware).
"""
import argparse, json, os, re, shutil, struct, subprocess, sys, tempfile, uuid
from dataclasses import dataclass, field, asdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import knowledge as KB

FVH_SIG = b"_FVH"           # firmware-volume header signature (at FV+0x28)
DEPEX_PUSH = 0x02           # EDK2 depex opcode: PUSH <16-byte GUID>


# ───────────────────────────── data model ─────────────────────────────────
@dataclass
class Module:
    guid: str
    ui: str = ""
    kind: str = ""                     # ffs file type (driver/peim/smm/...)
    size: int = 0
    category: str = ""                 # tpm / iommu / smbios / support / ""
    explanation: str = ""
    depex: list = field(default_factory=list)       # GUIDs the depex PUSHes
    protocols: list = field(default_factory=list)    # known protocol GUIDs found
    path: str = ""


@dataclass
class SmbiosStruct:
    type: int
    type_name: str
    handle: int
    strings: list = field(default_factory=list)
    uuid_raw: str = ""
    uuid_canonical: str = ""
    identifiers: dict = field(default_factory=dict)  # field -> value
    placeholder: bool = False


# ──────────────────────────── firmware image ──────────────────────────────
class FirmwareImage:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()

    def fv_map(self):
        """Locate every firmware volume by its _FVH signature."""
        out, i = [], 0
        d = self.data
        while True:
            j = d.find(FVH_SIG, i)
            if j < 0:
                break
            fv = j - 0x28                       # sig sits 0x28 into the FV header
            if fv >= 0:
                guid = str(uuid.UUID(bytes_le=d[fv:fv + 16]))
                length = struct.unpack_from("<Q", d, fv + 0x20)[0]
                if 0 < length <= len(d):
                    out.append({"offset": fv, "guid": guid, "length": length})
            i = j + 4
        return out

    def extract(self, outdir):
        """Decompress/extract all FVs/FFS/sections to a directory tree."""
        exe = shutil.which("uefi-firmware-parser")
        if not exe:
            sys.exit("error: uefi-firmware-parser not found (pip install uefi_firmware)")
        os.makedirs(outdir, exist_ok=True)
        subprocess.run([exe, "-b", "-e", "-o", outdir, self.path],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return outdir


# ──────────────────────────── module walker ───────────────────────────────
def _read_ui(d):
    f = os.path.join(d, "section2.ui")
    if os.path.exists(f):
        try:
            return open(f, "rb").read().decode("utf-16le", "ignore").strip("\x00").strip()
        except Exception:
            pass
    # some extractions name it differently; scan for any *.ui
    for fn in os.listdir(d):
        if fn.endswith(".ui"):
            try:
                return open(os.path.join(d, fn), "rb").read().decode("utf-16le", "ignore").strip("\x00").strip()
            except Exception:
                pass
    return ""


def _read_depex_guids(d):
    guids = []
    for fn in os.listdir(d):
        if fn.endswith(".depex"):
            blob = open(os.path.join(d, fn), "rb").read()
            k = 0
            while k < len(blob):
                op = blob[k]
                if op == DEPEX_PUSH and k + 17 <= len(blob):
                    guids.append(str(uuid.UUID(bytes_le=blob[k + 1:k + 17])))
                    k += 17
                else:
                    k += 1
    return guids


def _pe_blob(d):
    for fn in ("section1.pe", "file.obj"):
        p = os.path.join(d, fn)
        if os.path.exists(p):
            return open(p, "rb").read()
    return b""


def _classify(ui):
    low = ui.lower()
    for sub, cat, expl in KB.MODULE_KB:
        if sub in low:
            return cat, expl
    return "", ""


def walk_modules(extract_dir):
    mods, seen = [], set()
    guid_re = re.compile(r"file-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                         r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")
    protos = {k: v for k, v in KB.PROTOCOL_GUIDS.items()}
    proto_le = {uuid.UUID(g).bytes_le: g for g in protos}
    for dp, dirs, files in os.walk(extract_dir):
        m = guid_re.search(os.path.basename(dp))
        if not m:
            continue
        guid = m.group(1).lower()
        ui = _read_ui(dp)
        key = (guid, ui)
        if key in seen:
            continue
        seen.add(key)
        pe = _pe_blob(dp)
        found = [proto_le[sig] for sig in proto_le if sig in pe]
        cat, expl = _classify(ui)
        # a module with no name but referencing a subsystem protocol still counts
        if not cat and found:
            cat = KB.PROTOCOL_GUIDS[found[0]][0]
            expl = "(classified by referenced protocol) " + KB.PROTOCOL_GUIDS[found[0]][2]
        mods.append(Module(guid=guid, ui=ui, size=len(pe), category=cat,
                           explanation=expl, depex=_read_depex_guids(dp),
                           protocols=found, path=os.path.relpath(dp, extract_dir)))
    return mods


# ─────────────────────────── SMBIOS decoder ───────────────────────────────
def _resolve(strings, idx):
    return strings[idx - 1] if 1 <= idx <= len(strings) else ""


def parse_smbios_stream(blob, start):
    structs, pos = [], start
    while pos + 4 <= len(blob):
        stype, length = blob[pos], blob[pos + 1]
        if length < 4 or pos + length > len(blob):
            break
        handle = struct.unpack_from("<H", blob, pos + 2)[0]
        formatted = blob[pos:pos + length]
        # string set follows, terminated by 00 00
        sp = pos + length
        strings, cur = [], bytearray()
        while sp < len(blob):
            b = blob[sp]
            if b == 0:
                if cur:
                    strings.append(cur.decode("latin-1")); cur = bytearray()
                    sp += 1
                    if sp < len(blob) and blob[sp] == 0:   # double null -> end
                        sp += 1; break
                else:
                    sp += 1; break                          # empty string set
            else:
                cur.append(b); sp += 1
        s = SmbiosStruct(type=stype, type_name=KB.SMBIOS_TYPES.get(stype, f"Type {stype}"),
                         handle=handle, strings=strings)
        if stype == 0:
            s.identifiers = {"Vendor": _resolve(strings, formatted[4] if length > 4 else 0),
                             "Version": _resolve(strings, formatted[5] if length > 5 else 0),
                             "ReleaseDate": _resolve(strings, formatted[8] if length > 8 else 0)}
        elif stype == 1 and length >= 25:
            raw = formatted[8:24]
            s.uuid_raw = raw.hex()
            s.uuid_canonical = _smbios_uuid(raw)
            s.identifiers = {"Manufacturer": _resolve(strings, formatted[4]),
                             "Product": _resolve(strings, formatted[5]),
                             "Version": _resolve(strings, formatted[6]),
                             "Serial": _resolve(strings, formatted[7]),
                             "UUID": s.uuid_canonical}
            if length >= 27:
                s.identifiers["SKU"] = _resolve(strings, formatted[25])
                s.identifiers["Family"] = _resolve(strings, formatted[26])
        elif stype == 2 and length >= 8:
            s.identifiers = {"Manufacturer": _resolve(strings, formatted[4]),
                             "Product": _resolve(strings, formatted[5]),
                             "Version": _resolve(strings, formatted[6]),
                             "Serial": _resolve(strings, formatted[7])}
        elif stype == 3 and length >= 9:
            s.identifiers = {"Manufacturer": _resolve(strings, formatted[4]),
                             "Serial": _resolve(strings, formatted[6]) if length > 6 else "",
                             "AssetTag": _resolve(strings, formatted[8]) if length > 8 else ""}
        # placeholder heuristic
        vals = [str(v).strip().lower() for v in s.identifiers.values()]
        if vals and all((v in KB.SMBIOS_PLACEHOLDERS or v == "") for v in vals if v is not None):
            s.placeholder = True
        structs.append(s)
        pos = sp
        if stype == 127:
            break
    return structs


def _smbios_uuid(raw):
    """SMBIOS 2.6+ stores the first 3 UUID fields little-endian."""
    if len(raw) != 16:
        return ""
    if all(b == 0 for b in raw):
        return "00000000-0000-0000-0000-000000000000 (UNSET/zero)"
    if all(b == 0xFF for b in raw):
        return "ffffffff-ffff-ffff-ffff-ffffffffffff (UNSET/0xFF)"
    d1 = struct.unpack_from("<I", raw, 0)[0]
    d2 = struct.unpack_from("<H", raw, 4)[0]
    d3 = struct.unpack_from("<H", raw, 6)[0]
    rest = raw[8:]
    return "%08x-%04x-%04x-%s-%s" % (d1, d2, d3, rest[:2].hex(), rest[2:].hex())


def find_and_decode_smbios(extract_dir):
    """Locate the EFI_SMBIOS_STATIC_DATA file and decode it; fall back to a scan."""
    target = "daf4bf89-ce71-4917-b522-c89d32fbc59f"
    candidates = []
    for dp, _, files in os.walk(extract_dir):
        if target in dp.lower():
            for fn in files:
                if fn.endswith(".freeform.guid") or fn == "file.obj":
                    candidates.append(os.path.join(dp, fn))
    for c in candidates:
        blob = open(c, "rb").read()
        for start in (0x10, 0x0, 0x18):            # skip the leading data GUID
            if start < len(blob) and blob[start] == 0 and 0x12 <= blob[start + 1] <= 0x1b:
                structs = parse_smbios_stream(blob, start)
                if len(structs) >= 2:
                    return structs, os.path.relpath(c, extract_dir)
    return [], ""


# ───────────────────────────── ACPI scan ──────────────────────────────────
def scan_acpi(image_data, extract_dir):
    hits = {}
    sigs = {s.encode(): s for s in KB.ACPI_KB}
    blobs = [("raw-image", image_data)]
    for dp, _, files in os.walk(extract_dir):
        for fn in files:
            if fn in ("section1.pe", "file.obj") or fn.endswith(".raw"):
                try:
                    blobs.append((os.path.basename(dp)[:28], open(os.path.join(dp, fn), "rb").read()))
                except Exception:
                    pass
    for where, d in blobs:
        for sig_b, sig in sigs.items():
            i = 0
            while True:
                j = d.find(sig_b, i)
                if j < 0:
                    break
                ln = struct.unpack_from("<I", d, j + 4)[0] if j + 8 <= len(d) else 0
                if 0x24 <= ln <= 0x100000:        # plausible ACPI table length
                    hits.setdefault(sig, set()).add(where)
                i = j + 1
    return hits


# ─────────────────────────────── report ───────────────────────────────────
def build_report(img, modules, smbios, acpi):
    cats = {"tpm": [], "iommu": [], "smbios": [], "support": []}
    for m in modules:
        if m.category in cats:
            cats[m.category].append(m)
    return {"image": img.path, "size": len(img.data),
            "fv_map": img.fv_map(),
            "modules": {c: [asdict(m) for m in ms] for c, ms in cats.items()},
            "smbios": [asdict(s) for s in smbios],
            "acpi": {k: sorted(v) for k, v in acpi.items()}}


def _crossref(modules, proto_guid):
    return sorted({m.ui or m.guid for m in modules if proto_guid in m.protocols})


def print_report(img, modules, smbios, smbios_src, acpi, only, explain):
    W = 78
    def rule(c="─"): print(c * W)
    def head(t): rule("━"); print(t); rule("━")

    head(f"fwtriage report :: {os.path.basename(img.path)}  ({len(img.data):,} bytes)")
    print("Firmware volumes (flash layout):")
    for fv in img.fv_map():
        print(f"  @0x{fv['offset']:08x}  len=0x{fv['length']:08x}  fsguid={fv['guid']}")
    print()

    cat_titles = {"tpm": "TPM / TCG  (measured boot, attestation, key storage)",
                  "iommu": "IOMMU  (DMA remapping / pre-boot DMA protection)",
                  "smbios": "SMBIOS  (platform description & identity tables)"}
    for cat in ("tpm", "iommu", "smbios"):
        if only and cat not in only:
            continue
        ms = sorted([m for m in modules if m.category == cat], key=lambda m: m.ui.lower())
        head(f"{cat_titles[cat]}  —  {len(ms)} module(s)")
        for m in ms:
            tag = f"[{m.kind or 'module'}]"
            print(f"  • {m.ui or m.guid:30} {tag}")
            if explain and m.explanation:
                for line in _wrap(m.explanation, W - 6):
                    print(f"      {line}")
            if m.protocols:
                for g in m.protocols:
                    nm = KB.PROTOCOL_GUIDS[g][1]
                    print(f"      ↳ references {nm}")
        print()

    # protocol producer/consumer cross-reference
    if not only or {"tpm", "iommu", "smbios"} & set(only):
        head("Protocol / config-table cross-reference")
        for g, (cat, name, desc) in KB.PROTOCOL_GUIDS.items():
            if only and cat not in only:
                continue
            users = _crossref(modules, g)
            if users:
                print(f"  {name}  [{cat}]")
                for line in _wrap(desc, W - 6):
                    print(f"      {line}")
                print(f"      modules: {', '.join(users)}")
        print()

    # ACPI
    if not only or {"tpm", "iommu", "support"} & set(only):
        head("ACPI tables published for the OS")
        if not acpi:
            print("  (none detected)")
        for sig, (cat, desc) in KB.ACPI_KB.items():
            if sig in acpi and (not only or cat in only or cat == "support"):
                print(f"  {sig}  [{cat}]  seen in: {', '.join(sorted(acpi[sig])[:6])}"
                      + (" ..." if len(acpi[sig]) > 6 else ""))
                for line in _wrap(desc, W - 6):
                    print(f"      {line}")
        print()

    # SMBIOS identity decode
    if not only or "smbios" in only:
        head("SMBIOS identity decode  (serials & UUID)")
        if not smbios:
            print("  (static SMBIOS data not located)")
        else:
            print(f"  source: {smbios_src}\n")
            for s in smbios:
                if s.identifiers:
                    flag = "  <-- all placeholder/unset" if s.placeholder else ""
                    print(f"  Type {s.type} ({s.type_name}) handle 0x{s.handle:04x}{flag}")
                    for k, v in s.identifiers.items():
                        mark = ""
                        if v and str(v).strip().lower() in KB.SMBIOS_PLACEHOLDERS:
                            mark = "   [placeholder]"
                        print(f"      {k:14}: {v}{mark}")
                    print()
        print("  Note: on a retail board the Serial/UUID are programmed per-unit at the")
        print("  factory (written via the SMM DMI-edit path) and are NOT carried in a")
        print("  downloadable BIOS update, so placeholders here are expected.")
        print()

    # identity summary across subsystems
    head("Identity / 'serial' summary across the three subsystems")
    print("  SMBIOS : Type1 UUID + SerialNumber, Type2 board serial, Type3 chassis")
    print("           serial/asset — the OS-visible machine fingerprint (dmidecode).")
    print("  TPM    : no serial in flash. The unique key (Endorsement Key) lives")
    print("           inside the TPM/fTPM; firmware only sets it up, measures boot")
    print("           state into PCRs, and describes it via the TPM2 ACPI table.")
    print("  IOMMU  : no per-unit serial. Identity here = device IDs (PCI B/D/F) in")
    print("           the IVRS table mapping each device to an IOMMU unit.")
    rule()


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line); line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return out


# ─────────────────────────────── main ─────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="TPM/IOMMU/SMBIOS firmware triage (read-only).")
    ap.add_argument("image", help="raw BIOS/SPI image")
    ap.add_argument("--extract-dir", help="reuse/keep extraction here (else a temp dir)")
    ap.add_argument("--json", help="write full findings as JSON")
    ap.add_argument("--only", help="comma list: tpm,iommu,smbios")
    ap.add_argument("--no-explain", action="store_true", help="omit per-module explanations")
    ap.add_argument("--quiet", action="store_true", help="suppress progress on stderr")
    args = ap.parse_args()

    only = set(x.strip() for x in args.only.split(",")) if args.only else None
    img = FirmwareImage(args.image)

    tmp = args.extract_dir or tempfile.mkdtemp(prefix="fwtriage_")
    if not args.quiet:
        print(f"[*] extracting modules -> {tmp}", file=sys.stderr)
    reuse = args.extract_dir and os.path.isdir(args.extract_dir) and os.listdir(args.extract_dir)
    if not reuse:
        img.extract(tmp)

    if not args.quiet:
        print("[*] walking modules ...", file=sys.stderr)
    modules = walk_modules(tmp)
    if not args.quiet:
        print("[*] decoding SMBIOS static data ...", file=sys.stderr)
    smbios, smbios_src = find_and_decode_smbios(tmp)
    if not args.quiet:
        print("[*] scanning ACPI signatures ...", file=sys.stderr)
    acpi = scan_acpi(img.data, tmp)

    print_report(img, modules, smbios, smbios_src, acpi, only,
                 explain=not args.no_explain)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(build_report(img, modules, smbios, acpi), f, indent=2)
        if not args.quiet:
            print(f"[*] wrote {args.json}", file=sys.stderr)

    if not args.extract_dir:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
