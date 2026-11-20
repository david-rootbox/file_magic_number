#!/usr/bin/env python3
"""Build an offline Bash-readable signature table from vendored JSON data.

Parses data only: never imports or executes code from the upstream project.
Run from any directory: python3 tools/build_signatures.py
"""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "data/upstream"

# family: label | representative extensions | compatible MIME aliases | minimum size
# Compatibility means the same family, NOT structural validity.
FORMATS = {
    "png": ("imagen PNG", "png", "image/png", 45),
    "jpg": ("imagen JPEG", "jpg,jpeg,jpe", "image/jpeg", 4),
    "gif": ("imagen GIF", "gif", "image/gif", 14),
    "webp": ("imagen WebP", "webp", "image/webp", 20),
    "bmp": ("imagen BMP", "bmp", "image/bmp,image/x-ms-bmp", 26),
    "tif": ("imagen TIFF", "tif,tiff", "image/tiff", 8),
    "cr2": ("imagen Canon RAW CR2", "cr2", "image/x-canon-cr2,image/tiff", 16),
    "ico": ("icono ICO", "ico", "image/x-icon,image/vnd.microsoft.icon", 22),
    "jp2": ("imagen JPEG 2000", "jp2,j2k", "image/jp2,image/jpeg2000", 12),
    "jxl": ("imagen JPEG XL", "jxl", "image/jxl", 2),
    "qoi": ("imagen QOI", "qoi", "image/qoi,image/x-qoi", 14),
    "pdf": ("documento PDF", "pdf", "application/pdf", 14),
    "ps": ("documento PostScript", "ps", "application/postscript", 4),
    "eps": ("documento EPS", "eps", "application/postscript", 24),
    "zip": ("contenedor ZIP; subtipo no determinado por la firma", "zip", "application/zip,application/x-zip,application/x-zip-compressed,application/java-archive,application/x-java-archive,application/epub+zip,application/vnd.android.package-archive,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.openxmlformats-officedocument.presentationml.presentation,application/vnd.oasis.opendocument.text,application/vnd.oasis.opendocument.spreadsheet,application/vnd.oasis.opendocument.presentation", 22),
    "ole": ("contenedor OLE/CFB; puede ser DOC, XLS, PPT, MSI u otro", "ole,cfb", "application/x-ole-storage,application/CDFV2,application/x-cdf,application/msword,application/vnd.ms-excel,application/vnd.ms-powerpoint,application/x-msi,application/vnd.ms-outlook", 512),
    "ar": ("contenedor ar; puede ser biblioteca o paquete DEB", "ar,a,deb", "application/x-archive,application/vnd.debian.binary-package,application/x-debian-package", 8),
    "ebml": ("contenedor EBML; puede ser Matroska o WebM", "mkv,webm", "video/x-matroska,audio/x-matroska,video/webm,audio/webm", 8),
    "bmff": ("familia ISO BMFF; puede ser MP4, HEIF, AVIF u otra", "mp4,heif,avif", "video/mp4,audio/mp4,image/heif,image/heic,image/avif,video/quicktime,video/3gpp", 16),
    "gz": ("archivo GZIP", "gz,tgz", "application/gzip,application/x-gzip", 18),
    "bz2": ("archivo BZIP2", "bz2", "application/x-bzip2", 10),
    "xz": ("archivo XZ", "xz", "application/x-xz", 12),
    "rar": ("archivo RAR", "rar", "application/vnd.rar,application/x-rar,application/x-rar-compressed", 7),
    "7z": ("archivo 7-Zip", "7z", "application/x-7z-compressed", 32),
    "zst": ("archivo Zstandard", "zst", "application/zstd,application/x-zstd", 6),
    "lz4": ("archivo LZ4", "lz4", "application/x-lz4", 7),
    "tar": ("contenedor TAR", "tar", "application/x-tar", 512),
    "sqlite": ("base de datos SQLite", "sqlite,sqlite3,db", "application/vnd.sqlite3,application/x-sqlite3", 100),
    "elf": ("binario ELF", "elf,so", "application/x-executable,application/x-pie-executable,application/x-sharedlib,application/x-object,application/x-coredump", 52),
    "mz": ("familia MZ; puede ser DOS, EXE, DLL u otro", "exe,dll", "application/x-dosexec,application/vnd.microsoft.portable-executable", 64),
    "cafebabe": ("firma compartida: Java class o Mach-O universal", "class,macho", "application/x-java-applet,application/java-vm,application/x-mach-binary", 8),
    "macho": ("binario Mach-O", "macho,o", "application/x-mach-binary", 28),
    "wasm": ("binario WebAssembly", "wasm", "application/wasm", 8),
    "ogg": ("contenedor Ogg", "ogg,oga,ogv,opus", "application/ogg,audio/ogg,video/ogg", 27),
    "mp3": ("audio MPEG o etiqueta ID3", "mp3", "audio/mpeg", 10),
    "wav": ("audio WAV", "wav", "audio/x-wav,audio/wav,audio/vnd.wave", 12),
    "avi": ("contenedor AVI", "avi", "video/x-msvideo", 12),
    "aiff": ("audio AIFF", "aif,aiff", "audio/x-aiff,audio/aiff", 12),
    "flac": ("audio FLAC", "flac", "audio/flac,audio/x-flac", 8),
    "mid": ("audio MIDI", "mid,midi", "audio/midi,audio/x-midi", 14),
    "pcap": ("captura de red PCAP", "pcap,cap", "application/vnd.tcpdump.pcap,application/x-pcap", 24),
    "pcapng": ("captura de red PCAPNG", "pcapng", "application/x-pcapng", 28),
    "iso": ("imagen de disco ISO 9660", "iso", "application/x-iso9660-image", 34816),
    "dcm": ("imagen DICOM", "dcm,dicom", "application/dicom", 132),
    "dmg": ("imagen de disco Apple DMG", "dmg", "application/x-apple-diskimage", 512),
    "xml": ("familia de documentos XML", "xml", "application/xml,text/xml,image/svg+xml", 5),
    "svg": ("imagen SVG", "svg", "image/svg+xml", 5),
    "rtf": ("documento RTF", "rtf", "application/rtf,text/rtf", 7),
    "rpm": ("paquete RPM", "rpm", "application/x-rpm", 96),
    "woff": ("fuente WOFF", "woff", "font/woff,application/font-woff", 44),
    "woff2": ("fuente WOFF2", "woff2", "font/woff2", 48),
    "otf": ("fuente OpenType", "otf", "font/otf,application/vnd.ms-opentype", 12),
    "ttf": ("fuente TrueType", "ttf", "font/ttf,application/x-font-ttf", 12),
}

SPECIAL = {
    "7F454C46": "elf", "D0CF11E0A1B11AE1": "ole", "4D5A": "mz", "5A4D": "mz",
    "CAFE BABE".replace(" ", ""): "cafebabe", "213C617263683E0A": "ar",
    "1A45DFA3": "ebml", "53514C69746520666F726D6174203300": "sqlite",
    "716F6966": "qoi", "FEEDFACE": "macho", "FEEDFACF": "macho",
    "CEFAEDFE": "macho", "CFFAEDFE": "macho", "50415231": "parquet",
}

def main():
    records = []
    skipped = []

    def append(offset, pattern, extension, origin):
        pattern = pattern.replace(" ", "").lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}|\?\?)+", pattern):
            raise ValueError(f"Invalid pattern: {pattern}")
        if len(pattern.replace("?", "")) < 4 or set(pattern) <= {"0", "?"}:
            skipped.append((origin, "firma trivial, de un byte o solo ceros"))
            return
        if extension.lower() == "txt" or pattern.startswith("2b2f76"):
            skipped.append((origin, "marca de codificación; no identifica un formato único"))
            return
        group = SPECIAL.get(pattern.upper(), extension.lower())
        if not group or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", group):
            skipped.append((origin, "sin nombre utilizable"))
            return
        if group in {"mp4", "3gp"}:
            group = "bmff"
        label, extensions, mimes, minimum = FORMATS.get(group, (f"firma asociada a .{group}", group, "-", 0))
        if group == "doc":  # Old DeskMate signature is not a Word document.
            label = "documento DeskMate (no identifica un documento Word)"
        if any(c in label for c in "\t\r\n"):
            raise ValueError("Unsafe label")
        records.append((group, int(offset), pattern, extensions, mimes, label, minimum, origin))

    rows = json.loads((UPSTREAM / "rows_map.json").read_text())
    for key, row in rows.items():
        magic, offset, extensions, continuations, gap, repeat = row
        if repeat:
            skipped.append((key, "regla periódica: no basta un marcador de un byte"))
            continue
        if any(continuations):
            if len(extensions) != len(continuations):
                raise ValueError("Unpaired continuations")
            for extension, continuation in zip(extensions, continuations):
                append(offset, magic + " ??" * gap + " " + continuation, extension, key)
        else:
            for extension in extensions:
                append(offset, magic, extension, key)
    for magic, offset, extension in json.loads((UPSTREAM / "offset_list.json").read_text()):
        append(offset, magic, extension, f"offset:{offset}:{magic}")

    # Explicit local additions/corrections: generic JPEG SOI marker sequence,
    # ISO BMFF family (the brand must not be mistaken for a unique MP4 type),
    # current SQLite aliases are supplied by FORMATS above.
    append(0, "FF D8 FF", "jpg", "local:jpeg-soi")
    append(4, "66 74 79 70", "mp4", "local:iso-bmff")
    # Do not turn the XML-like SVG prefix into a format assertion by itself.
    # It remains independent evidence, and MIME agreement is still required.

    records = sorted(set(records), key=lambda r: (r[0], r[1], r[2], r[7]))
    source = json.loads((UPSTREAM / "source.json").read_text())
    for filename, expected in source["sha256"].items():
        actual = hashlib.sha256((UPSTREAM / filename).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"Source checksum mismatch: {filename}")
    lines = ["# file_magic_number signatures v2", f"# Source: {source['repository']} @ {source['commit']}",
             "# id\tfamily\toffset\thex-pattern\textensions\tmimes\tlabel\tminimum-size"]
    for index, (group, offset, pattern, extensions, mimes, label, minimum, origin) in enumerate(records, 1):
        lines.append(f"S{index:04d}\t{group}\t{offset}\t{pattern}\t{extensions}\t{mimes}\t{label}\t{minimum}")
    destination = ROOT / "data/signatures.tsv"
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    summary = {"rules": len(records), "families": len({r[0] for r in records}), "excluded": skipped}
    (ROOT / "data/import-report.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(f"Built {len(records)} rules, {summary['families']} families; {len(skipped)} excluded entries.")

if __name__ == "__main__":
    main()
