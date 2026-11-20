#!/usr/bin/env python3
"""Local terminal triage, bounded archives and a renderer for the existing probe.

Members are streamed to private, randomly located temporary files, never to
archive-supplied paths. No extract/extractall, member execution or network I/O.
"""
import argparse
import bz2
from dataclasses import dataclass, field
import fnmatch
import gzip
import lzma
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unicodedata
import xml.etree.ElementTree as ET
import zipfile
import zlib

VERSION = "4.0.0"
ROOT = Path(__file__).resolve().parents[1]
MIB = 1024 * 1024
DIRECTORY_LIMIT = 8 * MIB
DIRECTORY_ENTRIES = 10000

class ScanLimit(Exception):
    pass

class TimeLimit(ScanLimit):
    pass

class DTDRejected(ValueError):
    pass

class NoDTDTreeBuilder(ET.TreeBuilder):
    def doctype(self, name, pubid, system):
        raise DTDRejected("DTD is disabled")

def display(value, limit=360):
    """Escape terminal controls, bidi overrides and names containing newlines."""
    text = str(value)
    result = []
    for char in text[:limit]:
        number = ord(char)
        if unicodedata.category(char) in {"Cc", "Cf", "Cs"}:
            result.append(f"\\x{number:02x}" if number <= 255 else f"\\u{number:04x}")
        else:
            result.append(char)
    return "".join(result) + ("…" if len(text) > limit else "")

def human_size(size):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024

@dataclass
class Node:
    name: str
    depth: int = 0
    size: int = 0
    code: int = 1
    type_name: str = "sin analizar"
    mime: str = "no determinado"
    verdict: str = "análisis incompleto"
    lines: list = field(default_factory=list)
    notices: list = field(default_factory=list)
    children: list = field(default_factory=list)
    container: str = ""
    partial: bool = False
    def notice(self, message, review=False, partial=False):
        item = (message, review)
        if item not in self.notices:
            self.notices.append(item)
        self.partial |= partial
        if review and self.code != 2:
            self.code = 3

class ReaderBudget:
    """Seekable wrapper that bounds individual and cumulative TAR parser reads."""
    def __init__(self, source, allowance):
        self.source = source
        self.remaining = allowance
    def read(self, size=-1):
        if size < 0 or size > DIRECTORY_LIMIT or size > self.remaining:
            raise ScanLimit("lectura de metadatos o datos TAR superior al presupuesto")
        data = self.source.read(size)
        self.remaining -= len(data)
        return data
    def seek(self, *args):
        return self.source.seek(*args)
    def tell(self):
        return self.source.tell()
    def seekable(self):
        return True
    def readable(self):
        return True

class Scanner:
    def __init__(self, args, workspace):
        self.args = args
        self.workspace = Path(workspace)
        self.deadline = time.monotonic() + args.timeout
        self.entries = 0
        self.analyzed = 0
        self.skipped = 0
        self.expanded = 0
        self.sequence = 0
        self.roots = []
        self.stop = False

    def check_time(self):
        if time.monotonic() >= self.deadline:
            raise TimeLimit("límite global de tiempo alcanzado")

    def probe(self, path, node):
        self.check_time()
        process = subprocess.Popen(
            ["bash", str(ROOT / "lib/file_probe.sh"), "--verbose", "--max-bytes", str(self.args.max_bytes), "--", str(path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=max(.05, min(10, self.deadline - time.monotonic())))
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        text = stdout.decode("utf-8", errors="replace")
        node.lines = text.splitlines()
        node.code = process.returncode if process.returncode in (0, 1, 2, 3) else 2
        fields = {}
        for line in node.lines:
            key, separator, value = line.partition(": ")
            if separator:
                fields[key] = value
        node.type_name = fields.get("Tipo orientativo", "no identificado")
        node.mime = fields.get("MIME detectado", "no determinado")
        node.verdict = fields.get("Resultado", "el analizador no pudo completar la identificación")
        if node.code == 2:
            node.notice("Error del analizador: " + stderr.decode("utf-8", errors="replace").strip(), partial=True)
        sample = re.search(r"Muestra de contenido: (\d+)/(\d+)", text)
        if sample and int(sample[1]) < int(sample[2]):
            node.notice("Muestra de contenido limitada; quedan bytes sin inspeccionar por esa capa.", partial=True)
        if "ventana gramatical" in text or "primeros 131072 caracteres" in text or "Se alcanzó el límite" in text:
            node.partial = True
        self.analyzed += 1

    def path_findings(self, name, node, archive=False):
        normalized = name.replace("\\", "/")
        basename = normalized.rstrip("/").rsplit("/", 1)[-1]
        lowered = basename.lower()
        if archive and (normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized) or ".." in normalized.split("/")):
            node.notice("Ruta interna con traversal, absoluta o de unidad: revisar posible Zip Slip al extraer.", review=True)
        if archive and ":" in basename:
            node.notice("Nombre interno con ':'; revisar posibles Alternate Data Streams al escribir en Windows.", review=True)
        if any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in name):
            node.notice("Nombre con caracteres de control o de dirección de texto; se muestra escapado.", review=True)
        if lowered in {".htaccess", ".user.ini", "web.config"}:
            node.notice("Configuración de servidor presente; su efecto depende del servidor y del directorio de destino.", review=True)
        if re.search(r"\.(?:jpg|jpeg|png|gif|pdf|txt|docx)\.(?:php\d*|phtml|jsp|aspx?|exe|dll|sh)$", lowered):
            node.notice("Doble extensión con sufijo de código/ejecutable: revisar interpretación del nombre.", review=True)

    def compare_name(self, name, node):
        extension = name.replace("\\", "/").rsplit("/", 1)[-1].lower().rsplit(".", 1)[-1]
        families = {
            "png": {"image/png"}, "jpg": {"image/jpeg"}, "jpeg": {"image/jpeg"},
            "gif": {"image/gif"}, "webp": {"image/webp"}, "pdf": {"application/pdf"},
            "php": {"text/x-php", "application/x-php", "application/x-httpd-php", "text/plain", "text/html"},
            "phtml": {"text/x-php", "text/plain", "text/html"},
            "exe": {"application/x-dosexec", "application/vnd.microsoft.portable-executable"},
            "dll": {"application/x-dosexec", "application/vnd.microsoft.portable-executable"},
        }
        if extension in families and node.mime not in families[extension] and node.mime not in {"application/octet-stream", "no determinado", "inode/x-empty", "application/x-empty"}:
            node.notice(f"Extensión .{extension} y MIME {node.mime} no concuerdan según la tabla; el nombre no se usó para identificar.", review=True)

    def scan(self, path, node):
        self.check_time()
        node.size = path.stat().st_size
        self.probe(path, node)
        self.path_findings(node.name, node, archive=node.depth > 0)
        self.compare_name(node.name, node)
        if node.depth == 0 and self.args.expect and not fnmatch.fnmatchcase(node.mime.lower(), self.args.expect.lower()):
            node.notice(f"No cumple el MIME esperado {self.args.expect}; MIME local detectado: {node.mime}.", review=True)
        if node.code == 2:
            return
        with path.open("rb") as source:
            prefix = source.read(512)
        kind = None
        zip_metadata = None
        try:
            zip_metadata = self.zip_preflight(path)
            if zip_metadata:
                kind = "ZIP"
        except ScanLimit as error:
            if prefix.startswith(b"PK") or zip_metadata is not None:
                node.container = "ZIP"
                node.notice(str(error), partial=True)
                return
            # An EOCD that advertises an oversized directory is also worth
            # reporting when the file has a different leading header.
            node.notice("Posible ZIP adicional no inspeccionado: " + str(error), partial=True)
            return
        if kind is None:
            if prefix.startswith(b"\x1f\x8b"):
                kind = "GZIP"
            elif prefix.startswith(b"BZh"):
                kind = "BZIP2"
            elif prefix.startswith(b"\xfd7zXZ\0"):
                kind = "XZ"
            elif len(prefix) >= 512:
                try:
                    tarfile.TarInfo.frombuf(prefix, "utf-8", "surrogateescape")
                    kind = "TAR"
                except (tarfile.TarError, ValueError):
                    pass
        if not kind:
            if prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
                node.notice("Cabecera ZIP sin directorio final legible; contenedor truncado o inválido.", review=True, partial=True)
            elif prefix.startswith((b"Rar!", b"7z\xbc\xaf\x27\x1c", b"\x28\xb5\x2f\xfd", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")):
                node.notice("Formato reconocido sin parser interno en esta versión (RAR/7z/Zstd/OLE); contenido interno no examinado.", partial=True)
            return
        node.container = kind
        if self.args.max_depth == 0 or node.depth >= self.args.max_depth:
            node.notice(f"Inspección interna omitida: límite de profundidad {self.args.max_depth}.", partial=True)
            return
        if node.size > 512 * MIB:
            node.notice("Contenedor de más de 512 MiB: inspección interna omitida.", partial=True)
            return
        self.check_time()
        try:
            if kind == "ZIP":
                self.inspect_zip(path, node, zip_metadata, prefix)
            elif kind == "TAR":
                self.inspect_tar(path, node)
            else:
                self.inspect_compressed(path, node, kind)
        except TimeLimit:
            node.notice("Inspección de contenedor interrumpida por tiempo.", partial=True)
            raise
        except ScanLimit as error:
            node.notice(str(error), partial=True)
        except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, lzma.LZMAError, zlib.error, ValueError) as error:
            node.notice("Error o integridad no confirmada del contenedor: " + type(error).__name__, review=True, partial=True)

    def zip_preflight(self, path):
        size = path.stat().st_size
        with path.open("rb") as source:
            source.seek(max(0, size - 65557))
            tail = source.read(65557)
        position = tail.rfind(b"PK\x05\x06")
        if position < 0 or len(tail) - position < 22:
            return None
        disk, directory_disk, disk_entries, entries, directory_size, directory_offset, comment = struct.unpack_from("<HHHHIIH", tail, position + 4)
        if position + 22 + comment > len(tail):
            return None
        if disk or directory_disk or disk_entries != entries:
            raise ScanLimit("ZIP multipartes: análisis interno no soportado.")
        if entries == 65535 or directory_size == 0xffffffff or directory_offset == 0xffffffff:
            raise ScanLimit("Directorio ZIP64: se omite en esta versión para mantener límites de metadatos verificables.")
        if entries > DIRECTORY_ENTRIES or directory_size > DIRECTORY_LIMIT:
            raise ScanLimit("Directorio ZIP supera 10000 entradas u 8 MiB de metadatos; no se abrió.")
        return entries, directory_size

    def claim_entry(self):
        self.check_time()
        if self.entries >= self.args.max_members:
            raise ScanLimit(f"Presupuesto global de {self.args.max_members} entradas de contenedores agotado; quedan miembros sin examinar.")
        self.entries += 1

    def make_temp(self):
        self.sequence += 1
        return self.workspace / f"member-{self.sequence:05d}.bin"

    def copy_bounded(self, stream, destination, compressed_size=None):
        count = 0
        with destination.open("xb") as output:
            while True:
                self.check_time()
                allowance = min(self.args.max_member_mib * MIB - count, self.args.max_total_mib * MIB - self.expanded)
                data = stream.read(min(65536, max(1, allowance + 1)))
                if not data:
                    break
                self.expanded += len(data)
                count += len(data)
                if count > self.args.max_member_mib * MIB or self.expanded > self.args.max_total_mib * MIB:
                    raise ScanLimit("Límite real de bytes descomprimidos por miembro o global alcanzado; lectura detenida.")
                if compressed_size is not None and count / max(1, compressed_size) > self.args.max_ratio:
                    raise ScanLimit("Ratio real de expansión superior al límite; lectura detenida.")
                output.write(data)
        return count

    def entry(self, parent, name, declared_size=0):
        child = Node(name, parent.depth + 1, size=declared_size)
        parent.children.append(child)
        self.path_findings(name, child, archive=True)
        return child

    def skip(self, child, message, review=False):
        child.type_name = "no analizado"
        child.verdict = message
        child.notice(message, review=review, partial=True)
        self.skipped += 1

    def zip_package(self, infos, node):
        names = {info.filename.replace("\\", "/") for info in infos}
        office = "[Content_Types].xml" in names
        candidates = []
        for marker, label in [("word/document.xml", "Word OOXML (DOCX/DOCM)"), ("xl/workbook.xml", "Excel OOXML (XLSX/XLSM)"), ("ppt/presentation.xml", "PowerPoint OOXML (PPTX/PPTM)")]:
            if office and marker in names:
                candidates.append(label)
        if "AndroidManifest.xml" in names and ("classes.dex" in names or "resources.arsc" in names):
            candidates.append("paquete Android APK")
        if "META-INF/MANIFEST.MF" in names and any(name.endswith(".class") for name in names):
            candidates.append("paquete Java JAR")
        if "mimetype" in names and "META-INF/container.xml" in names:
            candidates.append("paquete EPUB")
        if candidates:
            node.notice("Estructura compatible con " + ", ".join(candidates) + "; marcadores internos, no validación completa del formato.")
        macros = [name for name in names if name.lower().endswith("/vbaproject.bin") or name.lower() == "vbaproject.bin"]
        if macros:
            node.notice(f"Componentes VBA declarados por nombre ({len(macros)}); posible contenido de macros, no se extrajo código VBA.", review=True)
        embedded = [name for name in names if re.match(r"^(?:word|xl|ppt)/embeddings/", name, re.I) and not name.endswith("/")]
        if embedded:
            node.notice(f"Objetos Office incrustados declarados: {len(embedded)}.", review=True)

    def contextualize_container(self, node, kind):
        # A readable PHP string in a valid TAR/ZIP can simply be one of its
        # ordinary source files. Preserve evidence without treating that alone
        # as a disguised binary/polyglot; member findings remain independent.
        compatible = ((kind == "ZIP" and (node.mime in {"application/zip", "application/x-zip", "application/x-zip-compressed", "application/java-archive", "application/x-java-archive", "application/epub+zip", "application/vnd.android.package-archive"} or node.mime.startswith(("application/vnd.openxmlformats-", "application/vnd.oasis.opendocument."))))
                      or (kind == "TAR" and node.mime == "application/x-tar")
                      or (kind == "GZIP" and node.mime in {"application/gzip", "application/x-gzip"})
                      or (kind == "BZIP2" and node.mime == "application/x-bzip2")
                      or (kind == "XZ" and node.mime == "application/x-xz"))
        if compatible and node.verdict.startswith("REVISAR CONTENIDO:"):
            if not any(review for _, review in node.notices):
                node.code = 1 if kind in {"GZIP", "BZIP2"} else 0
            node.verdict = "Contenedor identificado; las pistas de código se contextualizan en sus miembros."

    def relationship(self, name, path, node):
        if not name.lower().endswith(".rels"):
            return
        if path.stat().st_size > 128 * 1024:
            node.notice("Relaciones XML mayores de 128 KiB: comprobación de destinos externos omitida.", partial=True)
            return
        raw = path.read_bytes()
        if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)", raw, re.I):
            node.notice("Relaciones XML con DTD/ENTITY: parser omitido.", partial=True)
            return
        try:
            root = ET.fromstring(raw, parser=ET.XMLParser(target=NoDTDTreeBuilder()))
        except DTDRejected:
            node.notice("Relaciones XML con DTD/ENTITY: parser omitido.", partial=True)
            return
        except (ET.ParseError, ValueError):
            node.notice("Relaciones XML no parseables: destinos externos no comprobados.", partial=True)
            return
        count = sum(item.tag.rsplit("}", 1)[-1] == "Relationship" and item.attrib.get("TargetMode", "").lower() == "external" for item in root.iter())
        if count:
            node.notice(f"Relaciones externas en el documento: {count}; no se realizó ninguna conexión ni se confirma explotación.", review=True)

    def inspect_zip(self, path, node, metadata, prefix):
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if len(infos) > DIRECTORY_ENTRIES or len(infos) != metadata[0]:
                raise ScanLimit("Directorio ZIP inconsistente o superior al límite; no se recorrió.")
            node.notice(f"Directorio ZIP: {len(infos)} entradas declaradas.")
            if prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
                self.contextualize_container(node, "ZIP")
            if not prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
                node.notice("Estructura ZIP adicional tras otro encabezado: posible contenido concatenado o autoextraíble; revisar.", review=True)
            self.zip_package(infos, node)
            seen = set()
            for info in infos:
                self.claim_entry()
                name = info.orig_filename
                mode = info.external_attr >> 16
                if name in seen:
                    node.notice("Entradas con nombres duplicados; distintos lectores podrían elegir contenidos distintos.", review=True)
                seen.add(name)
                if info.is_dir():
                    self.path_findings(name, node, archive=True)
                    continue
                child = self.entry(node, name, info.file_size)
                if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                    self.skip(child, "Enlace o entrada especial: no se siguió ni materializó.", review=True)
                    continue
                if info.flag_bits & 1:
                    self.skip(child, "Miembro cifrado: contenido no analizado; no se probaron contraseñas.")
                    continue
                if info.file_size > self.args.max_member_mib * MIB or info.file_size > self.args.max_total_mib * MIB - self.expanded:
                    self.skip(child, "Tamaño declarado superior al presupuesto de descompresión.")
                    continue
                if info.file_size / max(1, info.compress_size) > self.args.max_ratio:
                    self.skip(child, "Ratio declarado de expansión superior al límite; posible riesgo de recursos, no prueba de bomba ZIP.", review=True)
                    continue
                temporary = self.make_temp()
                try:
                    with archive.open(info, "r") as stream:
                        self.copy_bounded(stream, temporary)
                    self.scan(temporary, child)
                    self.relationship(name, temporary, child)
                except (NotImplementedError, RuntimeError) as error:
                    self.skip(child, "Cifrado o método de compresión no soportado: " + type(error).__name__)
                except ScanLimit as error:
                    if isinstance(error, TimeLimit):
                        raise
                    self.skip(child, str(error))
                except (zipfile.BadZipFile, OSError, EOFError, zlib.error, ValueError) as error:
                    self.skip(child, "Integridad ZIP/CRC o lectura no confirmada: " + type(error).__name__, review=True)
                finally:
                    temporary.unlink(missing_ok=True)

    def inspect_tar(self, path, node):
        with path.open("rb") as source:
            reader = ReaderBudget(source, min(self.args.max_total_mib * MIB - self.expanded, 512 * MIB) + DIRECTORY_LIMIT)
            with tarfile.open(fileobj=reader, mode="r:") as archive:
                self.contextualize_container(node, "TAR")
                seen = set()
                for info in archive:
                    self.claim_entry()
                    if info.name in seen:
                        node.notice("Entradas TAR con nombres duplicados; revisar ambigüedad al extraer.", review=True)
                    seen.add(info.name)
                    if info.isdir():
                        self.path_findings(info.name, node, archive=True)
                        continue
                    child = self.entry(node, info.name, info.size)
                    if info.size < 0:
                        self.skip(child, "Tamaño negativo en cabecera TAR; entrada inválida.", review=True)
                        continue
                    if not info.isfile() or info.issparse():
                        self.skip(child, "Enlace, entrada especial o sparse TAR: no se siguió ni materializó.", review=True)
                        continue
                    if info.offset_data + info.size > node.size:
                        self.skip(child, "Miembro TAR excede el tamaño del contenedor; truncado o inválido.", review=True)
                        continue
                    if info.size > self.args.max_member_mib * MIB or info.size > self.args.max_total_mib * MIB - self.expanded:
                        self.skip(child, "Tamaño TAR declarado superior al presupuesto.")
                        continue
                    temporary = self.make_temp()
                    try:
                        with archive.extractfile(info) as stream:
                            self.copy_bounded(stream, temporary)
                        self.scan(temporary, child)
                    finally:
                        temporary.unlink(missing_ok=True)

    def inspect_compressed(self, path, node, kind):
        self.claim_entry()
        suffixes = {"GZIP": (".gz", ".tgz"), "BZIP2": (".bz2", ".tbz2"), "XZ": (".xz", ".txz")}
        suffix, tar_suffix = suffixes[kind]
        name = node.name.replace("\\", "/").rsplit("/", 1)[-1]
        if name.lower().endswith(tar_suffix):
            name = name[:-len(tar_suffix)] + ".tar"
        elif name.lower().endswith(suffix):
            name = name[:-len(suffix)]
        else:
            name = "contenido_descomprimido"
        child = self.entry(node, name)
        temporary = self.make_temp()
        opener = {"GZIP": gzip.open, "BZIP2": bz2.open, "XZ": lzma.open}[kind]
        try:
            with opener(path, "rb") as stream:
                self.copy_bounded(stream, temporary, compressed_size=max(1, node.size))
            self.contextualize_container(node, kind)
            self.scan(temporary, child)
        except ScanLimit as error:
            if isinstance(error, TimeLimit):
                raise
            self.skip(child, str(error), review="Ratio" in str(error))
        finally:
            temporary.unlink(missing_ok=True)

class Renderer:
    COLORS = {"blue": "\033[1;36m", "green": "\033[1;32m", "yellow": "\033[1;33m", "red": "\033[1;31m", "dim": "\033[2m"}
    def __init__(self, args):
        self.args = args
        self.color = args.color == "always" or (args.color == "auto" and sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb")
    def paint(self, value, color):
        return self.COLORS[color] + value + "\033[0m" if self.color else value
    def heading(self):
        print(self.paint(f"file_magic_number {VERSION}", "blue") + " · inspección local de archivos y contenedores", flush=True)
    def node(self, node):
        indent = "  " * node.depth
        label = {0: "CONCORDANTE", 1: "PARCIAL", 2: "ERROR", 3: "REVISAR"}[node.code]
        if node.partial and node.code == 0:
            label = "PARCIAL"
        color = "red" if node.code in (2, 3) else "yellow" if label == "PARCIAL" else "green"
        arrow = "↳ " if node.depth else "ARCHIVO · "
        print("\n" + indent + self.paint(arrow + display(node.name, 240), "blue") + self.paint("  [" + label + "]", color))
        shown_size = "no verificado" if node.type_name == "no analizado" and node.size == 0 else human_size(node.size)
        for key, value in [("Tipo", node.type_name), ("MIME", node.mime), ("Tamaño", shown_size)]:
            print(indent + "  " + key.ljust(9) + display(value))
        if node.container:
            print(indent + "  Contenedor " + self.paint(node.container, "blue"))
        print(indent + "  Evidencia " + display(node.verdict))
        for notice, review in node.notices:
            print(indent + "  " + self.paint("! " if review else "· ", "red" if review else "yellow") + display(notice))
        content = [line for line in node.lines if line.startswith("Contenido: ")]
        evidence = [line for line in node.lines if line.startswith("Magic [")]
        sample = [line for line in node.lines if line.startswith("Muestra de contenido:")]
        if sample:
            print(indent + "  " + self.paint(display(sample[0]), "dim"))
        for line in content:
            print(indent + "  " + self.paint("• ", "blue") + display(line))
        if self.args.verbose:
            for line in evidence + [line for line in node.lines if line.startswith(("Estructura básica:", "Descripción de file:", "Primeros 32 bytes", "Nota de contenido:"))]:
                print(indent + "  " + self.paint(display(line, 600), "dim"))
        elif evidence:
            for line in evidence[:2]:
                print(indent + "  " + self.paint(display(line.split(" | patrón ", 1)[0]), "dim"))
            if len(evidence) > 2:
                print(indent + "  " + self.paint("Más firmas: usa --verbose.", "dim"))
        for child in node.children:
            self.node(child)
    def summary(self, scanner, code):
        nodes = []
        def visit(node):
            nodes.append(node)
            for child in node.children:
                visit(child)
        for root in scanner.roots:
            visit(root)
        reviews = sum(n.code == 3 for n in nodes)
        partial = sum(n.partial for n in nodes)
        print("\n" + self.paint("RESUMEN", "blue"))
        print(f"  Analizados: {scanner.analyzed} · entradas de contenedores consideradas: {scanner.entries} · omitidos registrados: {scanner.skipped}")
        print(f"  Para revisar: {reviews} · nodos con alcance incompleto: {partial} · bytes descomprimidos: {human_size(scanner.expanded)}")
        print("  Alcance de la inspección: " + self.paint("INCOMPLETO" if partial or scanner.stop else "según los límites y parsers indicados", "yellow" if partial or scanner.stop else "dim"))
        print(f"  Código de salida: {code} · una identificación no certifica validez ni seguridad.")

def bounded_integer(low, high):
    def convert(value):
        if not re.fullmatch(r"[0-9]{1,9}", value) or not low <= int(value) <= high:
            raise argparse.ArgumentTypeError(f"debe ser un entero entre {low} y {high}")
        return int(value)
    return convert

def arguments(argv):
    parser = argparse.ArgumentParser(description="Identifica formatos y contenido; inspecciona contenedores con límites. Solo salida por terminal.",
                                     epilog="No genera informes, no ejecuta miembros y no escribe a las rutas del contenedor. Conserva data/ y lib/ junto al comando.")
    parser.add_argument("files", nargs="+", metavar="ARCHIVO")
    parser.add_argument("--version", action="version", version="file_magic_number " + VERSION)
    parser.add_argument("-v", "--verbose", action="store_true", help="mostrar firmas, bytes y evidencias detalladas")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="colores ANSI (auto por defecto)")
    parser.add_argument("--no-color", action="store_const", const="never", dest="color", help="desactivar colores")
    parser.add_argument("--max-bytes", type=bounded_integer(4096, 16 * MIB), default=MIB, help="muestra de contenido por archivo (bytes; defecto 1048576)")
    parser.add_argument("--max-depth", type=bounded_integer(0, 5), default=2, help="profundidad de contenedores (defecto 2; 0 omite interiores)")
    parser.add_argument("--no-archives", action="store_const", const=0, dest="max_depth", help="identificar contenedores sin recorrer sus miembros")
    parser.add_argument("--max-members", type=bounded_integer(1, 1000), default=50, help="presupuesto global de entradas, incluidos directorios (defecto 50)")
    parser.add_argument("--max-member-mib", type=bounded_integer(1, 64), default=8, help="límite descomprimido por miembro en MiB (defecto 8)")
    parser.add_argument("--max-total-mib", type=bounded_integer(1, 256), default=64, help="presupuesto global descomprimido en MiB (defecto 64)")
    parser.add_argument("--max-ratio", type=bounded_integer(1, 1000), default=200, help="máxima relación descomprimido/comprimido (defecto 200)")
    parser.add_argument("--timeout", type=bounded_integer(1, 120), default=30, help="segundos para todo el lote (defecto 30)")
    parser.add_argument("--expect", metavar="MIME", help="comparar el MIME local de los archivos raíz con un valor esperado; acepta image/*")
    args = parser.parse_args(argv)
    if len(args.files) > 100:
        parser.error("máximo 100 archivos raíz por lote")
    if args.expect and not re.fullmatch(r"[A-Za-z0-9.+-]+/(?:[A-Za-z0-9.+-]+|\*)", args.expect):
        parser.error("--expect requiere un MIME como application/pdf o image/*")
    return args

def aggregate(nodes):
    codes = []
    for node in nodes:
        codes.append(node.code)
        if node.partial:
            codes.append(1)
        codes.append(aggregate(node.children))
    if 2 in codes:
        return 2
    if 3 in codes:
        return 3
    return 1 if 1 in codes else 0

def finalize_tree(node):
    for child in node.children:
        finalize_tree(child)
    if any(child.partial or child.code == 2 for child in node.children):
        node.partial = True
    if any(child.code == 3 for child in node.children) and node.code != 2:
        node.code = 3
    elif node.code == 0 and any(child.code == 1 for child in node.children):
        node.code = 1

def main(argv=None):
    if sys.version_info < (3, 9):
        print("Error: se requiere Python 3.9 o superior.", file=sys.stderr)
        return 2
    args = arguments(argv)
    for name in ("lib/file_probe.sh", "lib/content_probe.py", "data/signatures.tsv"):
        if not (ROOT / name).is_file():
            print("Error: falta " + name + "; clona o actualiza el repositorio completo.", file=sys.stderr)
            return 2
    import resource
    for kind, requested in [(resource.RLIMIT_AS, 512 * MIB), (resource.RLIMIT_CPU, args.timeout + 1)]:
        inherited = resource.getrlimit(kind)
        bound = min([requested] + [value for value in inherited if value != resource.RLIM_INFINITY])
        resource.setrlimit(kind, (bound, bound))
    def alarm_handler(signum, frame):
        raise TimeLimit("límite global de tiempo alcanzado")
    previous = signal.signal(signal.SIGALRM, alarm_handler)
    renderer = Renderer(args)
    renderer.heading()
    with tempfile.TemporaryDirectory(prefix="file-magic-") as workspace:
        scanner = Scanner(args, workspace)
        signal.setitimer(signal.ITIMER_REAL, args.timeout)
        try:
            for name in args.files:
                node = Node(name)
                scanner.roots.append(node)
                path = Path(name).absolute()
                if not path.is_file():
                    node.code = 2
                    node.verdict = "la ruta no es un archivo regular accesible"
                    continue
                try:
                    scanner.scan(path, node)
                except subprocess.TimeoutExpired:
                    node.notice("El analizador agotó su tiempo; resultado incompleto.", partial=True)
                except (OSError, MemoryError) as error:
                    node.code = 2
                    node.verdict = "error de lectura o recursos: " + type(error).__name__
        except TimeLimit:
            if scanner.roots:
                scanner.roots[-1].notice("Límite global de tiempo alcanzado; quedan archivos o miembros sin analizar.", partial=True)
            scanner.stop = True
        except KeyboardInterrupt:
            print("\nAnálisis interrumpido; no se presenta como completo.", file=sys.stderr)
            return 130
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        for node in scanner.roots:
            finalize_tree(node)
        code = aggregate(scanner.roots)
        if scanner.stop and code == 0:
            code = 1
        for node in scanner.roots:
            renderer.node(node)
        renderer.summary(scanner, code)
        return code

if __name__ == "__main__":
    sys.exit(main())
