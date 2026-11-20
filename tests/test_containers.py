#!/usr/bin/env python3
"""Public CLI, resource boundaries and hostile archive regression fixtures."""
import bz2
import gzip
import io
import lzma
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tarfile
import tempfile
import time
import unittest
import warnings
import zipfile

from test_detector import PNG

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "file_magic_number"
PHP = b'\n<?= $nombre ?>\n'

def zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w", compression=compression) as archive:
            for name, content in entries:
                archive.writestr(name, content)
    return stream.getvalue()

def tar_bytes(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return stream.getvalue()

class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def write(self, name, content):
        path = self.work / name
        path.write_bytes(content)
        return path

    def run_cli(self, *args, code=None, env=None, script=SCRIPT):
        process = subprocess.run(["bash", str(script), *map(str, args)], cwd=self.work,
                                 env=env, capture_output=True, text=True, timeout=15)
        text = process.stdout + process.stderr
        self.assertNotIn("Traceback (most recent call last)", text)
        if code is not None:
            self.assertEqual(process.returncode, code, text)
        return process.returncode, text

    def test_version_and_help(self):
        self.assertIn("4.0.0", self.run_cli("--version", code=0)[1])
        self.assertIn("--max-depth", self.run_cli("--help", code=0)[1])

    def test_png_plain_terminal_layout(self):
        path = self.write("photo.png", PNG)
        result = self.run_cli(path, code=0)[1]
        for field in ("ARCHIVO", "Tipo", "MIME", "RESUMEN", "Analizados: 1"):
            self.assertIn(field, result)
        self.assertNotIn("\x1b", result)

    def test_forced_color(self):
        result = self.run_cli("--color", "always", self.write("photo.png", PNG), code=0)[1]
        self.assertIn("\x1b[", result)

    def test_no_color_override(self):
        result = self.run_cli("--color", "always", "--no-color", self.write("photo.png", PNG), code=0)[1]
        self.assertNotIn("\x1b", result)

    def test_zip_member_php(self):
        path = self.write("sample.zip", zip_bytes([("inside.php", PHP)]))
        result = self.run_cli(path, code=1)[1]
        self.assertIn("↳ inside.php", result)
        self.assertIn("código PHP probable", result)
        self.assertIn("Analizados: 2", result)

    def test_nested_archive(self):
        nested = zip_bytes([("image.jpg", PHP)])
        path = self.write("nested.zip", zip_bytes([("folder/inner.zip", nested)]))
        result = self.run_cli(path, code=3)[1]
        self.assertIn("↳ folder/inner.zip", result)
        self.assertIn("↳ image.jpg", result)
        self.assertIn("Extensión .jpg", result)

    def test_depth_limit_is_visible(self):
        nested = zip_bytes([("hidden.php", PHP)])
        path = self.write("nested.zip", zip_bytes([("inner.zip", nested)]))
        result = self.run_cli("--max-depth", "1", path)[1]
        self.assertIn("límite de profundidad 1", result)
        self.assertNotIn("↳ hidden.php", result)
        self.assertIn("alcance incompleto", result)

    def test_archives_can_be_disabled(self):
        path = self.write("skip.zip", zip_bytes([("inside.txt", b"hola")]))
        result = self.run_cli("--no-archives", path, code=1)[1]
        self.assertNotIn("↳ inside.txt", result)
        self.assertIn("límite de profundidad 0", result)

    def test_empty_zip(self):
        path = self.write("empty.zip", zip_bytes([]))
        self.assertIn("0 entradas declaradas", self.run_cli(path, code=0)[1])

    def test_truncated_zip(self):
        path = self.write("broken.zip", zip_bytes([("hello", b"hola")])[:-22])
        self.assertIn("truncado o inválido", self.run_cli(path, code=3)[1])

    def test_zip_crc_failure(self):
        data = bytearray(zip_bytes([("hello.txt", b"unique-fixture-data")], zipfile.ZIP_STORED))
        data[data.index(b"unique-fixture-data")] ^= 1
        result = self.run_cli(self.write("bad-crc.zip", data), code=3)[1]
        self.assertIn("Integridad ZIP/CRC", result)

    def test_zip_slip_does_not_write_to_member_paths(self):
        path = self.write("slip.zip", zip_bytes([("../ESCAPED", PHP), ("/tmp/ESCAPED-FILE-MAGIC", b"hola")]))
        before = sorted(str(p.relative_to(self.work)) for p in self.work.rglob("*"))
        result = self.run_cli(path, code=3)[1]
        self.assertIn("traversal", result)
        self.assertEqual(before, sorted(str(p.relative_to(self.work)) for p in self.work.rglob("*")))
        self.assertFalse((self.work.parent / "ESCAPED").exists())

    def test_windows_member_paths(self):
        path = self.write("windows.zip", zip_bytes([("C:\\Windows\\sample.txt", b"hola"), ("..\\escape.php", PHP)]))
        self.assertIn("unidad", self.run_cli(path, code=3)[1])

    def test_duplicate_zip_names(self):
        path = self.write("duplicates.zip", zip_bytes([("same.txt", b"one"), ("same.txt", b"two")]))
        self.assertIn("nombres duplicados", self.run_cli(path, code=3)[1])

    def test_zip_symlink_is_not_followed(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            info = zipfile.ZipInfo("link.txt")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "/etc/passwd")
        result = self.run_cli(self.write("symlink.zip", stream.getvalue()), code=3)[1]
        self.assertIn("Enlace o entrada especial", result)
        self.assertNotIn("root:x:", result)

    def test_zip_encrypted_member_is_skipped(self):
        data = bytearray(zip_bytes([("secret.txt", b"secret")], zipfile.ZIP_STORED))
        local = data.index(b"PK\x03\x04")
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<H", data, local + 6, struct.unpack_from("<H", data, local + 6)[0] | 1)
        struct.pack_into("<H", data, central + 8, struct.unpack_from("<H", data, central + 8)[0] | 1)
        result = self.run_cli(self.write("encrypted.zip", data), code=1)[1]
        self.assertIn("Miembro cifrado", result)
        self.assertIn("Analizados: 1", result)

    def test_ratio_limit_prevents_expansion(self):
        path = self.write("ratio.zip", zip_bytes([("zeros.bin", b"A" * (256 * 1024))]))
        result = self.run_cli("--max-ratio", "10", path, code=3)[1]
        self.assertIn("Ratio declarado", result)
        self.assertIn("bytes descomprimidos: 0 B", result)

    def test_declared_member_limit(self):
        path = self.write("big.zip", zip_bytes([("big.bin", b"A" * (1024 * 1024 + 1))], zipfile.ZIP_STORED))
        result = self.run_cli("--max-member-mib", "1", path, code=1)[1]
        self.assertIn("Tamaño declarado superior", result)

    def test_global_entry_limit(self):
        path = self.write("many.zip", zip_bytes([(f"{i}.txt", b"hola") for i in range(4)]))
        result = self.run_cli("--max-members", "2", path, code=1)[1]
        self.assertIn("Presupuesto global de 2 entradas", result)
        self.assertIn("entradas de contenedores consideradas: 2", result)
        self.assertNotIn("↳ 2.txt", result)

    def test_global_budget_is_shared_by_nested_containers(self):
        nested = zip_bytes([("hidden.txt", b"hola")])
        path = self.write("outer.zip", zip_bytes([("inner.zip", nested), ("last.txt", b"hola")]))
        result = self.run_cli("--max-members", "1", path, code=1)[1]
        self.assertIn("Presupuesto global", result)
        self.assertNotIn("↳ hidden.txt", result)
        self.assertNotIn("↳ last.txt", result)

    def test_global_byte_limit(self):
        path = self.write("budget.zip", zip_bytes([("a.bin", os.urandom(700000)), ("b.bin", os.urandom(700000))], zipfile.ZIP_STORED))
        result = self.run_cli("--max-member-mib", "1", "--max-total-mib", "1", path, code=1)[1]
        self.assertIn("Tamaño declarado superior", result)

    def test_zip_metadata_count_limit(self):
        data = bytearray(zip_bytes([]))
        struct.pack_into("<HH", data, 8, 10001, 10001)
        result = self.run_cli(self.write("metadata.zip", data), code=1)[1]
        self.assertIn("10000 entradas", result)

    def test_zip64_is_explicitly_incomplete(self):
        data = bytearray(zip_bytes([]))
        struct.pack_into("<HH", data, 8, 65535, 65535)
        result = self.run_cli(self.write("zip64.zip", data), code=1)[1]
        self.assertIn("ZIP64", result)

    def test_unsupported_zip_method(self):
        data = bytearray(zip_bytes([("data.txt", b"hello")], zipfile.ZIP_STORED))
        local = data.index(b"PK\x03\x04")
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<H", data, local + 8, 99)
        struct.pack_into("<H", data, central + 10, 99)
        result = self.run_cli(self.write("method.zip", data), code=1)[1]
        self.assertIn("método de compresión no soportado", result)

    def test_docx_structure(self):
        entries = [("[Content_Types].xml", b"<Types/>"), ("word/document.xml", b"<document/>")]
        result = self.run_cli(self.write("sample.docx", zip_bytes(entries)), code=1)[1]
        self.assertIn("Word OOXML", result)
        self.assertIn("no validación completa", result)

    def test_apk_structure(self):
        entries = [("AndroidManifest.xml", b"<manifest/>"), ("classes.dex", b"dex\n035\0" + b"\0" * 120)]
        self.assertIn("paquete Android APK", self.run_cli(self.write("sample.apk", zip_bytes(entries)))[1])

    def test_jar_structure(self):
        entries = [("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"), ("Main.class", bytes.fromhex("cafebabe0000003400010000"))]
        self.assertIn("paquete Java JAR", self.run_cli(self.write("sample.jar", zip_bytes(entries)))[1])

    def test_vba_component_name_is_an_indicator_not_macro_execution(self):
        entries = [("[Content_Types].xml", b"<Types/>"), ("word/document.xml", b"<document/>"), ("word/vbaProject.bin", b"placeholder")]
        result = self.run_cli(self.write("sample.docm", zip_bytes(entries)), code=3)[1]
        self.assertIn("Componentes VBA declarados", result)
        self.assertIn("no se extrajo código VBA", result)

    def test_office_external_relationships_are_not_visited(self):
        xml = b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" TargetMode="External" Target="https://example.invalid/private?token=SECRET" /></Relationships>'
        result = self.run_cli(self.write("rels.zip", zip_bytes([("word/_rels/document.xml.rels", xml)])), code=3)[1]
        self.assertIn("Relaciones externas", result)
        self.assertNotIn("token=SECRET", result)
        self.assertIn("no se realizó ninguna conexión", result)

    def test_tar_regular_member(self):
        result = self.run_cli(self.write("archive.tar", tar_bytes([("script.php", PHP)])), code=1)[1]
        self.assertIn("Contenedor TAR", result)
        self.assertIn("↳ script.php", result)
        self.assertIn("código PHP probable", result)

    def test_tar_symlink_and_fifo(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, kind in [("symlink", tarfile.SYMTYPE), ("fifo", tarfile.FIFOTYPE)]:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
                archive.addfile(info)
        result = self.run_cli(self.write("special.tar", stream.getvalue()), code=3)[1]
        self.assertIn("entrada especial o sparse", result)
        self.assertNotIn("root:x:", result)

    def test_tar_path_traversal(self):
        result = self.run_cli(self.write("traversal.tar", tar_bytes([("../../escape.php", PHP)])), code=3)[1]
        self.assertIn("traversal", result)
        self.assertFalse((self.work.parent / "escape.php").exists())

    def test_duplicate_tar_names(self):
        result = self.run_cli(self.write("duplicates.tar", tar_bytes([("same", b"one"), ("same", b"two")])), code=3)[1]
        self.assertIn("TAR con nombres duplicados", result)

    def test_oversized_tar_header_is_skipped(self):
        stream = io.BytesIO()
        info = tarfile.TarInfo("fake.bin")
        info.size = 100 * 1024 * 1024
        stream.write(info.tobuf(format=tarfile.USTAR_FORMAT))
        stream.write(b"\0" * 1024)
        result = self.run_cli(self.write("fake.tar", stream.getvalue()), code=3)[1]
        self.assertIn("excede el tamaño", result)

    def test_gzip_php(self):
        result = self.run_cli(self.write("script.php.gz", gzip.compress(PHP)), code=1)[1]
        self.assertIn("Contenedor GZIP", result)
        self.assertIn("↳ script.php", result)
        self.assertIn("código PHP probable", result)

    def test_tar_gzip(self):
        data = gzip.compress(tar_bytes([("hello.php", PHP)]))
        result = self.run_cli(self.write("archive.tgz", data), code=1)[1]
        self.assertIn("Contenedor GZIP", result)
        self.assertIn("Contenedor TAR", result)
        self.assertIn("↳ hello.php", result)

    def test_bzip2_and_xz(self):
        for name, content in [("script.php.bz2", bz2.compress(PHP)), ("script.php.xz", lzma.compress(PHP))]:
            with self.subTest(name=name):
                result = self.run_cli(self.write(name, content), code=1)[1]
                self.assertIn("↳ script.php", result)
                self.assertIn("código PHP probable", result)

    def test_truncated_gzip_is_not_presented_as_complete(self):
        result = self.run_cli(self.write("broken.gz", gzip.compress(PHP)[:-5]), code=3)[1]
        self.assertIn("integridad no confirmada", result)

    def test_real_expansion_cap_for_compressed_stream(self):
        path = self.write("huge.gz", gzip.compress(b"A" * (2 * 1024 * 1024)))
        result = self.run_cli("--max-member-mib", "1", "--max-ratio", "1000", path, code=1)[1]
        self.assertIn("Límite real de bytes", result)

    def test_rar_and_7z_are_explicitly_unsupported(self):
        for name, data in [("sample.rar", b'Rar!\x1a\x07\x00' + b'\0' * 32), ("sample.7z", bytes.fromhex('377abcaf271c') + b'\0' * 32)]:
            with self.subTest(name=name):
                self.assertIn("contenido interno no examinado", self.run_cli(self.write(name, data))[1])

    def test_appended_zip_does_not_replace_outer_image(self):
        path = self.write("appended.png", PNG + zip_bytes([("inside.txt", b"hola")]))
        result = self.run_cli(path, code=3)[1]
        self.assertIn("imagen PNG", result)
        self.assertIn("ZIP adicional", result)
        self.assertIn("↳ inside.txt", result)

    def test_name_mime_discrepancy(self):
        result = self.run_cli(self.write("image.jpg", PHP), code=3)[1]
        self.assertIn("Extensión .jpg", result)
        self.assertIn("código PHP probable", result)

    def test_double_extension(self):
        result = self.run_cli(self.write("image.jpg.php", PHP), code=3)[1]
        self.assertIn("Doble extensión", result)

    def test_expected_mime_policy(self):
        path = self.write("image.png", PNG)
        self.run_cli("--expect", "image/*", path, code=0)
        self.assertIn("No cumple el MIME esperado", self.run_cli("--expect", "application/pdf", path, code=3)[1])

    def test_expected_mime_only_applies_to_roots(self):
        path = self.write("data.zip", zip_bytes([("readme.txt", b"hola")]))
        result = self.run_cli("--expect", "application/zip", path, code=1)[1]
        self.assertNotIn("No cumple", result)

    def test_terminal_control_names_are_escaped(self):
        path = self.write("names.zip", zip_bytes([("evil\x1b[31m\n.php", PHP), ("safe\u202etxt.php", PHP)]))
        result = self.run_cli("--no-color", path, code=3)[1]
        self.assertNotIn("\x1b", result)
        self.assertNotIn("\u202e", result)
        self.assertIn("\\x1b", result)
        self.assertIn("\\u202e", result)

    def test_temporary_member_files_are_removed(self):
        path = self.write("archive.zip", zip_bytes([("inside.php", PHP)]))
        scratch = self.work / "temp"
        scratch.mkdir()
        env = os.environ.copy()
        env["TMPDIR"] = str(scratch)
        original = path.read_bytes()
        self.run_cli(path, code=1, env=env)
        self.assertEqual(list(scratch.iterdir()), [])
        self.assertEqual(path.read_bytes(), original)

    def test_members_are_not_executed(self):
        source = b'import os\nos.system("touch EXECUTED")\n'
        path = self.write("program.zip", zip_bytes([("program.py", source)]))
        self.run_cli(path, code=1)
        self.assertFalse((self.work / "EXECUTED").exists())

    def test_multiple_roots(self):
        one = self.write("one.png", PNG)
        two = self.write("two.png", PNG)
        self.assertIn("Analizados: 2", self.run_cli(one, two, code=0)[1])

    def test_cli_symlink_resolves_resources(self):
        link = self.work / "tool"
        link.symlink_to(SCRIPT)
        self.run_cli(self.write("image.png", PNG), code=0, script=link)

    def test_literal_dash_name(self):
        self.write("-", PNG)
        self.run_cli("--", "-", code=0)

    def test_cli_invalid_inputs(self):
        for args in [("--max-depth", "6"), ("--max-depth", "$(touch BAD)"), ("--max-members", "0"), ("--max-ratio", "0"), ("--max-total-mib", "999"), ("--expect", "not-mime")]:
            with self.subTest(args=args):
                self.run_cli(*args, "missing", code=2)
        self.run_cli(code=2)
        self.run_cli(self.work, code=2)
        fifo = self.work / "fifo"
        os.mkfifo(fifo)
        self.run_cli(fifo, code=2)
        self.assertFalse((self.work / "BAD").exists())

    def test_global_time_limit(self):
        path = self.write("many.zip", zip_bytes([(f"{i}.txt", b"texto para auditoria") for i in range(30)]))
        start = time.monotonic()
        code, text = self.run_cli("--timeout", "1", path)
        self.assertIn(code, (1, 3))
        self.assertIn("tiempo", text)
        self.assertLess(time.monotonic() - start, 5)

    def test_ntfs_stream_names_are_flagged(self):
        path = self.write("ads.zip", zip_bytes([("photo.jpg:script.php", PHP)]))
        self.assertIn("Alternate Data Streams", self.run_cli(path, code=3)[1])

    def test_utf16_relationship_dtd_is_not_parsed(self):
        xml = '<?xml version="1.0" encoding="utf-16"?><!DOCTYPE Relationships [<!ENTITY link "https://example.invalid/">]><Relationships><Relationship TargetMode="External" Target="&link;" /></Relationships>'.encode('utf-16')
        path = self.write("dtd.zip", zip_bytes([("word/_rels/document.xml.rels", xml)]))
        self.assertIn("DTD/ENTITY: parser omitido", self.run_cli(path)[1])

    def test_large_pax_metadata_read_is_bounded(self):
        info = tarfile.TarInfo("pax-header")
        info.type = tarfile.XHDTYPE
        info.size = 9 * 1024 * 1024
        data = info.tobuf(format=tarfile.USTAR_FORMAT) + b'\0' * 1024
        text = self.run_cli(self.write("pax.tar", data))[1]
        self.assertIn("lectura de metadatos", text)

    def test_negative_tar_size_is_invalid(self):
        info = tarfile.TarInfo("negative.bin")
        info.size = -1
        data = info.tobuf(format=tarfile.GNU_FORMAT) + b'\0' * 1024
        text = self.run_cli(self.write("negative.tar", data), code=3)[1]
        self.assertIn("INCOMPLETO", text)
        self.assertIn("Analizados: 1", text)

    def test_large_utf16_relationship_scope_is_explicit(self):
        xml = ('<?xml version="1.0" encoding="utf-16"?><Relationships>' + ' ' * 70000 + '</Relationships>').encode('utf-16')
        path = self.write("large-rels.zip", zip_bytes([("word/_rels/document.xml.rels", xml)], zipfile.ZIP_STORED))
        text = self.run_cli(path, code=1)[1]
        self.assertIn("Relaciones XML mayores de 128 KiB", text)
        self.assertIn("INCOMPLETO", text)

    def test_technical_error_is_not_replaced_by_filename_review(self):
        binary = self.work / 'bin'
        binary.mkdir()
        mock = binary / 'file'
        mock.write_text('#!/usr/bin/env bash\nexit 1\n')
        mock.chmod(0o755)
        env = os.environ.copy()
        env['PATH'] = str(binary) + os.pathsep + env['PATH']
        result = self.run_cli(self.write('image.jpg.php', PHP), env=env, code=2)[1]
        self.assertIn('[ERROR]', result)

if __name__ == "__main__":
    unittest.main(verbosity=2)
