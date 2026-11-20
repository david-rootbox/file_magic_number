#!/usr/bin/env python3
"""Behavioral regression tests. Uses Python's standard library only."""
import gzip
import hashlib
import io
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "file_magic_number"
REAL_FILE = shutil.which("file")

def chunk(name, data):
    return struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data) & 0xffffffff)

PNG = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
       + chunk(b"IDAT", zlib.compress(b"\0\xff\0\0")) + chunk(b"IEND", b""))

class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.png = self.write("imagen.php", PNG)

    def write(self, name, data):
        target = self.work / name
        target.write_bytes(data)
        return target

    def run_detector(self, *args, code=None, script=SCRIPT, env=None):
        process = subprocess.run(["bash", str(script), *map(str, args)], cwd=self.work,
                                 env=env, capture_output=True, text=True, timeout=10)
        if code is not None:
            self.assertEqual(process.returncode, code, process.stdout + process.stderr)
        return process.stdout + process.stderr

    def mock_mime(self, mime):
        binary = self.work / "bin"
        binary.mkdir()
        wrapper = binary / "file"
        wrapper.write_text('#!/usr/bin/env bash\nfor arg in "$@"; do\n'
                           ' if [[ "$arg" == --mime-type ]]; then printf "%s\\n" "$TEST_MIME"; exit 0; fi\n'
                           'done\nexec "$TEST_REAL_FILE" "$@"\n')
        wrapper.chmod(0o755)
        env = os.environ.copy()
        env.update(PATH=str(binary) + os.pathsep + env["PATH"], TEST_MIME=mime, TEST_REAL_FILE=REAL_FILE)
        return env

    def test_png_renamed_php(self):
        result = self.run_detector(self.png, code=0)
        self.assertIn("Tipo orientativo: imagen PNG", result)
        self.assertIn("MIME detectado: image/png", result)
        self.assertIn("Resultado: CONCORDANTE:", result)
        self.assertIn("89504e470d0a1a0a", result)

    def test_extension_does_not_change_detection(self):
        other = self.write("documento.exe", PNG)
        self.assertEqual(self.run_detector(self.png, code=0), self.run_detector(other, code=0))

    def test_verbose_header(self):
        self.assertIn("Primeros 32 bytes (hex): 89504e47", self.run_detector("--verbose", self.png, code=0))

    def test_header_only_is_not_confirmed(self):
        result = self.run_detector(self.write("stub", PNG[:8]), code=1)
        self.assertIn("EVIDENCIA PARCIAL", result)
        self.assertIn("imagen PNG", result)

    def test_missing_png_end_is_not_confirmed(self):
        result = self.run_detector(self.write("truncated", PNG[:-12]), code=1)
        self.assertIn("Estructura básica: falló", result)

    def test_fake_png_with_enough_bytes(self):
        result = self.run_detector(self.write("fake", PNG[:33] + b"A" * 100), code=1)
        self.assertIn("Estructura básica: falló", result)

    def test_mime_cannot_bypass_magic_check(self):
        result = self.run_detector(self.png, code=3, env=self.mock_mime("image/jpeg"))
        self.assertIn("CONTRADICCIÓN", result)
        self.assertIn("89504e470d0a1a0a", result)

    def test_mime_without_signature_is_partial(self):
        unknown = self.write("unknown", hashlib.sha256(b"fixture").digest() * 4)
        result = self.run_detector(unknown, code=1, env=self.mock_mime("image/png"))
        self.assertIn("SOLO MIME", result)
        self.assertIn("sin coincidencias", result)

    def test_zip_remains_a_container(self):
        target = self.work / "archive.php"
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("hola.txt", "hola")
        result = self.run_detector(target, code=0)
        self.assertIn("CONCORDANTE EN FAMILIA", result)
        self.assertIn("subtipo no determinado", result)

    def test_docx_mime_does_not_make_zip_signature_unique(self):
        target = self.work / "doc.bin"
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("word/document.xml", "<document/>")
        result = self.run_detector(target, code=0, env=self.mock_mime(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"))
        self.assertIn("CONCORDANTE EN FAMILIA", result)

    def test_sqlite(self):
        target = self.work / "db.png"
        with sqlite3.connect(target) as db:
            db.execute("CREATE TABLE test (id INTEGER)")
        self.assertIn("base de datos SQLite", self.run_detector(target, code=0))

    def test_real_elf(self):
        target = Path(shutil.which("true"))
        self.assertIn("binario ELF", self.run_detector(target, code=0))

    def test_tar_checks_offset_257(self):
        target = self.work / "archive.png"
        with tarfile.open(target, "w", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo("hola.txt")
            info.size = 4
            archive.addfile(info, io.BytesIO(b"hola"))
        self.assertIn("byte 257", self.run_detector(target, code=0))

    def test_dicom_checks_offset_128(self):
        target = self.write("dicom.bin", b"\0" * 128 + b"DICM" + b"\0" * 128)
        result = self.run_detector(target)
        self.assertIn("byte 128", result)
        self.assertIn("imagen DICOM", result)

    def test_wrong_offset_does_not_match(self):
        result = self.run_detector(self.write("wrong", b"DICM" + b"\0" * 252), code=1)
        self.assertNotIn("Magic [", result)

    def test_iso_distant_offset(self):
        data = bytearray(34816)
        data[32768:32775] = b"\x01CD001\x01"
        result = self.run_detector(self.write("iso.php", data))
        self.assertIn("byte 32769", result)
        self.assertIn("ISO 9660", result)

    def test_dmg_offset_from_end(self):
        data = bytearray(1024)
        data[512:516] = b"koly"
        result = self.run_detector(self.write("dmg.php", data))
        self.assertIn("Apple DMG", result)
        self.assertIn("byte 512", result)

    def test_wildcard_riff(self):
        data = b"RIFF" + struct.pack("<I", 28) + b"WEBPVP8 " + b"\0" * 20
        result = self.run_detector(self.write("webp.bin", data))
        self.assertIn("imagen WebP", result)
        self.assertIn("????????", result)

    def test_short_mz_is_not_unique_exe(self):
        result = self.run_detector(self.write("mz", b"MZ" + b"\0" * 128), code=1)
        self.assertIn("EVIDENCIA PARCIAL", result)
        self.assertIn("puede ser DOS, EXE, DLL", result)

    def test_gzip_short_signature_is_partial(self):
        result = self.run_detector(self.write("gz", gzip.compress(b"hola")), code=1)
        self.assertIn("firma corta", result)

    def test_shared_java_macho_signature(self):
        data = bytes.fromhex("cafebabe0000003400010000")
        self.assertIn("AMBIGUO", self.run_detector(self.write("class", data), code=3))

    def test_ole_is_not_automatically_word(self):
        data = bytes.fromhex("d0cf11e0a1b11ae1") + b"\0" * 504
        result = self.run_detector(self.write("ole", data))
        self.assertIn("contenedor OLE/CFB", result)
        self.assertNotIn("Tipo orientativo: documento Word", result)

    def test_multiple_strong_families_are_ambiguous(self):
        data = bytearray(34816)
        data[:len(PNG)] = PNG
        data[32769:32774] = b"CD001"
        result = self.run_detector(self.write("mixed", data), code=3)
        self.assertIn("AMBIGUO", result)
        self.assertIn("imagen PNG", result)
        self.assertIn("ISO 9660", result)

    def test_plain_text_has_no_guessed_unique_extension(self):
        result = self.run_detector(self.write("text.php", b"Hola, esto es texto plano.\n"), code=1)
        self.assertIn("SOLO MIME", result)
        self.assertNotIn("Extensiones de la familia", result)

    def test_empty(self):
        self.assertIn("archivo vacío", self.run_detector(self.write("empty", b""), code=1))

    def test_unknown(self):
        data = b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(16))
        self.assertIn("DESCONOCIDO", self.run_detector(self.write("unknown", data), code=1))

    def test_all_zero_header_does_not_assert_pdb(self):
        self.assertNotIn("Magic [", self.run_detector(self.write("zero", b"\0" * 1024), code=1))

    def test_names_with_spaces_and_shell_characters(self):
        target = self.write("$(touch SHOULD_NOT_EXIST) con espacios.php", PNG)
        self.assertIn("CONCORDANTE", self.run_detector(target, code=0))
        self.assertFalse((self.work / "SHOULD_NOT_EXIST").exists())

    def test_dash_and_literal_stdin_name(self):
        self.write("-", PNG)
        self.assertIn("CONCORDANTE", self.run_detector("--", "-", code=0))

    def test_symlinked_input_and_script(self):
        target = self.work / "input-link"
        target.symlink_to(self.png)
        link = self.work / "tool-link"
        link.symlink_to(SCRIPT)
        self.assertIn("CONCORDANTE", self.run_detector(target, script=link, code=0))

    def test_non_regular_files_are_rejected(self):
        fifo = self.work / "fifo"
        os.mkfifo(fifo)
        self.run_detector(fifo, code=2)
        self.run_detector(self.work, code=2)
        self.run_detector(self.work / "missing", code=2)

    def test_cli_errors(self):
        self.run_detector(code=2)
        self.run_detector("--nonexistent", code=2)
        self.run_detector(self.png, self.png, code=2)
        self.run_detector("--help", code=0)
        self.assertIn("2.0.0", self.run_detector("--version", code=0))

    def test_missing_database_is_an_error(self):
        copied = self.work / "tool"
        shutil.copyfile(SCRIPT, copied)
        self.assertIn("Falta data/signatures.tsv", self.run_detector(self.png, script=copied, code=2))

    def test_database_is_not_executed(self):
        copied = self.work / "tool"
        shutil.copyfile(SCRIPT, copied)
        data = self.work / "data"
        data.mkdir()
        (data / "signatures.tsv").write_text(
            'S9999\tpng\t$(touch BAD)\t89504e47\tpng\timage/png\tpng\t0\n')
        self.assertIn("Regla de firmas inválida", self.run_detector(self.png, script=copied, code=2))
        self.assertFalse((self.work / "BAD").exists())

    def test_dataset_build_is_reproducible(self):
        targets = [ROOT / "data/signatures.tsv", ROOT / "data/import-report.json"]
        before = [p.read_bytes() for p in targets]
        subprocess.run([shutil.which("python3"), str(ROOT / "tools/build_signatures.py")],
                       check=True, capture_output=True, timeout=10)
        self.assertEqual(before, [p.read_bytes() for p in targets])

if __name__ == "__main__":
    unittest.main(verbosity=2)
