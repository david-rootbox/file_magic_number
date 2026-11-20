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
        self.assertIn("3.0.0", self.run_detector("--version", code=0))

    def test_missing_database_is_an_error(self):
        copied = self.work / "tool"
        shutil.copyfile(SCRIPT, copied)
        self.assertIn("Falta data/signatures.tsv", self.run_detector(self.png, script=copied, code=2))

    def test_database_is_not_executed(self):
        copied = self.work / "tool"
        shutil.copyfile(SCRIPT, copied)
        shutil.copytree(ROOT / "lib", self.work / "lib")
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

    def test_php_short_echo_when_file_only_reports_plain_text(self):
        target = self.write("c.php", b'\n<?= $nombre ?>\n')
        result = self.run_detector(target, code=1, env=self.mock_mime("text/plain"))
        self.assertIn("Tipo orientativo: código PHP probable (.php)", result)
        self.assertIn("MIME detectado: text/plain", result)
        self.assertIn("PHP | probable | documento | byte 1", result)

    def test_php_full_tag_and_function_call(self):
        result = self.run_detector(self.write("renamed.jpg", b'<?php phpinfo(); ?>'), code=1)
        self.assertIn("código PHP probable", result)

    def test_php_short_echo_literal(self):
        result = self.run_detector(self.write("unknown", b'<?= "hola" ?>'), code=1)
        self.assertIn("código PHP probable", result)

    def test_php_marker_alone_is_only_possible(self):
        result = self.run_detector(self.write("marker", b'<?php '), code=1)
        self.assertIn("Contenido: PHP | posible", result)
        self.assertNotIn("Tipo orientativo: código PHP probable", result)

    def test_php_after_utf8_bom_and_newline(self):
        result = self.run_detector(self.write("bom", b'\xef\xbb\xbf\n<?= $nombre ?>'), code=1)
        self.assertIn("PHP | probable | documento | byte 4", result)
        self.assertIn("UTF-8 con BOM", result)

    def test_php_utf16_bom(self):
        result = self.run_detector(self.write("utf16", b'\xff\xfe' + '\n<?= $nombre ?>'.encode('utf-16-le')), code=1)
        self.assertIn("PHP | probable | documento | byte 4", result)
        self.assertIn("UTF-16 LE", result)

    def test_php_utf16_without_bom(self):
        result = self.run_detector(self.write("utf16", '\n<?= $nombre ?>'.encode('utf-16-le')), code=1)
        self.assertIn("PHP | probable", result)
        self.assertIn("sin BOM", result)

    def test_php_utf32_bom(self):
        result = self.run_detector(self.write("utf32", b'\0\0\xfe\xff' + '\n<?= $nombre ?>'.encode('utf-32-be')), code=1)
        self.assertIn("PHP | probable | documento | byte 8", result)

    def test_php_beyond_binary_header_window(self):
        result = self.run_detector(self.write("deep", b' ' * 8192 + b'<?= $nombre ?>'), code=1)
        self.assertIn("PHP | probable | documento | byte 8192", result)

    def test_php_quoted_close_tag_does_not_end_block_early(self):
        result = self.run_detector(self.write("quoted", b'<?php echo "?>"; $nombre = 1; ?>'), code=1)
        self.assertIn("código PHP probable", result)
        self.assertNotIn("sin cierre en el bloque", result)

    def test_php_comment_is_not_corroborating_code(self):
        result = self.run_detector(self.write("comment", b'<?php /* echo $variable; */ ?>'), code=1)
        self.assertIn("PHP | posible", result)
        self.assertNotIn("Tipo orientativo: código PHP probable", result)

    def test_php_malformed_opening_is_not_full_tag(self):
        result = self.run_detector(self.write("bad", b'<?phpfoo echo 1; ?>'))
        self.assertNotIn("Contenido: PHP", result)

    def test_html_php_and_javascript_are_separate_layers(self):
        data = b'<html><body><p><?= $nombre ?></p><script>console.log("hola");</script></body></html>'
        result = self.run_detector(self.write("template", data), code=1)
        self.assertIn("plantilla HTML con PHP probable", result)
        self.assertIn("Contenido: PHP | probable", result)
        self.assertIn("Contenido: HTML | probable", result)
        self.assertIn("Contenido: JavaScript | probable | bloque <script>", result)

    def test_php_in_html_attribute_with_javascript(self):
        data = b'<html><a href="<?= $url ?>">Ir</a><script>const x = 1; console.log(x);</script></html>'
        result = self.run_detector(self.write("attribute", data), code=1)
        self.assertIn("plantilla HTML con PHP probable", result)
        self.assertIn("PHP | probable | documento", result)

    def test_json_with_quoted_php_stays_json(self):
        data = b'{"example": "<?php echo 1; ?>"}\n'
        result = self.run_detector(self.write("data", data), code=1)
        self.assertIn("datos JSON", result)
        self.assertIn("PHP | posible | cadena JSON", result)
        self.assertNotIn("Tipo orientativo: código PHP", result)

    def test_nonstandard_json_constant_is_not_syntax_verified(self):
        result = self.run_detector(self.write("data", b'{"x": NaN}'))
        self.assertNotIn("Contenido: JSON | sintaxis verificada", result)

    def test_markdown_php_example_is_not_the_document_language(self):
        data = b'# Ejemplo\n\n```php\n<?php echo 1; ?>\n```\n'
        result = self.run_detector(self.write("notes", data), code=1)
        self.assertIn("documento Markdown probable", result)
        self.assertIn("PHP | posible | ejemplo Markdown", result)

    def test_python_ast_and_quoted_php(self):
        data = b'import os\n\ndef example():\n    return "<?php echo 1; ?>"\n'
        result = self.run_detector(self.write("python.txt", data), code=1)
        self.assertIn("contenido Python probable", result)
        self.assertIn("Python | sintaxis analizada (AST)", result)
        self.assertIn("PHP | posible | cadena/comentario de Python", result)

    def test_python_source_is_never_executed(self):
        data = b'import os\nos.system("touch EXECUTED")\n'
        result = self.run_detector(self.write("dangerous.txt", data), code=1)
        self.assertIn("Python", result)
        self.assertFalse((self.work / "EXECUTED").exists())

    def test_php_source_is_never_executed(self):
        data = b'<?php file_put_contents("EXECUTED", "x"); ?>'
        result = self.run_detector(self.write("dangerous.txt", data), code=1)
        self.assertIn("PHP | probable", result)
        self.assertFalse((self.work / "EXECUTED").exists())

    def test_javascript_with_quoted_php(self):
        data = b'const example = "<?= $nombre ?>";\nconsole.log(example);\n'
        result = self.run_detector(self.write("script.txt", data), code=1)
        self.assertIn("contenido JavaScript/TypeScript probable", result)
        self.assertIn("PHP | posible | cadena/comentario de JavaScript", result)

    def test_typescript_annotations(self):
        data = b'interface User { name: string; }\nconst user: User = {name: "David"};\n'
        self.assertIn("contenido TypeScript probable", self.run_detector(self.write("ts", data), code=1))

    def test_shell_shebang_and_quoted_php(self):
        data = b'#!/usr/bin/env bash\n# <?php echo 1; ?>\necho hola\n'
        result = self.run_detector(self.write("shell", data), code=1)
        self.assertIn("contenido Shell (Bash) probable", result)
        self.assertIn("PHP | posible | cadena/comentario de shell", result)

    def test_env_shebang(self):
        data = b'#!/usr/bin/env -S python3 -u\nprint("hola")\n'
        self.assertIn("contenido Python probable", self.run_detector(self.write("py", data), code=1))

    def test_css(self):
        self.assertIn("contenido CSS probable", self.run_detector(self.write("css", b'.card { color: red; padding: 10px; }'), code=1))

    def test_sql(self):
        self.assertIn("contenido SQL probable", self.run_detector(self.write("sql", b'CREATE TABLE users (id INTEGER);'), code=1))

    def test_c_family(self):
        data = b'#include <stdio.h>\nint main(void) { printf("hola"); return 0; }\n'
        self.assertIn("contenido C/C++ probable", self.run_detector(self.write("c", data), code=1))

    def test_xml_is_not_php(self):
        data = b'<?xml version="1.0"?>\n<root><item>hola</item></root>'
        result = self.run_detector(self.write("xml", data))
        self.assertIn("XML | sintaxis verificada", result)
        self.assertNotIn("Contenido: PHP", result)

    def test_svg_xml_parser(self):
        data = b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1" /></svg>'
        self.assertIn("SVG | sintaxis verificada", self.run_detector(self.write("svg", data)))

    def test_json_script_block_not_javascript(self):
        data = b'<html><script type="application/ld+json">{"x":1}</script></html>'
        result = self.run_detector(self.write("html", data))
        self.assertIn("JSON | sintaxis verificada | bloque <script>", result)
        self.assertNotIn("Contenido: JavaScript", result)

    def test_image_with_php_metadata_preserves_image_type(self):
        data = PNG[:-12] + chunk(b'tEXt', b'Description\0<?= $nombre ?>') + PNG[-12:]
        result = self.run_detector(self.write("image", data), code=3)
        self.assertIn("Tipo orientativo: imagen PNG", result)
        self.assertIn("REVISAR CONTENIDO", result)
        self.assertIn("PHP | probable | fragmento incrustado", result)

    def test_scan_limit_is_explicit(self):
        target = self.write("deep", b' ' * 6000 + b'<?= $nombre ?>')
        short = self.run_detector("--max-bytes", "4096", target, code=1)
        self.assertIn("Muestra limitada", short)
        self.assertNotIn("Contenido: PHP", short)
        longer = self.run_detector("--max-bytes", "8192", target, code=1)
        self.assertIn("PHP | probable", longer)

    def test_invalid_scan_limits(self):
        for value in ("1", "16777217", "bad", "$(touch BAD)"):
            self.run_detector("--max-bytes", value, self.png, code=2)
        self.run_detector("--max-bytes", code=2)
        self.assertFalse((self.work / "BAD").exists())

    def test_quoted_php_without_identifiable_host_language(self):
        result = self.run_detector(self.write("quoted", b'example = "<?php echo 1; ?>"'), code=1)
        self.assertIn("PHP | posible | cadena citada", result)
        self.assertNotIn("Tipo orientativo: código PHP", result)

    def test_php_evidence_does_not_print_sensitive_source(self):
        secret = 'PRIVATE_EXAMPLE_123456'
        result = self.run_detector(self.write("private", ('<?php $token = "' + secret + '"; ?>').encode()), code=1)
        self.assertIn("PHP | probable", result)
        self.assertNotIn(secret, result)

    def test_large_json_does_not_become_php_when_parser_limit_is_reached(self):
        data = b'{"padding": "' + b'A' * 140000 + b'", "example": "<?= $nombre ?>"}'
        result = self.run_detector(self.write("large-json", data), code=1)
        self.assertIn("PHP | posible | estructura tipo JSON", result)
        self.assertNotIn("Tipo orientativo: código PHP", result)

    def test_xml_template_keeps_carrier_and_php(self):
        data = b'<?xml version="1.0"?>\n<root><?= $nombre ?></root>'
        result = self.run_detector(self.write("xml-template", data))
        self.assertIn("plantilla XML con PHP probable", result)
        self.assertIn("XML | probable", result)
        self.assertIn("PHP | probable", result)

    def test_svg_with_script_shows_both_layers(self):
        data = b'<svg xmlns="http://www.w3.org/2000/svg"><script>console.log("hola");</script></svg>'
        result = self.run_detector(self.write("svg-script", data))
        self.assertIn("SVG", result)
        self.assertIn("JavaScript | probable | bloque <script>", result)

    def test_binary_readable_python_fragment_does_not_replace_png(self):
        source = b'Description\0import os\n\ndef example():\n    return 42\n'
        data = PNG[:-12] + chunk(b'tEXt', source) + PNG[-12:]
        result = self.run_detector(self.write("python-image", data), code=3)
        self.assertIn("Tipo orientativo: imagen PNG", result)
        self.assertIn("Python | posible | cadena legible dentro de datos binarios", result)

    def test_missing_content_helper_is_an_error(self):
        copied = self.work / "tool"
        shutil.copyfile(SCRIPT, copied)
        shutil.copytree(ROOT / "data", self.work / "data")
        self.assertIn("Falta lib/content_probe.py", self.run_detector(self.png, script=copied, code=2))

    def test_plain_prose_keywords_are_not_enough_for_language(self):
        data = b'This document discusses function names, Python, PHP, JavaScript and SQL.\n'
        result = self.run_detector(self.write("prose", data), code=1)
        self.assertNotIn("Contenido:", result)

    def test_clipped_utf8_character_does_not_break_decoder(self):
        data = b' ' * 4095 + 'á'.encode() + b' ' * 10
        result = self.run_detector("--max-bytes", "4096", self.write("clipped", data), code=1)
        self.assertIn("codificación: UTF-8/ASCII", result)
        self.assertIn("Muestra limitada", result)

if __name__ == "__main__":
    unittest.main(verbosity=2)
