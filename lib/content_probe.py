#!/usr/bin/env python3
"""Bounded, read-only content classification. Never execute the inspected file.

Emits a small TSV protocol for the Bash front end; no source snippets, paths or
user-controlled terminal control sequences are included in its report.
"""
import argparse
import ast
import codecs
from dataclasses import dataclass
from html.parser import HTMLParser
import io
import json
import re
import shlex
import sys
import tokenize
import xml.etree.ElementTree as ET

DEFAULT_LIMIT = 1024 * 1024
GRAMMAR_LIMIT = 128 * 1024
BLOCK_LIMIT = 64 * 1024
MAX_FINDINGS = 24

@dataclass
class Finding:
    language: str
    label: str
    level: str
    scope: str
    offset: int
    evidence: str

def clean(value):
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(value))

def emit(*values):
    print("\t".join(clean(value) for value in values))

def text_ratio(text):
    if not text:
        return 1.0
    bad = sum((ord(c) < 32 and c not in "\n\r\t\f") or ord(c) == 127 for c in text)
    return 1 - bad / len(text)

def decode_sample(raw, clipped):
    # UTF-32 LE must be tested before UTF-16 LE: their BOM prefixes overlap.
    for bom, codec, name in [(b"\xff\xfe\0\0", "utf-32-le", "UTF-32 LE"),
                             (b"\0\0\xfe\xff", "utf-32-be", "UTF-32 BE"),
                             (b"\xff\xfe", "utf-16-le", "UTF-16 LE"),
                             (b"\xfe\xff", "utf-16-be", "UTF-16 BE"),
                             (b"\xef\xbb\xbf", "utf-8", "UTF-8 con BOM")]:
        if raw.startswith(bom):
            try:
                # A bounded sample can end within a multibyte character.
                decoded = codecs.getincrementaldecoder(codec)(errors="strict").decode(raw[len(bom):], final=not clipped)
                return decoded, name, codec, len(bom), text_ratio(decoded) >= .97
            except UnicodeError:
                break
    for codec, name in [("utf-8", "UTF-8/ASCII")]:
        try:
            decoded = codecs.getincrementaldecoder(codec)(errors="strict").decode(raw, final=not clipped)
            if "\0" not in decoded and text_ratio(decoded) >= .97:
                return decoded, name, codec, 0, True
        except UnicodeError:
            pass
    # Conservative BOM-less UTF-16 detection based on alternating NULs.
    if len(raw) >= 8:
        even, odd = raw[:4096:2], raw[1:4096:2]
        for codec, zero, other in [("utf-16-le", odd, even), ("utf-16-be", even, odd)]:
            if zero.count(0) / len(zero) > .6 and other.count(0) / len(other) < .1:
                try:
                    decoded = raw[:len(raw) // 2 * 2].decode(codec)
                    if text_ratio(decoded) >= .97:
                        return decoded, codec.upper() + " probable (sin BOM)", codec, 0, True
                except UnicodeError:
                    pass
    decoded = raw.decode("latin-1")
    return decoded, "8 bits sin determinar" if text_ratio(decoded) >= .97 and b"\0" not in raw else "datos binarios", "latin-1", 0, text_ratio(decoded) >= .97 and b"\0" not in raw

def strip_c_literals(text):
    """Mask comments/strings without modifying positions; not a full lexer."""
    pattern = r"/\*[\s\S]*?(?:\*/|$)|//[^\n]*|'(?:\\[\s\S]|[^'\\])*'|\"(?:\\[\s\S]|[^\"\\])*\"|`(?:\\[\s\S]|[^`\\])*`"
    spans = []
    pieces = []
    last = 0
    for match in re.finditer(pattern, text):
        pieces.append(text[last:match.start()])
        pieces.append(re.sub(r"[^\n]", " ", match.group()))
        spans.append((match.start(), match.end()))
        last = match.end()
    pieces.append(text[last:])
    return "".join(pieces), spans

def python_mask(text):
    # Tokenization is passive; source code is never compiled for execution.
    starts = [0]
    starts.extend(m.end() for m in re.finditer("\n", text))
    chars = list(text)
    spans = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type in (tokenize.STRING, tokenize.COMMENT):
                start = starts[token.start[0] - 1] + token.start[1]
                end = starts[token.end[0] - 1] + token.end[1]
                spans.append((start, end))
                chars[start:end] = ["\n" if c == "\n" else " " for c in text[start:end]]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return "".join(chars), spans

def inside(position, spans):
    return any(start <= position < end for start, end in spans)

def declared_interpreter(text):
    if not text.startswith("#!"):
        return None
    try:
        words = shlex.split(text.splitlines()[0][2:])
    except ValueError:
        return None
    interpreters = {"python": ("python", "Python"), "python2": ("python", "Python"), "python3": ("python", "Python"),
                    "bash": ("shell", "Shell (Bash)"), "sh": ("shell", "Shell (sh)"), "zsh": ("shell", "Shell (Zsh)"), "dash": ("shell", "Shell (dash)"),
                    "node": ("javascript", "JavaScript"), "php": ("php", "PHP")}
    if not words:
        return None
    command = words[0].rsplit("/", 1)[-1]
    if command == "env":
        command = next((word.rsplit("/", 1)[-1] for word in words[1:] if not word.startswith("-") and "=" not in word), "")
    if re.fullmatch(r"python[23]\.\d+", command):
        command = "python3" if command.startswith("python3") else "python2"
    return interpreters.get(command)

def reject_constant(value):
    raise ValueError("non-standard JSON constant")

def php_body(text, start):
    """Get an opening block's tokens, ignoring quoted ?> and comments."""
    end = min(len(text), start + BLOCK_LIMIT)
    pos, state, tokens = start, "code", []
    while pos < end:
        char = text[pos]
        pair = text[pos:pos + 2]
        if state in ("'", '"', "`"):
            if char == "\\":
                pos += 2
                continue
            if char == state:
                state = "code"
            pos += 1
            continue
        if state == "block":
            if pair == "*/":
                state = "code"
                pos += 2
            else:
                pos += 1
            continue
        if pair == "?>" and state in ("code", "line"):
            return "".join(tokens), pos + 2, True
        if state == "line":
            if char in "\r\n":
                state = "code"
                tokens.append("\n")
            pos += 1
            continue
        if pair == "/*":
            state = "block"
            pos += 2
            continue
        if pair == "//" or (char == "#" and pair != "#["):
            state = "line"
            pos += 2 if pair == "//" else 1
            continue
        if char in ("'", '"', "`"):
            state = char
            tokens.append(" LITERAL ")
        else:
            tokens.append(char)
        pos += 1
    return "".join(tokens), end, False

class Markup(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.tags = []
        self.closed = set()
        self.blocks = []
        self.active = None
        self.buffer = []
        self.external_script = False
    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag in ("script", "style"):
            self.active = (tag, dict(attrs).get("type", "").lower())
            self.buffer = []
            if tag == "script" and dict(attrs).get("src"):
                self.external_script = True
    def handle_endtag(self, tag):
        self.closed.add(tag)
        if self.active and tag == self.active[0]:
            self.blocks.append((*self.active, "".join(self.buffer)))
            self.active = None
    def handle_data(self, data):
        if self.active:
            self.buffer.append(data)

def analyze(raw, total, binary_container=False, scan_strings=True):
    clipped = len(raw) < total
    text, encoding, codec, bom, looks_text = decode_sample(raw, clipped)
    window = text[:GRAMMAR_LIMIT]
    complete_grammar = not clipped and len(text) <= GRAMMAR_LIMIT
    findings, notes = [], []
    base_scope = "fragmento incrustado" if binary_container or not looks_text else "documento"
    primary = ""
    alert = False
    def byte_offset(index):
        return bom + len(text[:index].encode(codec, errors="replace"))
    def add(language, label, level, scope, index, evidence):
        if len(findings) < MAX_FINDINGS and not any(f.language == language and f.scope == scope for f in findings):
            findings.append(Finding(language, label, level, scope, byte_offset(index), evidence))

    json_document = False
    json_like = looks_text and window.lstrip().startswith(("{", "["))
    if json_like and complete_grammar:
        try:
            value = json.loads(window, parse_constant=reject_constant)
            json_document = isinstance(value, (dict, list))
        except (ValueError, RecursionError):
            pass
        if json_document:
            add("json", "JSON", "sintaxis verificada", base_scope, 0, "objeto o array analizado con el parser JSON estricto")
            primary = "datos JSON (objeto/array con sintaxis válida)"
    if json_like and not json_document:
        notes.append("Estructura inicial compatible con JSON; no se confirmó su sintaxis en el rango permitido.")

    # Markdown is a carrier of examples; fenced snippets are not classified as
    # the language of the entire document.
    fences = [(m.start(), m.end()) for m in re.finditer(r"(?m)^```[^\n]*\n[\s\S]*?^```[^\n]*$", window)]
    markdown = bool(looks_text and fences and re.search(r"(?m)^#{1,6} \S", window))
    if markdown:
        primary = "documento Markdown probable (con ejemplos de código)"
        add("markdown", "Markdown", "probable", base_scope, 0, "encabezados y bloques de código delimitados")

    c_mask, c_spans = strip_c_literals(window)
    py_mask, py_spans = python_mask(window) if looks_text and not json_document else (window, [])
    python_cues = re.search(r"(?m)^\s*(?:(?:async\s+)?def\s+\w+\s*\(|class\s+\w+[^\n]*:|from\s+[.\w]+\s+import\s+|import\s+[A-Za-z_]\w*(?:\s|\.|$)|(?:if|for|with|while)\s+[^\n]+:\s*$)", py_mask)
    js_cues = [pattern for pattern in (
        r"\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=",
        r"\bfunction\s+[A-Za-z_$][\w$]*\s*\([^)]{0,200}\)\s*\{",
        r"=>\s*(?:\{|[A-Za-z_$])", r"\bconsole\.(?:log|error|warn)\s*\(",
        r"\bmodule\.exports\s*=", r"\bimport\s+[^;\n]{1,100}\s+from\s+",
        r"\bexport\s+(?:default|function|const|class)\b") if re.search(pattern, c_mask)]
    javascript = bool(js_cues)
    typescript = bool(re.search(r"\binterface\s+\w+\s*\{[^}]{0,200}:|\b(?:const|let)\s+\w+\s*:\s*(?:string|number|boolean|[A-Z]\w*)\b|\btype\s+\w+\s*=\s*(?:\{|string\b|number\b)", c_mask))
    python_document = bool(looks_text and python_cues and not json_document and not markdown)
    declaration = declared_interpreter(window) if looks_text else None
    if python_document:
        parsed = False
        if complete_grammar:
            try:
                ast.parse(window)
                parsed = True
            except (SyntaxError, ValueError, RecursionError):
                pass
        distinctive = bool(re.search(r"(?m)^\s*(?:async\s+)?def\s+\w+\([^\n]*\)\s*(?:->[^\n]+)?\s*:|^\s*class\s+\w+[^\n]*:", py_mask))
        python_document = parsed or distinctive
        if python_document:
            add("python", "Python", "sintaxis analizada (AST)" if parsed else "probable", base_scope,
                python_cues.start(), "construcciones propias de Python" + (" y AST analizado" if parsed else "; sintaxis no confirmada"))

    # PHP tags can be anywhere, including after a BOM, a newline, HTML or image
    # metadata. A tag alone is only an indicator; code tokens add evidence.
    php_blocks = []
    php_document = False
    php_end = -1
    html_carrier = bool(re.search(r"(?im)^\s*(?:<!doctype\s+html\b|<(?:html|div|p|form|a|body|head)\b)", window))
    for match in re.finditer(r"<\?(?:php(?=[\t\n\r ])|=)", text, re.IGNORECASE):
        if match.start() < php_end:
            continue
        code, php_end, closed = php_body(text, match.end())
        php_blocks.append((match.start(), php_end))
        short_echo = match.group().endswith("=")
        has_code = bool(re.search(r"\$[A-Za-z_]\w*|\b(?:echo|print|function|class|namespace|use|return|include|require|if|foreach|new|declare)\b|\b[A-Za-z_]\w*\s*\(", code)
                        or (short_echo and re.search(r"\bLITERAL\b|\d|[A-Za-z_$][\w$]*", code)))
        scope = base_scope
        if json_document:
            scope = "cadena JSON (marcador citado)"
        elif json_like:
            scope = "estructura tipo JSON (contexto sin validar)"
        elif markdown and inside(match.start(), fences):
            scope = "ejemplo Markdown"
        elif markdown and match.start() >= len(window):
            scope = "marcador en Markdown (contexto fuera de la ventana gramatical)"
        elif (python_document or (declaration and declaration[0] == "python")) and inside(match.start(), py_spans):
            scope = "cadena/comentario de Python"
        elif looks_text and (javascript or typescript or (declaration and declaration[0] == "javascript")) and not html_carrier and inside(match.start(), c_spans):
            scope = "cadena/comentario de JavaScript"
        elif declaration and declaration[0] == "shell" and inside(match.start(), py_spans):
            scope = "cadena/comentario de shell"
        elif looks_text and not html_carrier and inside(match.start(), c_spans) and re.search(r"(?m)^\s*(?:[A-Za-z_]\w*\s*=|print\s*\()", window):
            scope = "cadena citada (lenguaje sin determinar)"
        level = "probable" if has_code and scope == base_scope else "posible"
        add("php", "PHP", level, scope, match.start(),
            "apertura " + ("<?=" if short_echo else "<?php") + (" y tokens de código" if has_code else "; sin código corroborante")
            + ("; sin cierre en el bloque examinado" if not closed else ""))
        if scope == base_scope and has_code:
            php_document = True
            alert |= binary_container or not looks_text
        if len(php_blocks) >= 64:
            notes.append("Se alcanzó el límite de 64 bloques PHP examinados.")
            break

    # Hide PHP from the HTML parser while retaining the surrounding markup.
    markup_text = window
    for start, end in reversed(php_blocks):
        if start < len(window):
            end = min(end, len(window))
            markup_text = markup_text[:start] + re.sub(r"[^\n]", " ", markup_text[start:end]) + markup_text[end:]
    markup = Markup()
    try:
        markup.feed(markup_text)
    except (ValueError, RecursionError):
        pass
    html_tags = set(markup.tags) & {"html", "head", "body", "div", "p", "span", "h1", "a", "form", "script", "style", "title", "table", "button"}
    html = bool(not json_document and not markdown and (re.search(r"<!doctype\s+html\b", markup_text, re.I)
                or "html" in markup.tags or html_tags & markup.closed))
    xml_family = ''
    if looks_text and complete_grammar and not (json_like or markdown or html) and markup_text.lstrip().startswith("<") and not re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", markup_text, re.I):
        try:
            root = ET.fromstring(markup_text)
            xml_family = "svg" if root.tag.split("}")[-1].lower() == "svg" else "xml"
            add(xml_family, xml_family.upper(), "probable" if php_blocks else "sintaxis verificada", base_scope, 0,
                "estructura XML tras separar bloques PHP" if php_blocks else "documento XML analizado sin declaraciones DTD/ENTITY")
        except (ET.ParseError, ValueError, RecursionError):
            pass
    if html:
        add("html", "HTML", "probable", base_scope, 0, "etiquetas de documento o elementos HTML emparejados")
    if html or xml_family == "svg":
        for tag, block_type, block in markup.blocks:
            if tag == "script" and block.strip() and block_type in ("", "text/javascript", "application/javascript", "module"):
                add("javascript", "JavaScript", "probable", "bloque <script>", max(0, window.lower().find("<script")), "bloque script de tipo JavaScript con contenido")
            elif tag == "script" and block.strip() and block_type in ("application/json", "application/ld+json"):
                try:
                    json.loads(block, parse_constant=reject_constant)
                    add("json", "JSON", "sintaxis verificada", "bloque <script>", max(0, window.lower().find("<script")), "script de datos JSON con sintaxis válida")
                except (ValueError, RecursionError):
                    pass
            elif tag == "style" and block.strip():
                add("css", "CSS", "probable", "bloque <style>", max(0, window.lower().find("<style")), "bloque style con contenido")

    if looks_text and not (json_document or markdown or html or php_document):
        if typescript:
            add("typescript", "TypeScript", "probable", base_scope, 0, "anotaciones de tipos o declaración interface con campos tipados")
        elif javascript:
            # A generic declaration on its own also fits other C-like languages.
            if len(js_cues) >= 2 or re.search(r"\b(?:console\.(?:log|error|warn)\s*\(|module\.exports\s*=|export\s+default)", c_mask):
                add("javascript", "JavaScript/TypeScript", "probable", base_scope, 0, "construcciones de la familia JavaScript; sin analizador sintáctico completo")
        if re.search(r"(?m)^\s*#\s*include\s*[<\"]", window) and re.search(r"\b(?:int\s+main|std::|printf\s*\()", c_mask):
            add("cpp", "C/C++", "probable", base_scope, 0, "directivas include y construcciones C/C++")
        if re.search(r"(?im)^\s*(?:CREATE\s+TABLE\s+\w+\s*\(|INSERT\s+INTO\s+\w+|SELECT\s+[^\n;]{1,300}\s+FROM\s+\w+)", c_mask):
            add("sql", "SQL", "probable", base_scope, 0, "estructura de sentencia SQL")
        if re.search(r"(?m)^\s*(?:[.#][\w-]+|body|html)\s*\{", c_mask) and re.search(r"\b(?:color|display|margin|padding|background(?:-color)?)\s*:", c_mask):
            add("css", "CSS", "probable", base_scope, 0, "selector y declaraciones de propiedades CSS")
        if re.search(r"(?m)^\s*(?:if\s+\[|for\s+\w+\s+in\s)", window) and re.search(r"(?m)^\s*(?:then|fi|do|done)\b", window):
            add("shell", "Shell", "probable", base_scope, 0, "estructuras de control de shell")

    # Shebang is an explicit declaration, not proof that the body is valid.
    if declaration:
        language, label = declaration
        add(language, label, "probable", base_scope, 0, "intérprete declarado en shebang; cuerpo no validado por esa declaración")

    document = [f for f in findings if f.scope == "documento" and f.level != "posible"]
    languages = {f.language for f in document}
    if not (json_document or markdown):
        if html:
            primary = "plantilla HTML con PHP probable" if php_document else "documento HTML probable"
        elif xml_family:
            primary = ("plantilla " + xml_family.upper() + " con PHP probable") if php_document else ("contenido " + xml_family.upper() + " con sintaxis XML válida")
        elif php_document and looks_text:
            primary = "código PHP probable (.php)"
        elif len(languages) == 1:
            primary = "contenido " + document[0].label + " probable"
        elif len(languages) > 1:
            primary = "contenido textual ambiguo: " + ", ".join(sorted({f.label for f in document}))
    carriers = {"html", "php", "xml", "svg"}
    ambiguous = len(languages - carriers) > 1 or (bool(languages & carriers) and bool(languages - carriers))
    if scan_strings and (binary_container or not looks_text):
        string_count = 0
        for match in re.finditer(rb"[\x09\x0a\x0d\x20-\x7e]{24,}", raw):
            # Inspect at most 16 readable runs, with at most 16 KiB per run.
            # These are context-free strings, never proof of a second format.
            fragment = match.group()[:16 * 1024]
            nested = analyze(fragment, len(fragment), binary_container=True, scan_strings=False)
            for finding in nested["findings"]:
                if finding.language == "php" or any(f.language == finding.language for f in findings):
                    continue
                if len(findings) < MAX_FINDINGS:
                    findings.append(Finding(finding.language, finding.label, "posible", "cadena legible dentro de datos binarios",
                                            match.start() + finding.offset, finding.evidence + "; contexto binario, no demuestra ejecución"))
                    if finding.language in {"python", "javascript", "typescript", "shell", "cpp"}:
                        alert = True
            string_count += 1
            if string_count == 16:
                notes.append("Se alcanzó el límite de 16 cadenas legibles examinadas dentro del formato binario.")
                break
    if binary_container or not looks_text:
        primary = ""
    if clipped:
        notes.append("Muestra limitada: puede haber contenido fuera del rango examinado.")
    if len(text) > GRAMMAR_LIMIT:
        notes.append("Los lenguajes generales se examinan en los primeros 131072 caracteres; los marcadores PHP se buscan en toda la muestra.")
    if not findings:
        notes.append("No se encontraron pistas suficientes de los lenguajes soportados en la muestra.")
    return {"kind": "texto" if looks_text else "binario", "encoding": encoding, "sampled": len(raw), "total": total,
            "primary": primary, "findings": findings, "notes": notes, "alert": alert, "ambiguous": ambiguous}

def main():
    if sys.version_info < (3, 9):
        print("Se requiere Python 3.9 o superior.", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--binary-container", choices=("0", "1"), default="0")
    parser.add_argument("path")
    args = parser.parse_args()
    if not 4096 <= args.max_bytes <= 16 * 1024 * 1024:
        parser.error("max-bytes must be between 4096 and 16777216")
    try:
        # Resource bounds apply only to this helper, not the user's terminal.
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
        resource.setrlimit(resource.RLIMIT_AS, (384 * 1024 * 1024, 384 * 1024 * 1024))
        with open(args.path, "rb") as source:
            import os
            total = os.fstat(source.fileno()).st_size
            raw = source.read(args.max_bytes)
        report = analyze(raw, total, args.binary_container == "1")
    except (OSError, MemoryError, RecursionError) as error:
        print("No se pudo completar el análisis de contenido: " + type(error).__name__, file=sys.stderr)
        return 2
    emit("META", report["kind"], report["encoding"], report["sampled"], report["total"])
    emit("PRIMARY", report["primary"] or "-")
    emit("ALERT", int(report["alert"]), int(report["ambiguous"]))
    for finding in report["findings"]:
        emit("FINDING", finding.language, finding.label, finding.level, finding.scope, finding.offset, finding.evidence)
    for note in report["notes"]:
        emit("NOTE", note)
    return 0

if __name__ == "__main__":
    sys.exit(main())
