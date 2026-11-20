# 🔎 file_magic_number

**Inspección rápida de archivos y contenedores para auditorías, con evidencias y una terminal legible.**

La versión **4.0.0** combina MIME/libmagic, magic numbers y reconocimiento de contenido con recorrido limitado de contenedores. Muestra el formato exterior, las pistas de código y los miembros internos por separado. La salida va únicamente a la terminal: no genera informes ni archivos JSON de resultados.

## Qué puedes revisar

- Archivos cuya extensión no concuerda con el MIME detectado: por ejemplo, `imagen.jpg` que contiene PHP.
- Texto que `file` identifica como `ASCII text`, pero presenta indicadores de PHP, Python u otros lenguajes soportados.
- Miembros de ZIP, TAR y flujos GZIP/BZIP2/XZ, incluidos contenedores anidados dentro de los límites.
- Estructuras compatibles con DOCX/DOCM, XLSX/XLSM, PPTX/PPTM, JAR, APK y EPUB a partir de sus marcadores internos.
- Rutas internas absolutas o con `..`, nombres con dos puntos que pueden interpretarse como ADS en Windows, enlaces, entradas especiales y nombres duplicados.
- Componentes Office llamados `vbaProject.bin`, objetos en directorios `embeddings` y relaciones XML externas. Son indicadores: no se extrae ni ejecuta código VBA ni se visitan destinos externos.
- Archivos cifrados, dañados, con métodos de compresión no soportados o que superan los presupuestos: aparecen explícitamente como no analizados o incompletos.

Las coincidencias orientan la revisión. No prueban que exista una vulnerabilidad, que un archivo se ejecute en un servidor o que sea malicioso.

## Instalación

Requiere **Linux, Bash ≥ 4.4, Python ≥ 3.9, file/libmagic y GNU Coreutils**. Solo se utiliza la biblioteca estándar de Python; no necesitas `pip` ni paquetes adicionales. Se conservan la base de firmas y su licencia en el repositorio.

En Arch Linux:

```bash
sudo pacman -S --needed bash python file coreutils git
```

En Debian/Ubuntu/Kali con una versión compatible de Python:

```bash
sudo apt install bash python3 file coreutils git
```

Para instalar en tu carpeta actual:

```bash
git clone https://github.com/david-rootbox/file_magic_number.git
cd file_magic_number
./file_magic_number --version
./file_magic_number "archivo.zip"
```

### Todos los usuarios: /opt + /usr/local/bin

```bash
sudo git clone https://github.com/david-rootbox/file_magic_number.git /opt/file_magic_number
sudo chown -R root:root /opt/file_magic_number
sudo chmod -R a+rX /opt/file_magic_number
sudo chmod -R go-w /opt/file_magic_number
sudo chmod 755 /opt/file_magic_number/file_magic_number
sudo mkdir -p /usr/local/bin
sudo ln -s /opt/file_magic_number/file_magic_number /usr/local/bin/file_magic_number
file_magic_number --version
```

Mantén `data/` y `lib/` junto al comando. El enlace simbólico permite ejecutarlo desde cualquier carpeta; `/usr/local/bin` debe estar en tu `PATH`. Para analizar archivos que tu usuario puede leer no hace falta `sudo`.

Si ya tienes esta instalación:

```bash
sudo git -C /opt/file_magic_number pull --ff-only
file_magic_number --version
```

## Ejemplos de uso en una auditoría

### 1. Revisar una subida con extensión dudosa

```bash
file_magic_number "imagen.jpg"
file_magic_number --verbose "imagen.jpg"
```

La clasificación se basa en el contenido. Después se compara el nombre como evidencia adicional; la extensión no decide el tipo. Un `.jpg` con PHP puede mostrar **PHP probable**, MIME `text/plain` y una discrepancia de extensión.

### 2. Inspeccionar un ZIP y sus miembros

```bash
file_magic_number "entrega.zip"
```

El árbol identifica cada miembro por separado y propaga al contenedor los avisos de revisión o de alcance incompleto. Para profundizar en anidados:

```bash
file_magic_number --max-depth 3 --max-members 100 --timeout 60 "entrega.zip"
```

### 3. Revisar documentos y paquetes

```bash
file_magic_number "documento.docx"
file_magic_number "presentacion.pptm"
file_magic_number "aplicacion.apk"
file_magic_number "aplicacion.jar"
```

Se reconocen estructuras compatibles y se inspeccionan miembros cuando es posible. Encontrar `word/vbaProject.bin` señala un componente potencial de macros; no verifica ni extrae sus instrucciones. Los bytes binarios de Android/Java no se decompilan.

### 4. Recorrer un respaldo comprimido

```bash
file_magic_number "respaldo.tar.gz"
file_magic_number "codigo.php.gz"
```

GZIP/BZIP2/XZ producen un miembro virtual con el contenido descomprimido. En `tar.gz`, la capa comprimida y el TAR consumen dos niveles; el límite predeterminado permite analizar los archivos regulares de ese TAR.

### 5. Comparar contra un MIME esperado

```bash
file_magic_number --expect 'image/*' "subida.png"
file_magic_number --expect application/pdf "curriculum.pdf"
```

La comparación usa el MIME **detectado localmente** por libmagic y se aplica solo a los archivos raíz. No recibe ni verifica el `Content-Type` HTTP enviado al servidor. Tampoco reproduce la política de subida o ejecución de la aplicación.

### 6. Revisar varios archivos por terminal

```bash
file_magic_number "foto.png" "documento.pdf" "paquete.zip"
file_magic_number ./muestras/*.zip
```

Acepta hasta 100 rutas de archivo por lote; los presupuestos de miembros, bytes y tiempo se comparten. No recorre carpetas del sistema automáticamente.

## Salida y colores

La terminal muestra secciones **ARCHIVO**, tipo/MIME, evidencias, miembros indentados y **RESUMEN**. Un ejemplo resumido del árbol:

```text
ARCHIVO · entrega.zip  [REVISAR]
  Tipo     contenedor ZIP; subtipo no determinado por la firma
  MIME     application/zip
  Contenedor ZIP

  ↳ imagen.jpg  [REVISAR]
    Tipo     código PHP probable (.php)
    MIME     text/plain
    ! Extensión .jpg y MIME text/plain no concuerdan según la tabla...
    • Contenido: PHP | probable | documento | byte 1 | apertura <?= y tokens de código
```

| Indicador | Color habitual | Interpretación |
| --- | --- | --- |
| `CONCORDANTE` | Verde | MIME y firma compatibles; no significa que el archivo sea seguro. |
| `PARCIAL` | Amarillo | Identificación parcial, contenido probable o alcance limitado. |
| `REVISAR` | Rojo | Discrepancias, contenido adicional o miembros que requieren revisión. |
| `ERROR` | Rojo | Fallo técnico o archivo no accesible. |

Los colores se activan automáticamente con una salida TTY. Se omiten al redirigir, con `NO_COLOR` o con `TERM=dumb`. Los nombres con controles ANSI, saltos de línea o marcas de dirección de texto se muestran escapados.

```bash
file_magic_number --color always "archivo.zip"
file_magic_number --no-color "archivo.zip"
```

`--verbose` muestra más evidencia: firmas y offsets, cabecera hexadecimal, descripción de `file`, comprobaciones de estructura y notas del analizador. No amplía por sí solo la muestra.

## Opciones y límites

```bash
file_magic_number --help
```

| Opción | Predeterminado | Alcance |
| --- | --- | --- |
| `--max-depth N` | `2` | Hasta 5 niveles. Raíz = 0; `0` omite interiores. |
| `--no-archives` | Desactivado | Identifica el contenedor sin recorrer miembros; se informa como incompleto. |
| `--max-members N` | `50` | Entradas globales, incluidos directorios; máximo 1000. |
| `--max-member-mib N` | `8` | Máximo descomprimido por miembro; hasta 64 MiB. |
| `--max-total-mib N` | `64` | Presupuesto global descomprimido; hasta 256 MiB. Los anidados consumen presupuesto de nuevo en cada capa. |
| `--max-ratio N` | `200` | Relación máxima entre bytes descomprimidos y comprimidos; hasta 1000. Superarlo no prueba que exista una bomba. |
| `--timeout N` | `30` | Segundos de tiempo total para el lote; hasta 120. |
| `--max-bytes N` | `1048576` | Muestra de contenido por archivo; entre 4096 y 16777216 bytes. No sustituye los límites de descompresión. |
| `--expect MIME` | Ninguno | Compara MIME local de las raíces con un valor, o con `image/*`, por ejemplo. |
| `--color auto/always/never` | `auto` | Control de colores; `--no-color` equivale a `never`. |

Antes de abrir el directorio ZIP se comprueban límites de **10000 entradas y 8 MiB de metadatos**. Se omiten directorios ZIP64/multipartes y contenedores mayores de **512 MiB**. El parser TAR tiene además un presupuesto de lectura para impedir solicitudes de metadatos desmedidas.

Las cifras de `omitidos registrados` cuentan miembros omitidos explícitamente; una interrupción de profundidad, tiempo o metadatos puede dejar otros sin enumerar. El resumen indica **INCOMPLETO** cuando se conoce una limitación. Aun sin ese aviso, solo se aplicaron las firmas, muestras y parsers descritos aquí.

## Manejo de contenedores

| Formato | Inspección |
| --- | --- |
| ZIP | Directorio y archivos regulares no cifrados con métodos soportados por la biblioteca estándar instalada; CRC al terminar la lectura del miembro. |
| DOCX/XLSX/PPTX, variantes con macros, JAR/APK/EPUB | Recorrido ZIP y marcadores de estructura; no se certifica el formato completo. |
| TAR | Archivos regulares; no se siguen enlaces ni se materializan dispositivos, FIFO o archivos sparse. |
| GZIP/BZIP2/XZ | Descompresión acotada y análisis del miembro virtual; puede revelar otro contenedor. |
| RAR, 7z, Zstd y OLE/Office antiguo | Identificación exterior cuando es posible, sin inspección interna en esta versión. Se marca esa limitación. |

No se utilizan `extract`/`extractall` para escribir miembros en sus rutas. Los archivos regulares permitidos se leen a copias temporales dentro de una carpeta privada, con nombres controlados por el programa, y se eliminan al terminar normalmente. Los originales no se modifican. No se ejecutan miembros, macros, comandos encontrados ni conexiones de relaciones externas.

Una estructura ZIP válida tras una cabecera distinta se señala como posible contenido concatenado o autoextraíble. No basta para certificar un políglota. Los cifrados, errores de lectura, métodos no soportados, CRC incorrectos y límites agotados quedan visibles; no se presentan como contenido limpio.

## Capas de identificación conservadas

1. `file`/libmagic detecta un MIME y una descripción.
2. La tabla local compara firmas con posiciones y comodines: **259 reglas para 201 familias**.
3. El analizador de contenido busca indicadores de lenguajes y estructuras, sin confiar en el nombre.
4. Los parsers de contenedores contextualizan el contenido y aplican presupuestos compartidos.

PHP puede reconocerse con `<?php` y `<?=`, incluso tras saltos de línea o BOM. Se distinguen, de manera heurística, ejemplos citados en JSON, Markdown y algunos lenguajes de programación. Se mantienen las pistas de Python, JavaScript/TypeScript, Shell, HTML, XML/SVG, JSON, SQL, CSS y C/C++.

La muestra predeterminada es 1 MiB. Los marcadores PHP se buscan en esa muestra con un máximo de 64 bloques y hasta 64 KiB por bloque. Los lenguajes generales y parsers usan una ventana de hasta 131072 caracteres; el parseo completo requiere que el documento quepa y que no se haya cortado la muestra. En binarios se examinan además hasta 16 cadenas legibles de hasta 16 KiB cada una. Los offsets corresponden al archivo o miembro que muestra la sección, no a una posición física equivalente dentro del ZIP comprimido.

Hay comprobaciones básicas de inicio/cierre PNG y cierre EOI JPEG; no se verifican todos los CRC de imagen, segmentos o píxeles. `ast.parse` no ejecuta el código Python ni valida todos los aspectos semánticos. Las relaciones XML se analizan hasta 128 KiB, con DTD deshabilitadas, también cuando están codificadas en UTF-16. Si se supera ese límite o no se puede parsear el documento, la comprobación se marca como omitida.

El proceso principal limita su memoria virtual a 512 MiB y el analizador de contenido a 384 MiB y hasta 5 segundos de CPU/8 segundos de espera externa. Se respetan límites heredados más estrictos. Estos son controles de recursos, no una garantía de aislamiento frente a vulnerabilidades de los parsers instalados.

## Códigos de salida

| Código | Significado |
| --- | --- |
| `0` | Evidencia concordante dentro de los controles aplicados. No certifica seguridad. |
| `1` | Evidencia parcial, contenido textual probable, formato desconocido u omisiones/límites. |
| `2` | Error de uso, dependencia, lectura o análisis técnico. Tiene prioridad si el lote también contiene avisos. |
| `3` | Elementos para revisar: discrepancias, rutas problemáticas, indicadores o ambigüedad. No significa automáticamente malware. |

El código agregado contempla los miembros. Una coincidencia de PHP en los bytes de un TAR/ZIP válido puede corresponder simplemente a un archivo fuente empaquetado: se conserva la evidencia y se contextualiza por miembro, en lugar de declararlo automáticamente un políglota.

## Procedencia y mantenimiento

La tabla se deriva de [TheDiscordian/magic-bytes](https://github.com/TheDiscordian/magic-bytes), revisión [`26e7a9bd21d6b9d08740fb91b4a0f49754daacdb`](https://github.com/TheDiscordian/magic-bytes/tree/26e7a9bd21d6b9d08740fb91b4a0f49754daacdb), con licencia MIT. Se conservan los datos originales, su licencia, hashes y un informe del proceso de importación; este último describe la base de firmas, no genera resultados de análisis de tus archivos.

| Archivo | Función |
| --- | --- |
| `file_magic_number` | Entrada Bash pública, compatible con el enlace de `/usr/local/bin`. |
| `lib/terminal_scan.py` | Terminal, presupuestos, nombres y contenedores. |
| `lib/file_probe.sh` | Motor interno de MIME, firmas y comprobaciones básicas. |
| `lib/content_probe.py` | Reconocimiento pasivo de contenido y lenguajes. |
| `data/signatures.tsv` | Reglas locales normalizadas. |
| `data/upstream/` | Fuentes originales, licencia y procedencia. |
| `tools/build_signatures.py` | Reconstrucción reproducible de la tabla. |

```bash
python3 tools/build_signatures.py
bash -n file_magic_number
bash -n lib/file_probe.sh
python3 -m unittest discover -s tests -v
```

Las pruebas cubren el motor de identificación y la CLI pública: anidados, rutas problemáticas, enlaces, cifrados, nombres duplicados, archivos dañados, límites de lectura/descompresión/tiempo, marcadores de paquetes, colores, controles de terminal y limpieza temporal. No requieren conexión ni paquetes Python externos. Verifican comportamientos; no representan una medición universal de precisión.

## Uso e interpretación en pentest

Utiliza los resultados para decidir qué archivo o comportamiento del servidor revisar después: validación de subidas, manejo de nombres, procesamiento de documentos, extracción de contenedores o contenido activo inesperado. El programa hace análisis local; no prueba endpoints, no confirma ejecución remota y no reemplaza analizadores de macros, decompiladores o validadores completos.

La ausencia de hallazgos no demuestra ausencia de código o de vulnerabilidades. Las firmas y reglas pueden tener errores, los lenguajes pueden ser ambiguos y un archivo puede contener datos fuera de los límites. MIME y firmas tampoco constituyen pruebas estadísticamente independientes.

Referencias: [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), [file/libmagic](https://github.com/file/file/blob/master/doc/file.man), [ZIP](https://docs.python.org/3/library/zipfile.html), [TAR](https://docs.python.org/3/library/tarfile.html), [etiquetas PHP](https://www.php.net/manual/en/language.basic-syntax.phptags.php).
