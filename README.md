# 🔎 file_magic_number

**Descubre qué contiene un archivo, aunque su extensión diga otra cosa.**

Herramienta de línea de comandos escrita en Bash que identifica formatos mediante `file`/libmagic y firmas de cabecera (*magic numbers*). Ofrece resultados en español y un modo detallado para inspeccionar el MIME y los primeros bytes.

```console
$ ./file_magic_number imagen.php
El archivo parece ser: .png (imagen PNG)
```

En este ejemplo, `imagen.php` contiene una imagen PNG: el resultado depende de su contenido.

## Características

- Identificación por contenido sin confiar en la extensión del nombre.
- Nombres legibles para imágenes, documentos, archivos comprimidos, ejecutables, código y otros formatos.
- Modo `--verbose` con MIME, descripción de `file` y hasta 32 bytes en hexadecimal.
- Comparación adicional de cabeceras conocidas cuando el formato no está en la tabla de nombres del script.
- Soporte para rutas con espacios, enlaces simbólicos y nombres que empiezan por `-`.
- Mensajes explícitos para archivos vacíos, formatos desconocidos y errores de lectura.
- Análisis local: no envía archivos a ningún servidor ni necesita conexión a Internet para ejecutarse.

## Requisitos

Entorno Linux con **Bash**, **file/libmagic** y las utilidades **od**, **tr** y **cat** de Coreutils. Para descargar el repositorio mediante los siguientes pasos, también necesitas Git.

**Arch Linux:**

```bash
sudo pacman -S bash file coreutils git
```

**Debian, Ubuntu o Kali:**

```bash
sudo apt install bash file coreutils git
```

## Instalación

```bash
git clone https://github.com/david-rootbox/file_magic_number.git
cd file_magic_number
chmod +x file_magic_number
```

## Uso

### Identificar un archivo

```bash
./file_magic_number "archivo.php"
```

### Mostrar MIME y bytes de cabecera

```bash
./file_magic_number --verbose "archivo.php"
```

Ejemplo con un PNG de 1 × 1 píxeles renombrado a `.php`:

```text
El archivo parece ser: .png (imagen PNG)
MIME: image/png
Descripción de file: PNG image data, 1 x 1, 8-bit/color RGB, non-interlaced
Método: libmagic: firmas y otras comprobaciones del contenido
Primeros 32 bytes (o los disponibles), en hexadecimal:
 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52
 00 00 00 01 00 00 00 01 08 02 00 00 00 90 77 53
```

### Rutas con espacios y variables

```bash
./file_magic_number "./mis archivos/imagen.bin"

archivo="./mis archivos/imagen.bin"
./file_magic_number "$archivo"
```

### Nombres que empiezan por un guion

Usa `--` para terminar la lista de opciones:

```bash
./file_magic_number -- -archivo.bin
```

### Ayuda

```bash
./file_magic_number --help
```

## Cómo interpreta los resultados

1. Consulta el MIME y la descripción que detecta `file`/libmagic.
2. Asigna un nombre representativo a los formatos frecuentes.
3. Si no encuentra ese nombre, compara algunas firmas conocidas de la cabecera.
4. Para otros formatos, consulta las extensiones que ofrece libmagic y conserva su descripción cuando está disponible.

Si únicamente coincide una cabecera, muestra una aclaración:

```text
El archivo parece ser: .png (imagen PNG)
Nota: solo coincide la firma de cabecera; no confirma un archivo válido.
```

Si no puede identificar el formato, lo indica sin asignar una extensión:

```text
No se pudo identificar un formato concreto.
Descripción de file: data
```

El texto plano se informa como **texto plano (sin extensión única)**.

## Códigos de salida

| Código | Significado |
| --- | --- |
| `0` | Se reconoció un tipo de contenido o una firma. |
| `1` | Archivo vacío o sin un formato concreto identificado. |
| `2` | Error de uso, dependencia o lectura. |

El código `0` **no significa que el archivo sea válido o seguro**.

## Alcance

La identificación es orientativa. Algunos formatos comparten firmas, otros no tienen una firma única y las cabeceras pueden estar incompletas o manipuladas. La extensión mostrada es representativa; puede haber varias extensiones posibles para un mismo contenido.

El script se apoya en la base de libmagic instalada y no sustituye un validador específico del formato ni un análisis de seguridad. La comparación adicional de cabeceras cubre un conjunto limitado de firmas; no detecta todos los formatos ni garantiza descubrir contenidos incrustados o archivos políglotas.

El archivo analizado se lee para identificarlo; el script no lo ejecuta ni lo modifica.

## Referencias

- [Documentación de file](https://github.com/file/file/blob/master/doc/file.man)
- [Base de firmas de file/libmagic](https://github.com/file/file/tree/master/magic/Magdir)
- [GCK File Signatures — SEARCH](https://filesig.search.org/)
- [Tabla clásica de Gary Kessler](https://www.garykessler.net/library/file_sigs_GCK_latest.html)
