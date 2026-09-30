# jsonlink — JSON object-file linker

`jsonlink` is a small command-line linker. Its input is a JSON description of one
or more object files; it does not parse ELF or any other native object format.

## Input format

```json
{
  "objects": [
    {
      "name": "example.o",
      "align": 16,
      "text": "c390",
      "data": "78563412",
      "symbols": [
        {"name": "main", "binding": "strong", "section": "text", "value": 0},
        {"name": "helper", "binding": "weak", "section": "text", "value": 1},
        {"name": "state", "binding": "local", "section": "data", "value": 2}
      ],
      "relocations": [
        {"section": "data", "offset": 0, "type": "ABS32", "symbol": "main"},
        {"section": "text", "offset": 0, "type": "PCREL16", "symbol": "helper"}
      ]
    }
  ]
}
```

- `text` and `data` are byte strings encoded as hexadecimal.
- Object `align` must be 1, 2, 4, 8, or 16 bytes and defaults to 1.
- Symbol `binding` is `local`, `strong`, or `weak`.
- Symbol `value` is an offset inside that object's named section.
- Relocation `type` is:
  - `ABS32`: writes `S + A` as a 32-bit little-endian value.
  - `PCREL16`: writes `S + A - (P + 2)` as a signed 16-bit little-endian value.

Here `S` is the symbol address, `A` is the optional addend, `P` is the patch's
start address, and `P + 2` is the end of the PCREL16 patch.

## Layout and symbol rules

- All non-empty `.text` sections are placed first, followed by all non-empty
  `.data` sections.
- Sections within each group retain input object order.
- Each object chunk is placed at the next offset satisfying that object's
  alignment. Alignment gaps contain zero bytes.
- The image base address is `0x1000`.
- Local symbols are resolved only inside their own object.
- A strong global definition wins over weak definitions.
- Multiple weak definitions resolve to the first input object's definition.
- Multiple strong definitions, unresolved symbols, patches crossing a section,
  ABS32 values outside 32 bits, and PCREL16 values outside signed 16 bits are
  errors.

All validation and patching is completed in memory first. An image file is
published only after a successful link, using a temporary file and atomic
rename. The linker exits with an error and no completed report instead of
leaving a half-linked image.

## Usage

```sh
# Write image to a.out and print the JSON evidence report to stdout.
go run . objects.json

# Explicit output paths.
go run . -o image.bin -report report.json objects.json

# Include the complete linked image as hex in the report.
go run . -o image.bin -image-hex objects.json

# Read JSON from stdin and write the raw image to stdout.
cat objects.json | go run . -o - -report /dev/null -
```

The report contains the chunk layout, global and object-local symbol
addresses, every symbol definition (including unused weak definitions), and
per-relocation before/after bytes with the formula used to produce them.
