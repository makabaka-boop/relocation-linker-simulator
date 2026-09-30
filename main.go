// Command jsonlink links a small, JSON-described object format into a raw
// little-endian memory image. It deliberately does not parse ELF.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	baseAddress = 0x1000
	abs32Size   = 4
	pcrel16Size = 2
)

// ByteSlice is a byte slice represented as a hex string in JSON.
type ByteSlice []byte

func (b ByteSlice) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString([]byte(b)))
}

func (b *ByteSlice) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*b = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("must be a hex string: %w", err)
	}
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		*b = nil
		return nil
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid hex bytes: %w", err)
	}
	*b = ByteSlice(raw)
	return nil
}

// Hex renders an unsigned integer as a 0x-prefixed hexadecimal JSON string.
type Hex uint64

func (h Hex) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%x", uint64(h)))
}

func (h *Hex) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		v, err := parseHexUint64(s)
		if err != nil {
			return err
		}
		*h = Hex(v)
		return nil
	}

	var n uint64
	if err := json.Unmarshal(data, &n); err != nil {
		return fmt.Errorf("hex number must be a decimal number or 0x string: %w", err)
	}
	*h = Hex(n)
	return nil
}

func parseHexUint64(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	var v uint64
	for _, c := range s {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = byte(c - '0')
		case c >= 'a' && c <= 'f':
			d = byte(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = byte(c-'A') + 10
		default:
			return 0, fmt.Errorf("invalid hexadecimal number %q", s)
		}
		if v > (^uint64(0)-uint64(d))/16 {
			return 0, fmt.Errorf("hexadecimal number 0x%s overflows uint64", s)
		}
		v = v*16 + uint64(d)
	}
	return v, nil
}

type inputFile struct {
	Objects []inputObject `json:"objects"`
}

type inputObject struct {
	Name        string        `json:"name,omitempty"`
	Align       *int64        `json:"align,omitempty"`
	Text        ByteSlice     `json:"text,omitempty"`
	Data        ByteSlice     `json:"data,omitempty"`
	Symbols     []inputSymbol `json:"symbols,omitempty"`
	Relocations []inputReloc  `json:"relocations,omitempty"`
}

type inputSymbol struct {
	Name    string `json:"name"`
	Binding string `json:"binding"` // local, strong, or weak
	Section string `json:"section"` // text or data
	Value   int64  `json:"value"`
}

type inputReloc struct {
	Section string `json:"section"` // text or data
	Offset  int64  `json:"offset"`
	Type    string `json:"type"` // ABS32 or PCREL16
	Symbol  string `json:"symbol"`
	Addend  int64  `json:"addend"`
}

type chunk struct {
	object  int
	name    string
	section string
	offset  int
	size    int
	align   int
}

type symbolDef struct {
	name     string
	object   int
	binding  string
	section  string
	value    int
	address  int
	selected bool
}

type preparedReloc struct {
	object      int
	objectName  string
	section     string
	offset      int
	typ         string
	symbol      string
	symbolObj   int
	addend      int64
	patchAddr   int64
	targetAddr  int64
	oldBytes    []byte
	written     []byte
	absValue    uint32
	delta       int64
	imageOffset int
}

// Report is the machine-readable link report.
type Report struct {
	BaseAddress Hex                 `json:"base_address"`
	ImagePath   string              `json:"image_path,omitempty"`
	ImageSize   int                 `json:"image_size"`
	ImageSHA256 string              `json:"image_sha256_hex"`
	Layout      []LayoutReport      `json:"layout"`
	SymbolAddrs SymbolAddressReport `json:"symbol_addresses"`
	Symbols     []SymbolReport      `json:"symbols"`
	Relocations []RelocReport       `json:"relocations"`
	ImageHex    string              `json:"image_hex,omitempty"`
}

type LayoutReport struct {
	ObjectIndex int    `json:"object_index"`
	ObjectName  string `json:"object_name,omitempty"`
	Section     string `json:"section"`
	ImageOffset Hex    `json:"image_offset"`
	Address     Hex    `json:"address"`
	Size        int    `json:"size"`
	Alignment   int    `json:"alignment"`
}

type SymbolAddressReport struct {
	Global map[string]Hex `json:"global"`
	Local  []LocalAddress `json:"local"`
}

type LocalAddress struct {
	ObjectIndex int    `json:"object_index"`
	ObjectName  string `json:"object_name,omitempty"`
	Name        string `json:"name"`
	Address     Hex    `json:"address"`
}

type SymbolReport struct {
	ObjectIndex   int    `json:"object_index"`
	ObjectName    string `json:"object_name,omitempty"`
	Name          string `json:"name"`
	Binding       string `json:"binding"`
	Section       string `json:"section"`
	SectionOffset Hex    `json:"section_offset"`
	Address       Hex    `json:"address"`
	Selected      bool   `json:"selected"`
}

type RelocReport struct {
	ObjectIndex  int    `json:"object_index"`
	ObjectName   string `json:"object_name,omitempty"`
	Section      string `json:"section"`
	Offset       Hex    `json:"offset"`
	ImageOffset  Hex    `json:"image_offset"`
	PatchAddress Hex    `json:"patch_address"`
	Type         string `json:"type"`
	Symbol       string `json:"symbol"`
	SymbolObject int    `json:"symbol_object_index"`
	Addend       int64  `json:"addend"`
	Target       Hex    `json:"target_address"`
	BytesBefore  string `json:"bytes_before"`
	BytesWritten string `json:"bytes_written"`
	Value        Hex    `json:"absolute_value,omitempty"`
	SignedDelta  *int64 `json:"signed_delta,omitempty"`
	Formula      string `json:"formula"`
}

type linker struct {
	objs     []inputObject
	aligns   []int
	chunks   []chunk
	defs     []symbolDef
	locals   []map[string]int
	globals  map[string][]int
	winners  map[string]int
	image    []byte
	prepared []preparedReloc
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "jsonlink:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("jsonlink", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outPath := fs.String("o", "a.out", "write raw image to `path` (use - for stdout)")
	reportPath := fs.String("report", "-", "write JSON report to `path` (- for stdout)")
	includeImageHex := fs.Bool("image-hex", false, "include the complete image as hex in the report")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: jsonlink [-o image.bin] [flags] objects.json\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("exactly one JSON input file is required (use - for stdin)")
	}
	if *outPath == "-" && *reportPath == "-" {
		return errors.New("refusing to write raw image and JSON report to stdout together")
	}

	input, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}

	image, report, err := link(input)
	if err != nil {
		return err
	}
	if *includeImageHex {
		report.ImageHex = hex.EncodeToString(image)
	}
	if *outPath != "-" {
		report.ImagePath = *outPath
	}

	// The complete image has already been constructed in memory. The file is
	// published with rename so a failure cannot leave a truncated image.
	if err := writeImage(*outPath, image, stdout); err != nil {
		return err
	}
	if *outPath == "-" {
		return nil // raw image consumes stdout
	}

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	reportJSON = append(reportJSON, '\n')
	if err := writeReport(*reportPath, reportJSON, stdout); err != nil {
		return err
	}
	return nil
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return data, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

// link performs every validation and relocation in memory. It returns no
// image or report if there is any error.
func link(data []byte) ([]byte, Report, error) {
	var in inputFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, Report{}, fmt.Errorf("parse JSON: %w", err)
	}
	if dec.More() {
		return nil, Report{}, errors.New("parse JSON: unexpected second JSON value")
	}

	l := &linker{
		objs:    in.Objects,
		aligns:  make([]int, len(in.Objects)),
		locals:  make([]map[string]int, len(in.Objects)),
		globals: make(map[string][]int),
		winners: make(map[string]int),
	}
	if err := l.validate(); err != nil {
		return nil, Report{}, err
	}
	l.layout()
	l.resolveGlobals()
	if err := l.resolveSymbolsAndRelocations(); err != nil {
		return nil, Report{}, err
	}
	l.applyRelocations()

	report := l.makeReport()
	// Return a copy so callers cannot mutate the image through the report's
	// backing array in future edits.
	image := append([]byte(nil), l.image...)
	return image, report, nil
}

func (l *linker) validate() error {
	var errs []string
	validAlign := map[int64]bool{1: true, 2: true, 4: true, 8: true, 16: true}
	validBinding := map[string]bool{"local": true, "strong": true, "weak": true}
	validSection := map[string]bool{"text": true, "data": true}

	for i := range l.objs {
		l.locals[i] = make(map[string]int)
	}

	// Validate objects and build the symbol tables in one pass. Local symbols
	// are namespaced by object, while strong and weak symbols are global.
	for i := range l.objs {
		obj := &l.objs[i]
		label := objectLabel(i, obj.Name)

		align := int64(1)
		if obj.Align != nil {
			align = *obj.Align
		}
		if !validAlign[align] {
			errs = append(errs, fmt.Sprintf("%s: alignment %d is not one of 1, 2, 4, 8, 16", label, align))
		}
		l.aligns[i] = int(align)

		for si := range obj.Symbols {
			sym := &obj.Symbols[si]
			prefix := fmt.Sprintf("%s: symbol %q", label, sym.Name)
			if sym.Name == "" {
				errs = append(errs, fmt.Sprintf("%s: empty name", prefix))
			}
			if !validBinding[sym.Binding] {
				errs = append(errs, fmt.Sprintf("%s: binding %q must be local, strong, or weak", prefix, sym.Binding))
			}
			if !validSection[sym.Section] {
				errs = append(errs, fmt.Sprintf("%s: section %q must be text or data", prefix, sym.Section))
				continue
			}

			sectionBytes := obj.sectionBytes(sym.Section)
			validValue := true
			if len(sectionBytes) == 0 {
				errs = append(errs, fmt.Sprintf("%s: symbol cannot be placed in empty .%s", prefix, sym.Section))
				validValue = false
			} else if sym.Value < 0 || sym.Value > int64(len(sectionBytes)) {
				errs = append(errs, fmt.Sprintf("%s: value 0x%x is outside .%s (size 0x%x)", prefix, sym.Value, sym.Section, len(sectionBytes)))
				validValue = false
			}

			if sym.Name == "" || !validBinding[sym.Binding] || !validValue {
				continue
			}
			idx := len(l.defs)
			l.defs = append(l.defs, symbolDef{
				name:    sym.Name,
				object:  i,
				binding: sym.Binding,
				section: sym.Section,
				value:   int(sym.Value),
			})
			if sym.Binding == "local" {
				if _, exists := l.locals[i][sym.Name]; exists {
					errs = append(errs, fmt.Sprintf("%s: duplicate local symbol", prefix))
					continue
				}
				l.locals[i][sym.Name] = idx
			} else {
				l.globals[sym.Name] = append(l.globals[sym.Name], idx)
			}
		}

		for ri := range obj.Relocations {
			r := &obj.Relocations[ri]
			width := relocWidth(r.Type)
			prefix := fmt.Sprintf("%s: relocation %d", label, ri)
			if width == 0 {
				errs = append(errs, fmt.Sprintf("%s: type %q must be ABS32 or PCREL16", prefix, r.Type))
				continue
			}
			if !validSection[r.Section] {
				errs = append(errs, fmt.Sprintf("%s: section %q must be text or data", prefix, r.Section))
				continue
			}
			if r.Symbol == "" {
				errs = append(errs, fmt.Sprintf("%s: empty symbol", prefix))
			}
			sectionBytes := obj.sectionBytes(r.Section)
			if r.Offset < 0 || r.Offset+int64(width) > int64(len(sectionBytes)) {
				errs = append(errs, fmt.Sprintf(
					"%s: %s patch at offset 0x%x is outside .%s (size 0x%x, patch width %d)",
					prefix, r.Type, r.Offset, r.Section, len(sectionBytes), width,
				))
			}
		}
	}

	for name, defs := range l.globals {
		winner := -1
		strongCount := 0
		for _, idx := range defs {
			d := &l.defs[idx]
			if d.binding == "strong" {
				strongCount++
				winner = idx // strong always replaces a weak candidate
			} else if winner < 0 {
				// Object order is preserved, so this selects the first weak
				// definition when no strong definition exists.
				winner = idx
			}
		}
		if strongCount > 1 {
			errs = append(errs, fmt.Sprintf("global symbol %q has %d strong definitions", name, strongCount))
			continue
		}
		l.winners[name] = winner
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (o *inputObject) sectionBytes(section string) []byte {
	if section == "text" {
		return o.Text
	}
	return o.Data
}

func relocWidth(typ string) int {
	switch typ {
	case "ABS32":
		return abs32Size
	case "PCREL16":
		return pcrel16Size
	default:
		return 0
	}
}

func (l *linker) layout() {
	cursor := 0
	addSection := func(section string) {
		for i := range l.objs {
			b := l.objs[i].sectionBytes(section)
			if len(b) == 0 {
				continue
			}
			aligned := alignOffset(cursor, l.aligns[i])
			c := chunk{
				object:  i,
				name:    l.objs[i].Name,
				section: section,
				offset:  aligned,
				size:    len(b),
				align:   l.aligns[i],
			}
			l.chunks = append(l.chunks, c)
			cursor = aligned + len(b)
		}
	}
	addSection("text")
	addSection("data")

	l.image = make([]byte, cursor)
	for _, c := range l.chunks {
		copy(l.image[c.offset:], l.objs[c.object].sectionBytes(c.section))
	}
}

func alignOffset(offset, alignment int) int {
	if alignment <= 1 {
		return offset
	}
	return (offset + alignment - 1) / alignment * alignment
}

func (l *linker) resolveGlobals() {
	for _, idx := range l.winners {
		l.defs[idx].selected = true
	}
}

func (l *linker) chunkForObjectSection(obj int, section string) (chunk, bool) {
	for _, c := range l.chunks {
		if c.object == obj && c.section == section {
			return c, true
		}
	}
	return chunk{}, false
}

func (l *linker) resolveSymbolsAndRelocations() error {
	// Assign every symbol definition its actual address, including weak
	// definitions not selected for resolution.
	for i := range l.defs {
		d := &l.defs[i]
		c, ok := l.chunkForObjectSection(d.object, d.section)
		if !ok {
			return fmt.Errorf("internal error: missing chunk for %s .%s", objectLabel(d.object, l.objs[d.object].Name), d.section)
		}
		d.address = baseAddress + c.offset + d.value
	}

	var errs []string
	for oi := range l.objs {
		obj := &l.objs[oi]
		label := objectLabel(oi, obj.Name)
		for ri := range obj.Relocations {
			r := &obj.Relocations[ri]
			width := relocWidth(r.Type)
			c, ok := l.chunkForObjectSection(oi, r.Section)
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: relocation %d targets empty .%s", label, ri, r.Section))
				continue
			}
			imageOff := c.offset + int(r.Offset)
			patchAddr := int64(baseAddress + c.offset + int(r.Offset))

			defIdx, local := l.locals[oi][r.Symbol]
			if !local {
				var found bool
				defIdx, found = l.winners[r.Symbol]
				if !found {
					errs = append(errs, fmt.Sprintf("%s: relocation %d: unresolved symbol %q", label, ri, r.Symbol))
					continue
				}
			}
			def := &l.defs[defIdx]
			target := int64(def.address) + r.Addend

			old := append([]byte(nil), l.image[imageOff:imageOff+width]...)
			p := preparedReloc{
				object:      oi,
				objectName:  obj.Name,
				section:     r.Section,
				offset:      int(r.Offset),
				typ:         r.Type,
				symbol:      r.Symbol,
				symbolObj:   def.object,
				addend:      r.Addend,
				patchAddr:   patchAddr,
				targetAddr:  target,
				oldBytes:    old,
				imageOffset: imageOff,
			}

			switch r.Type {
			case "ABS32":
				if target < 0 || target > 0xffffffff {
					errs = append(errs, fmt.Sprintf(
						"%s: relocation %d: ABS32 target %s for %q is outside [0, 0xffffffff]",
						label, ri, signedHex(target), r.Symbol,
					))
					continue
				}
				p.absValue = uint32(target)
				p.written = []byte{0, 0, 0, 0}
				binary.LittleEndian.PutUint32(p.written, p.absValue)
			case "PCREL16":
				end := patchAddr + pcrel16Size
				delta := target - end
				if delta < -32768 || delta > 32767 {
					errs = append(errs, fmt.Sprintf(
						"%s: relocation %d: PCREL16 delta %d (0x%x) for %q is outside int16",
						label, ri, delta, delta, r.Symbol,
					))
					continue
				}
				p.delta = delta
				p.written = []byte{0, 0}
				binary.LittleEndian.PutUint16(p.written, uint16(int16(delta)))
			}
			l.prepared = append(l.prepared, p)
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (l *linker) applyRelocations() {
	for _, p := range l.prepared {
		copy(l.image[p.imageOffset:p.imageOffset+len(p.written)], p.written)
	}
}

func (l *linker) makeReport() Report {
	r := Report{
		BaseAddress: Hex(baseAddress),
		ImageSize:   len(l.image),
		ImageSHA256: fmt.Sprintf("%x", sha256.Sum256(l.image)),
		Layout:      make([]LayoutReport, 0, len(l.chunks)),
		SymbolAddrs: SymbolAddressReport{
			Global: make(map[string]Hex),
			Local:  make([]LocalAddress, 0),
		},
		Symbols:     make([]SymbolReport, 0, len(l.defs)),
		Relocations: make([]RelocReport, 0, len(l.prepared)),
	}
	for _, c := range l.chunks {
		r.Layout = append(r.Layout, LayoutReport{
			ObjectIndex: c.object,
			ObjectName:  c.name,
			Section:     c.section,
			ImageOffset: Hex(c.offset),
			Address:     Hex(baseAddress + c.offset),
			Size:        c.size,
			Alignment:   c.align,
		})
	}
	for i := range l.defs {
		d := &l.defs[i]
		r.Symbols = append(r.Symbols, SymbolReport{
			ObjectIndex:   d.object,
			ObjectName:    l.objs[d.object].Name,
			Name:          d.name,
			Binding:       d.binding,
			Section:       d.section,
			SectionOffset: Hex(d.value),
			Address:       Hex(d.address),
			Selected:      d.selected,
		})
		if d.binding == "local" {
			r.SymbolAddrs.Local = append(r.SymbolAddrs.Local, LocalAddress{
				ObjectIndex: d.object,
				ObjectName:  l.objs[d.object].Name,
				Name:        d.name,
				Address:     Hex(d.address),
			})
		} else if d.selected {
			r.SymbolAddrs.Global[d.name] = Hex(d.address)
		}
	}
	for _, p := range l.prepared {
		rr := RelocReport{
			ObjectIndex:  p.object,
			ObjectName:   p.objectName,
			Section:      p.section,
			Offset:       Hex(p.offset),
			ImageOffset:  Hex(p.imageOffset),
			PatchAddress: Hex(p.patchAddr),
			Type:         p.typ,
			Symbol:       p.symbol,
			SymbolObject: p.symbolObj,
			Addend:       p.addend,
			Target:       Hex(uint64(p.targetAddr)),
			BytesBefore:  hex.EncodeToString(p.oldBytes),
			BytesWritten: hex.EncodeToString(p.written),
		}
		if p.typ == "ABS32" {
			rr.Value = Hex(p.absValue)
			rr.Formula = "S + A"
		} else {
			delta := p.delta
			rr.SignedDelta = &delta
			rr.Formula = "S + A - (P + 2)"
		}
		r.Relocations = append(r.Relocations, rr)
	}
	return r
}

func writeImage(path string, image []byte, out io.Writer) error {
	if path == "-" {
		if _, err := out.Write(image); err != nil {
			return fmt.Errorf("write image: %w", err)
		}
		return nil
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, ".tmp-"+base+"-*")
	if err != nil {
		return fmt.Errorf("create temporary image: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	defer cleanup()

	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary image: %w", err)
	}
	if _, err := tmp.Write(image); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary image: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary image: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary image: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publish image: %w", err)
	}
	return nil
}

func writeReport(path string, data []byte, out io.Writer) error {
	if path == "-" {
		if _, err := out.Write(data); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write report %s: %w", path, err)
	}
	return nil
}

func objectLabel(index int, name string) string {
	if name != "" {
		return fmt.Sprintf("object %d (%s)", index, name)
	}
	return fmt.Sprintf("object %d", index)
}

func signedHex(v int64) string {
	if v < 0 {
		return fmt.Sprintf("-0x%x", -v)
	}
	return fmt.Sprintf("0x%x", v)
}
