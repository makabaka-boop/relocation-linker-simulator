package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }

func marshalInput(t *testing.T, in inputFile) []byte {
	t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func buildExpectedImage(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	put := func(data ...byte) { b.Write(data) }
	pad := func(n int) { b.Write(make([]byte, n)) }

	// Object 0 .text at image offset 0:
	// ABS32 at 0 -> local L = 0x1000, little endian 00 10 00 00.
	put(0x00, 0x10, 0x00, 0x00)
	// PCREL16 at 4 -> G = 0x1006; 0x1006 - (0x1004 + 2) = 0.
	put(0x00, 0x00)
	put(0x77, 0x88, 0x99, 0xaa)

	// Object 1 has 16-byte alignment, so its .text starts at offset 16.
	pad(6)
	put(0xb0, 0xb1, 0xb2, 0xb3)
	// PCREL16 at patch address 0x1014 -> local L = 0x1011:
	// 0x1011 - (0x1014 + 2) = -5, encoded fb ff.
	put(0xfb, 0xff)

	// All .text is followed by .data in object order. Object 0's data has
	// 2-byte alignment and offset 22 is already aligned.
	put(0xa0, 0xa1, 0xa2)

	// Object 1's data has 16-byte alignment, so it starts at offset 32.
	pad(7)
	// ABS32 -> D = 0x1017, encoded 17 10 00 00.
	put(0x17, 0x10, 0x00, 0x00)
	put(0xe4, 0xe5)
	return b.Bytes()
}

func TestLinkHandComputedLayoutAndEvidence(t *testing.T) {
	in := inputFile{Objects: []inputObject{
		{
			Name:  "one",
			Align: ptr[int64](2),
			Text:  ByteSlice{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa},
			Data:  ByteSlice{0xa0, 0xa1, 0xa2},
			Symbols: []inputSymbol{
				{Name: "L", Binding: "local", Section: "text", Value: 0},
				{Name: "G", Binding: "strong", Section: "text", Value: 6},
				{Name: "D", Binding: "strong", Section: "data", Value: 1},
			},
			Relocations: []inputReloc{
				{Section: "text", Offset: 0, Type: "ABS32", Symbol: "L"},
				{Section: "text", Offset: 4, Type: "PCREL16", Symbol: "G"},
			},
		},
		{
			Name:  "two",
			Align: ptr[int64](16),
			Text:  ByteSlice{0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5},
			Data:  ByteSlice{0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5},
			Symbols: []inputSymbol{
				{Name: "L", Binding: "local", Section: "text", Value: 1},
				{Name: "H", Binding: "strong", Section: "text", Value: 0},
			},
			Relocations: []inputReloc{
				{Section: "text", Offset: 4, Type: "PCREL16", Symbol: "L"},
				{Section: "data", Offset: 0, Type: "ABS32", Symbol: "D"},
			},
		},
	}}

	image, report, err := link(marshalInput(t, in))
	if err != nil {
		t.Fatal(err)
	}
	if want := buildExpectedImage(t); !bytes.Equal(image, want) {
		t.Fatalf("image mismatch\n got: %s\nwant: %s", hex.EncodeToString(image), hex.EncodeToString(want))
	}

	wantLayout := []struct {
		section string
		offset  int
		size    int
		align   int
	}{
		{"text", 0, 10, 2},
		{"text", 16, 6, 16},
		{"data", 22, 3, 2},
		{"data", 32, 6, 16},
	}
	if len(report.Layout) != len(wantLayout) {
		t.Fatalf("got %d layout entries, want %d", len(report.Layout), len(wantLayout))
	}
	for i, want := range wantLayout {
		got := report.Layout[i]
		if got.Section != want.section || int(got.ImageOffset) != want.offset || got.Size != want.size || got.Alignment != want.align {
			t.Fatalf("layout %d = %+v, want %+v", i, got, want)
		}
		if int(got.Address) != baseAddress+want.offset {
			t.Fatalf("layout %d address = 0x%x", i, got.Address)
		}
	}

	wantGlobals := map[string]int{
		"G": 0x1006,
		"H": 0x1010,
		"D": 0x1017,
	}
	if len(report.SymbolAddrs.Global) != len(wantGlobals) {
		t.Fatalf("global addresses = %v", report.SymbolAddrs.Global)
	}
	for name, addr := range wantGlobals {
		if int(report.SymbolAddrs.Global[name]) != addr {
			t.Fatalf("global %s = 0x%x, want 0x%x", name, report.SymbolAddrs.Global[name], addr)
		}
	}
	locals := report.SymbolAddrs.Local
	if len(locals) != 2 || locals[0].ObjectIndex != 0 || locals[0].Name != "L" || int(locals[0].Address) != 0x1000 ||
		locals[1].ObjectIndex != 1 || locals[1].Name != "L" || int(locals[1].Address) != 0x1011 {
		t.Fatalf("local symbol scope/addresses wrong: %+v", locals)
	}

	wantRelocs := []struct {
		before string
		after  string
		target int
		delta  *int64
	}{
		{before: "11223344", after: "00100000", target: 0x1000},
		{before: "5566", after: "0000", target: 0x1006, delta: ptr[int64](0)},
		{before: "b4b5", after: "fbff", target: 0x1011, delta: ptr[int64](-5)},
		{before: "e0e1e2e3", after: "17100000", target: 0x1017},
	}
	if len(report.Relocations) != len(wantRelocs) {
		t.Fatalf("got %d relocations, want %d", len(report.Relocations), len(wantRelocs))
	}
	for i, want := range wantRelocs {
		got := report.Relocations[i]
		if got.BytesBefore != want.before || got.BytesWritten != want.after || int(got.Target) != want.target {
			t.Fatalf("relocation %d = %+v, want before %s after %s target 0x%x", i, got, want.before, want.after, want.target)
		}
		if want.delta == nil {
			if got.SignedDelta != nil || int(got.Value) != want.target {
				t.Fatalf("ABS evidence %d = %+v", i, got)
			}
		} else if got.SignedDelta == nil || *got.SignedDelta != *want.delta {
			t.Fatalf("PCREL delta %d = %v, want %d", i, got.SignedDelta, *want.delta)
		}
	}
}

func TestAllSupportedObjectAlignments(t *testing.T) {
	in := inputFile{}
	wantOffsets := []int{0, 2, 4, 8, 16, 17, 18, 20, 24, 32}
	for _, align := range []int64{1, 2, 4, 8, 16} {
		in.Objects = append(in.Objects, inputObject{
			Name:  "aligned-object",
			Align: ptr(align),
			Text:  ByteSlice{0xaa},
			Data:  ByteSlice{0xdd},
		})
	}
	_, report, err := link(marshalInput(t, in))
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range wantOffsets {
		if got := int(report.Layout[i].ImageOffset); got != want {
			t.Fatalf("chunk %d offset = 0x%x, want 0x%x", i, got, want)
		}
	}
}

func TestLocalSymbolShadowsGlobal(t *testing.T) {
	in := inputFile{Objects: []inputObject{
		{
			Name: "local-owner",
			Text: ByteSlice{1, 2, 3, 4, 5, 6},
			Symbols: []inputSymbol{
				{Name: "G", Binding: "local", Section: "text", Value: 0},
			},
			Relocations: []inputReloc{
				{Section: "text", Offset: 0, Type: "ABS32", Symbol: "G"},
				{Section: "text", Offset: 4, Type: "PCREL16", Symbol: "G"},
			},
		},
		{
			Name: "global-owner",
			Text: ByteSlice{7, 8, 9, 10},
			Symbols: []inputSymbol{
				{Name: "G", Binding: "strong", Section: "text", Value: 0},
			},
			Relocations: []inputReloc{
				{Section: "text", Offset: 0, Type: "ABS32", Symbol: "G"},
			},
		},
	}}
	image, report, err := link(marshalInput(t, in))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("00100000faff06100000")
	if !bytes.Equal(image, want) {
		t.Fatalf("image = %x, want %x", image, want)
	}
	if got := int(report.SymbolAddrs.Global["G"]); got != 0x1006 {
		t.Fatalf("global G = 0x%x, want 0x1006", got)
	}
	if len(report.SymbolAddrs.Local) != 1 || int(report.SymbolAddrs.Local[0].Address) != 0x1000 {
		t.Fatalf("local G evidence wrong: %+v", report.SymbolAddrs.Local)
	}
}

func TestStrongDefinitionBeatsWeakDefinition(t *testing.T) {
	in := inputFile{Objects: []inputObject{
		{
			Name:        "weak-owner",
			Text:        ByteSlice{1, 2, 3, 4},
			Symbols:     []inputSymbol{{Name: "W", Binding: "weak", Section: "text", Value: 0}},
			Relocations: []inputReloc{{Section: "text", Offset: 2, Type: "PCREL16", Symbol: "W"}},
		},
		{
			Name:        "strong-owner",
			Text:        ByteSlice{5, 6, 7, 8},
			Symbols:     []inputSymbol{{Name: "W", Binding: "strong", Section: "text", Value: 0}},
			Relocations: []inputReloc{{Section: "text", Offset: 0, Type: "ABS32", Symbol: "W"}},
		},
	}}
	image, report, err := link(marshalInput(t, in))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		1, 2, 0x00, 0x00, // PCREL from 0x1002 to strong W at 0x1004: delta 0
		0x04, 0x10, 0x00, 0x00, // ABS32 -> 0x1004
	}
	if !bytes.Equal(image, want) {
		t.Fatalf("image = %x, want %x", image, want)
	}
	if int(report.SymbolAddrs.Global["W"]) != 0x1004 {
		t.Fatalf("W resolved to 0x%x, want 0x1004", report.SymbolAddrs.Global["W"])
	}
	var weak, strong SymbolReport
	for _, s := range report.Symbols {
		if s.Name != "W" {
			continue
		}
		if s.Binding == "weak" {
			weak = s
		} else {
			strong = s
		}
	}
	if !strong.Selected || weak.Selected || int(weak.Address) != 0x1000 || int(strong.Address) != 0x1004 {
		t.Fatalf("weak/strong reports wrong: weak=%+v strong=%+v", weak, strong)
	}
}

func TestFirstWeakWinsWhenNoStrongExists(t *testing.T) {
	in := inputFile{Objects: []inputObject{
		{Text: ByteSlice{1}, Symbols: []inputSymbol{{Name: "W", Binding: "weak", Section: "text", Value: 0}}},
		{Text: ByteSlice{2}, Symbols: []inputSymbol{{Name: "W", Binding: "weak", Section: "text", Value: 0}}},
	}}
	_, report, err := link(marshalInput(t, in))
	if err != nil {
		t.Fatal(err)
	}
	if addr := int(report.SymbolAddrs.Global["W"]); addr != 0x1000 {
		t.Fatalf("first weak W = 0x%x, want 0x1000", addr)
	}
}

func TestLinkErrorsProduceNoImage(t *testing.T) {
	tests := []struct {
		name string
		in   inputFile
		want string
	}{
		{
			name: "unresolved symbol",
			in: inputFile{Objects: []inputObject{{
				Text:        ByteSlice{1, 2, 3, 4},
				Relocations: []inputReloc{{Section: "text", Offset: 0, Type: "ABS32", Symbol: "missing"}},
			}}},
			want: "unresolved symbol",
		},
		{
			name: "two strong definitions",
			in: inputFile{Objects: []inputObject{
				{Text: ByteSlice{1}, Symbols: []inputSymbol{{Name: "X", Binding: "strong", Section: "text", Value: 0}}},
				{Text: ByteSlice{2}, Symbols: []inputSymbol{{Name: "X", Binding: "strong", Section: "text", Value: 0}}},
			}},
			want: "2 strong definitions",
		},
		{
			name: "patch out of bounds",
			in: inputFile{Objects: []inputObject{{
				Text:        ByteSlice{1},
				Relocations: []inputReloc{{Section: "text", Offset: 0, Type: "ABS32", Symbol: "X"}},
				Symbols:     []inputSymbol{{Name: "X", Binding: "strong", Section: "data", Value: 0}},
			}}},
			want: "outside .text",
		},
		{
			name: "invalid alignment",
			in: inputFile{Objects: []inputObject{{
				Align: ptr[int64](32),
				Text:  ByteSlice{1},
			}}},
			want: "alignment 32",
		},
		{
			name: "ABS32 overflow",
			in: inputFile{Objects: []inputObject{{
				Text: ByteSlice{1, 2, 3, 4},
				Symbols: []inputSymbol{
					{Name: "X", Binding: "strong", Section: "text", Value: 0},
				},
				Relocations: []inputReloc{{Section: "text", Offset: 0, Type: "ABS32", Symbol: "X", Addend: 0xffffffff}},
			}}},
			want: "ABS32 target",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			image, report, err := link(marshalInput(t, tt.in))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
			if image != nil || report.ImageSize != 0 || len(report.Relocations) != 0 {
				t.Fatalf("failed link produced output: image=%v report=%+v", image, report)
			}
		})
	}
}

func TestPCREL16Overflow(t *testing.T) {
	// Patch ends at address 0x1004; target is at 0x9004. The displacement is
	// exactly 0x8000, which does not fit in signed int16.
	text := make(ByteSlice, 0x8004)
	in := inputFile{Objects: []inputObject{{
		Text: text,
		Symbols: []inputSymbol{
			{Name: "end", Binding: "strong", Section: "text", Value: int64(len(text))},
		},
		Relocations: []inputReloc{
			{Section: "text", Offset: 2, Type: "PCREL16", Symbol: "end"},
		},
	}}}
	image, _, err := link(marshalInput(t, in))
	if err == nil || !strings.Contains(err.Error(), "PCREL16 delta") {
		t.Fatalf("error = %v, want PCREL16 overflow", err)
	}
	if image != nil {
		t.Fatalf("overflow produced an image")
	}
}

func TestCommandWritesImageAndJSONReport(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.json")
	imagePath := filepath.Join(dir, "image.bin")
	reportPath := filepath.Join(dir, "report.json")
	in := inputFile{Objects: []inputObject{{
		Text: ByteSlice{1, 2, 3, 4},
		Symbols: []inputSymbol{
			{Name: "X", Binding: "strong", Section: "text", Value: 0},
		},
		Relocations: []inputReloc{
			{Section: "text", Offset: 0, Type: "ABS32", Symbol: "X"},
		},
	}}}
	if err := os.WriteFile(inputPath, marshalInput(t, in), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-o", imagePath, "-report", reportPath, "-image-hex", inputPath}, nil, nil); err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, 0x10, 0, 0}; !bytes.Equal(image, want) {
		t.Fatalf("image = %x, want %x", image, want)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.ImageHex != hex.EncodeToString(image) || int(report.SymbolAddrs.Global["X"]) != 0x1000 {
		t.Fatalf("report did not match image: %+v", report)
	}
}

func TestCommandErrorLeavesExistingOutputUntouched(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.json")
	imagePath := filepath.Join(dir, "image.bin")
	marker := []byte("existing complete image")
	if err := os.WriteFile(imagePath, marker, 0o644); err != nil {
		t.Fatal(err)
	}
	in := inputFile{Objects: []inputObject{{
		Text:        ByteSlice{1},
		Relocations: []inputReloc{{Section: "text", Offset: 0, Type: "ABS32", Symbol: "missing"}},
	}}}
	if err := os.WriteFile(inputPath, marshalInput(t, in), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	err := run([]string{"-o", imagePath, inputPath}, nil, &stderr)
	if err == nil {
		t.Fatal("expected link failure")
	}
	got, readErr := os.ReadFile(imagePath)
	if readErr != nil || !bytes.Equal(got, marker) {
		t.Fatalf("existing output changed: got %q err=%v", got, readErr)
	}
}
