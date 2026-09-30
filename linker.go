package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
)

const (
	baseAddress = 0x1000
	sectionText = ".text"
	sectionData = ".data"

	scopeLocal  = "local"
	scopeGlobal = "global"

	bindingStrong = "strong"
	bindingWeak   = "weak"
)

// ByteSlice accepts either a base64 string or a JSON array of byte values.
type ByteSlice []byte

func (b *ByteSlice) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*b = nil
		return nil
	}

	if len(data) > 0 && data[0] == '"' {
		var encoded string
		if err := json.Unmarshal(data, &encoded); err != nil {
			return err
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("decode base64 bytes: %w", err)
		}
		*b = decoded
		return nil
	}

	var values []json.Number
	if err := json.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("bytes must be a base64 string or an array of byte values: %w", err)
	}

	out := make(ByteSlice, len(values))
	for i, value := range values {
		n, err := value.Int64()
		if err != nil || n < 0 || n > 255 {
			return fmt.Errorf("byte at index %d is not an integer in [0,255]", i)
		}
		out[i] = byte(n)
	}
	*b = out
	return nil
}

type Section struct {
	Bytes ByteSlice `json:"bytes"`
	Align int       `json:"align"`
}

type Symbol struct {
	Name    string `json:"name"`
	Section string `json:"section"`
	Offset  int    `json:"offset"`
	Scope   string `json:"scope"`
	Binding string `json:"binding"`
}

type Relocation struct {
	Type    string `json:"type"`
	Section string `json:"section"`
	Offset  int    `json:"offset"`
	Symbol  string `json:"symbol"`
	Addend  *int64 `json:"addend"`
}

type Object struct {
	Name        string       `json:"name"`
	Text        *Section     `json:"text"`
	Data        *Section     `json:"data"`
	Symbols     []Symbol     `json:"symbols"`
	Relocations []Relocation `json:"relocations"`
}

type Report struct {
	ImageBase    int                `json:"image_base"`
	ImageBaseHex string             `json:"image_base_hex"`
	ImageBase64  string             `json:"image_base64"`
	ImageSize    int                `json:"image_size"`
	Sections     []SectionReport    `json:"sections"`
	Symbols      []SymbolReport     `json:"symbols"`
	Relocations  []RelocationReport `json:"relocations"`
}

type SectionReport struct {
	ObjectIndex int    `json:"object_index"`
	ObjectName  string `json:"object_name"`
	Section     string `json:"section"`
	Address     int    `json:"address"`
	AddressHex  string `json:"address_hex"`
	Size        int    `json:"size"`
	Alignment   int    `json:"alignment"`
	BytesHex    string `json:"bytes_hex"`
}

type SymbolReport struct {
	ObjectIndex int    `json:"object_index"`
	ObjectName  string `json:"object_name"`
	Name        string `json:"name"`
	Scope       string `json:"scope"`
	Binding     string `json:"binding,omitempty"`
	Section     string `json:"section"`
	Offset      int    `json:"offset"`
	Address     int    `json:"address"`
	AddressHex  string `json:"address_hex"`
	Selected    bool   `json:"selected"`
}

type RelocationReport struct {
	ObjectIndex          int    `json:"object_index"`
	ObjectName           string `json:"object_name"`
	Index                int    `json:"relocation_index"`
	Type                 string `json:"type"`
	Section              string `json:"section"`
	Offset               int    `json:"offset"`
	PatchStart           int    `json:"patch_start"`
	PatchEnd             int    `json:"patch_end"`
	PatchStartHex        string `json:"patch_start_hex"`
	PatchEndHex          string `json:"patch_end_hex"`
	Symbol               string `json:"symbol"`
	SymbolScope          string `json:"symbol_scope"`
	SymbolBinding        string `json:"symbol_binding,omitempty"`
	DefinedInObjectIndex int    `json:"defined_in_object_index"`
	DefinedInObjectName  string `json:"defined_in_object_name"`
	TargetAddress        int    `json:"target_address"`
	TargetAddressHex     string `json:"target_address_hex"`
	Addend               int64  `json:"addend"`
	ComputedValue        int64  `json:"computed_value"`
	BytesBefore          string `json:"bytes_before"`
	BytesAfter           string `json:"bytes_after"`
}

type sectionKey struct {
	object  int
	section string
}

type placedSection struct {
	object    int
	name      string
	input     *Section
	address   int
	alignment int
}

type symbolDefinition struct {
	name    string
	object  int
	section string
	offset  int
	address int
	scope   string
	binding string
}

type plannedPatch struct {
	imageOffset int
	bytes       []byte
	evidence    RelocationReport
}

func Link(objects []Object) (*Report, error) {
	// 第一阶段：只计算布局，不修改任何字节。
	placements := make([]placedSection, 0, len(objects)*2)
	placementByKey := make(map[sectionKey]int)
	cursor := baseAddress

	for _, sectionName := range []string{sectionText, sectionData} {
		for i := range objects {
			var section *Section
			if sectionName == sectionText {
				section = objects[i].Text
			} else {
				section = objects[i].Data
			}
			if section == nil {
				continue
			}

			alignment := section.Align
			if alignment == 0 {
				alignment = 1
			}
			if !validAlignment(alignment) {
				return nil, fmt.Errorf("object %d (%s): %s alignment %d is not one of 1, 2, 4, 8, or 16",
					i, objectName(objects, i), sectionName, section.Align)
			}

			address := alignUp(cursor, alignment)
			if len(section.Bytes) > math.MaxInt-address {
				return nil, fmt.Errorf("object %d (%s): %s is too large", i, objectName(objects, i), sectionName)
			}

			key := sectionKey{object: i, section: sectionName}
			placementByKey[key] = len(placements)
			placements = append(placements, placedSection{
				object:    i,
				name:      sectionName,
				input:     section,
				address:   address,
				alignment: alignment,
			})
			cursor = address + len(section.Bytes)
		}
	}

	image := make([]byte, cursor-baseAddress)
	for _, placement := range placements {
		start := placement.address - baseAddress
		copy(image[start:start+len(placement.input.Bytes)], placement.input.Bytes)
	}

	// 第二阶段：建立局部和全局符号表。强符号替换先出现的弱符号；
	// 两个强符号冲突立即报错。
	locals := make(map[int]map[string]symbolDefinition)
	globals := make(map[string]symbolDefinition)
	symbolReports := make([]SymbolReport, 0)

	for i := range objects {
		seenNames := make(map[string]bool)
		for _, symbol := range objects[i].Symbols {
			if symbol.Name == "" {
				return nil, fmt.Errorf("object %d (%s): symbol has an empty name", i, objectName(objects, i))
			}
			if seenNames[symbol.Name] {
				return nil, fmt.Errorf("object %d (%s): duplicate symbol name %q", i, objectName(objects, i), symbol.Name)
			}
			seenNames[symbol.Name] = true

			key := sectionKey{object: i, section: symbol.Section}
			placementIndex, ok := placementByKey[key]
			if !ok {
				return nil, fmt.Errorf("object %d (%s): symbol %q: section %q is not present",
					i, objectName(objects, i), symbol.Name, symbol.Section)
			}
			placement := placements[placementIndex]
			size := len(placement.input.Bytes)
			if symbol.Offset < 0 || symbol.Offset > size {
				return nil, fmt.Errorf("object %d (%s): symbol %q: offset %d is outside %s (size %d)",
					i, objectName(objects, i), symbol.Name, symbol.Offset, symbol.Section, size)
			}

			scope := symbol.Scope
			if scope == "" {
				scope = scopeGlobal
			}
			if scope != scopeLocal && scope != scopeGlobal {
				return nil, fmt.Errorf("object %d (%s): symbol %q: unknown scope %q",
					i, objectName(objects, i), symbol.Name, symbol.Scope)
			}

			binding := symbol.Binding
			if scope == scopeLocal {
				if binding != "" {
					return nil, fmt.Errorf("object %d (%s): local symbol %q must not set binding",
						i, objectName(objects, i), symbol.Name)
				}
			} else {
				if binding == "" {
					binding = bindingStrong
				}
				if binding != bindingStrong && binding != bindingWeak {
					return nil, fmt.Errorf("object %d (%s): global symbol %q: unknown binding %q",
						i, objectName(objects, i), symbol.Name, symbol.Binding)
				}
			}

			definition := symbolDefinition{
				name:    symbol.Name,
				object:  i,
				section: symbol.Section,
				offset:  symbol.Offset,
				address: placement.address + symbol.Offset,
				scope:   scope,
				binding: binding,
			}
			symbolReports = append(symbolReports, SymbolReport{
				ObjectIndex: i,
				ObjectName:  objects[i].Name,
				Name:        symbol.Name,
				Scope:       scope,
				Binding:     binding,
				Section:     symbol.Section,
				Offset:      symbol.Offset,
				Address:     definition.address,
				AddressHex:  hexAddress(definition.address),
			})

			if scope == scopeLocal {
				if locals[i] == nil {
					locals[i] = make(map[string]symbolDefinition)
				}
				locals[i][symbol.Name] = definition
				continue
			}

			if existing, ok := globals[symbol.Name]; ok {
				if existing.binding == bindingStrong && binding == bindingStrong {
					return nil, fmt.Errorf("duplicate strong global symbol %q in object %d (%s) and object %d (%s)",
						symbol.Name, existing.object, objects[existing.object].Name, i, objects[i].Name)
				}
				if existing.binding == bindingWeak && binding == bindingStrong {
					globals[symbol.Name] = definition
				}
				// strong + weak: keep the strong one; weak + weak: keep first.
			} else {
				globals[symbol.Name] = definition
			}
		}
	}

	for i := range symbolReports {
		report := &symbolReports[i]
		if report.Scope == scopeLocal {
			report.Selected = true
			continue
		}
		chosen := globals[report.Name]
		report.Selected = chosen.object == report.ObjectIndex
	}

	// 第三阶段：验证并计算所有重定位，但仍不写入。
	patches := make([]plannedPatch, 0)
	for objectIndex := range objects {
		for relocationIndex, relocation := range objects[objectIndex].Relocations {
			prefix := fmt.Sprintf("object %d (%s): relocation %d",
				objectIndex, objectName(objects, objectIndex), relocationIndex)

			placementIndex, ok := placementByKey[sectionKey{object: objectIndex, section: relocation.Section}]
			if !ok {
				return nil, fmt.Errorf("%s: section %q is not present", prefix, relocation.Section)
			}
			placement := placements[placementIndex]
			sectionSize := len(placement.input.Bytes)

			patchSize := 0
			switch relocation.Type {
			case "ABS32":
				patchSize = 4
			case "PCREL16":
				patchSize = 2
			default:
				return nil, fmt.Errorf("%s: unknown relocation type %q", prefix, relocation.Type)
			}

			if relocation.Offset < 0 || relocation.Offset > sectionSize || relocation.Offset+patchSize > sectionSize {
				return nil, fmt.Errorf("%s: %s patch at offset %d does not fit in %s (size %d)",
					prefix, relocation.Type, relocation.Offset, relocation.Section, sectionSize)
			}

			target, ok := locals[objectIndex][relocation.Symbol]
			if !ok {
				target, ok = globals[relocation.Symbol]
				if !ok {
					return nil, fmt.Errorf("%s: unresolved symbol %q", prefix, relocation.Symbol)
				}
			}

			addend := int64(0)
			if relocation.Addend != nil {
				addend = *relocation.Addend
			}
			patchStart := placement.address + relocation.Offset
			patchEnd := patchStart + patchSize
			imageOffset := patchStart - baseAddress
			bytesBefore := hex.EncodeToString(image[imageOffset : imageOffset+patchSize])

			evidence := RelocationReport{
				ObjectIndex:          objectIndex,
				ObjectName:           objects[objectIndex].Name,
				Index:                relocationIndex,
				Type:                 relocation.Type,
				Section:              relocation.Section,
				Offset:               relocation.Offset,
				PatchStart:           patchStart,
				PatchEnd:             patchEnd,
				PatchStartHex:        hexAddress(patchStart),
				PatchEndHex:          hexAddress(patchEnd),
				Symbol:               relocation.Symbol,
				SymbolScope:          target.scope,
				SymbolBinding:        target.binding,
				DefinedInObjectIndex: target.object,
				DefinedInObjectName:  objects[target.object].Name,
				TargetAddress:        target.address,
				TargetAddressHex:     hexAddress(target.address),
				Addend:               addend,
				BytesBefore:          bytesBefore,
			}

			var patchBytes []byte
			switch relocation.Type {
			case "ABS32":
				value, ok := addInt64(int64(target.address), addend)
				if !ok || value < 0 || value > math.MaxUint32 {
					return nil, fmt.Errorf("%s: ABS32 value %d does not fit in uint32", prefix, value)
				}
				patchBytes = []byte{
					byte(value),
					byte(value >> 8),
					byte(value >> 16),
					byte(value >> 24),
				}
				evidence.ComputedValue = value

			case "PCREL16":
				targetPlusAddend, ok := addInt64(int64(target.address), addend)
				if !ok {
					return nil, fmt.Errorf("%s: PCREL16 computation overflows int64", prefix)
				}
				value, ok := subtractInt64(targetPlusAddend, int64(patchEnd))
				if !ok || value < math.MinInt16 || value > math.MaxInt16 {
					return nil, fmt.Errorf("%s: PCREL16 displacement %d does not fit in int16", prefix, targetPlusAddend-int64(patchEnd))
				}
				unsigned := uint16(int16(value))
				patchBytes = []byte{byte(unsigned), byte(unsigned >> 8)}
				evidence.ComputedValue = value
			}

			evidence.BytesAfter = hex.EncodeToString(patchBytes)
			patches = append(patches, plannedPatch{
				imageOffset: imageOffset,
				bytes:       patchBytes,
				evidence:    evidence,
			})
		}
	}

	// 所有输入和计算都已成功，此刻才一次性提交补丁并生成外部输出所需的数据。
	relocationReports := make([]RelocationReport, len(patches))
	for i, patch := range patches {
		copy(image[patch.imageOffset:patch.imageOffset+len(patch.bytes)], patch.bytes)
		relocationReports[i] = patch.evidence
	}

	sectionReports := make([]SectionReport, 0, len(placements))
	for _, placement := range placements {
		start := placement.address - baseAddress
		end := start + len(placement.input.Bytes)
		sectionReports = append(sectionReports, SectionReport{
			ObjectIndex: placement.object,
			ObjectName:  objects[placement.object].Name,
			Section:     placement.name,
			Address:     placement.address,
			AddressHex:  hexAddress(placement.address),
			Size:        len(placement.input.Bytes),
			Alignment:   placement.alignment,
			BytesHex:    hex.EncodeToString(image[start:end]),
		})
	}

	return &Report{
		ImageBase:    baseAddress,
		ImageBaseHex: hexAddress(baseAddress),
		ImageBase64:  base64.StdEncoding.EncodeToString(image),
		ImageSize:    len(image),
		Sections:     sectionReports,
		Symbols:      symbolReports,
		Relocations:  relocationReports,
	}, nil
}

func objectName(objects []Object, index int) string {
	if objects[index].Name != "" {
		return objects[index].Name
	}
	return fmt.Sprintf("object[%d]", index)
}

func validAlignment(alignment int) bool {
	switch alignment {
	case 1, 2, 4, 8, 16:
		return true
	default:
		return false
	}
}

func alignUp(address, alignment int) int {
	return (address + alignment - 1) / alignment * alignment
}

func hexAddress(value int) string {
	return fmt.Sprintf("0x%x", value)
}

func addInt64(a, b int64) (int64, bool) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, false
	}
	if b < 0 && a < math.MinInt64-b {
		return 0, false
	}
	return a + b, true
}

func subtractInt64(a, b int64) (int64, bool) {
	if b < 0 && a > math.MaxInt64+b {
		return 0, false
	}
	if b > 0 && a < math.MinInt64+b {
		return 0, false
	}
	return a - b, true
}

func strictUnmarshalJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != nil {
		return nil // 只有一个 JSON 值。
	}
	return fmt.Errorf("unexpected trailing JSON value %q", string(trailing))
}

// ParseInput accepts one object, an array of objects, or {"objects": [...]}.
func ParseInput(data []byte, defaultName string) ([]Object, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty JSON input")
	}

	var objects []Object
	switch trimmed[0] {
	case '{':
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &fields); err != nil {
			return nil, err
		}
		if raw, ok := fields["objects"]; ok {
			if string(bytes.TrimSpace(raw)) != "null" {
				var wrapper struct {
					Objects []Object `json:"objects"`
				}
				if err := strictUnmarshalJSON(trimmed, &wrapper); err != nil {
					return nil, err
				}
				objects = wrapper.Objects
			}
		} else {
			var object Object
			if err := strictUnmarshalJSON(trimmed, &object); err != nil {
				return nil, err
			}
			objects = []Object{object}
		}
	case '[':
		if err := strictUnmarshalJSON(trimmed, &objects); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("JSON input must be an object or array")
	}

	if len(objects) == 1 && objects[0].Name == "" {
		objects[0].Name = defaultName
	}
	if len(objects) > 1 {
		for i := range objects {
			if objects[i].Name == "" {
				objects[i].Name = fmt.Sprintf("%s#%d", defaultName, i)
			}
		}
	}
	return objects, nil
}
