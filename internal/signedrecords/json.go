package signedrecords

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"
)

const (
	MaxJSONDepth  = 32
	MaxJSONValues = 65536
)

var jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()
var rawMessageType = reflect.TypeFor[json.RawMessage]()

// DecodeJSON decodes a bounded record without duplicate members, unknown struct
// fields, case aliases, trailing documents or malformed Unicode. Missing required
// fields and domain semantics remain the caller's responsibility. The destination
// changes only after successful decoding. Anonymous field promotion is unsupported;
// use explicit JSON field names for embedded structures.
func DecodeJSON(raw []byte, dst any, maxBytes int) error {
	value := reflect.ValueOf(dst)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() {
		return fmt.Errorf("%w: JSON destination must be a nonnil pointer", ErrInvalid)
	}
	if maxBytes <= 0 || maxBytes > MaxEnvelopeBytes || len(raw) > maxBytes {
		return fmt.Errorf("%w: JSON byte budget", ErrLimit)
	}
	snapshot := bytes.Clone(raw)
	parsed, err := parseJSON(snapshot, maxBytes)
	if err != nil {
		return err
	}
	if err := checkFields(parsed, value.Type().Elem(), 0); err != nil {
		return err
	}
	decoded := reflect.New(value.Type().Elem())
	decoder := json.NewDecoder(bytes.NewReader(snapshot))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(decoded.Interface()); err != nil {
		return fmt.Errorf("%w: JSON record does not match destination schema", ErrInvalid)
	}
	value.Elem().Set(decoded.Elem())
	return nil
}

func parseJSON(raw []byte, maxBytes int) (any, error) {
	if maxBytes <= 0 || maxBytes > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: invalid JSON byte budget", ErrLimit)
	}
	if len(raw) > maxBytes {
		return nil, fmt.Errorf("%w: JSON input exceeds byte budget", ErrLimit)
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: JSON must be nonempty valid UTF-8", ErrInvalid)
	}
	if err := unicodeEscapes(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	count := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		count++
		if depth > MaxJSONDepth || count > MaxJSONValues {
			return nil, fmt.Errorf("%w: JSON nesting or value count", ErrLimit)
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: malformed JSON", ErrInvalid)
		}
		delimiter, container := token.(json.Delim)
		if !container {
			return token, nil
		}
		switch delimiter {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				count++
				if count > MaxJSONValues {
					return nil, fmt.Errorf("%w: JSON member count", ErrLimit)
				}
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, fmt.Errorf("%w: malformed JSON object", ErrInvalid)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("%w: JSON object key", ErrInvalid)
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("%w: duplicate JSON member", ErrInvalid)
				}
				item, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				object[key] = item
			}
			close, err := decoder.Token()
			if err != nil || close != json.Delim('}') {
				return nil, fmt.Errorf("%w: malformed JSON object", ErrInvalid)
			}
			return object, nil
		case '[':
			var array []any
			for decoder.More() {
				item, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			close, err := decoder.Token()
			if err != nil || close != json.Delim(']') {
				return nil, fmt.Errorf("%w: malformed JSON array", ErrInvalid)
			}
			return array, nil
		default:
			return nil, fmt.Errorf("%w: unexpected JSON delimiter", ErrInvalid)
		}
	}
	value, err := read(1)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw[decoder.InputOffset():])) != 0 {
		return nil, fmt.Errorf("%w: trailing JSON content", ErrInvalid)
	}
	return value, nil
}

// encoding/json intentionally replaces invalid surrogate escapes. Reject them
// before tokenization instead of allowing two different encodings to collapse.
func unicodeEscapes(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		if !inString {
			if raw[i] == '"' {
				inString = true
			}
			continue
		}
		if raw[i] == '"' {
			inString = false
			continue
		}
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return fmt.Errorf("%w: incomplete JSON escape", ErrInvalid)
		}
		if raw[i] != 'u' {
			continue
		}
		code, ok := hex4(raw, i+1)
		if !ok {
			return fmt.Errorf("%w: invalid Unicode escape", ErrInvalid)
		}
		end := i + 5
		switch {
		case code >= 0xd800 && code <= 0xdbff:
			if end+6 > len(raw) || raw[end] != '\\' || raw[end+1] != 'u' {
				return fmt.Errorf("%w: unpaired Unicode surrogate", ErrInvalid)
			}
			low, ok := hex4(raw, end+2)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return fmt.Errorf("%w: unpaired Unicode surrogate", ErrInvalid)
			}
			i = end + 5
		case code >= 0xdc00 && code <= 0xdfff:
			return fmt.Errorf("%w: unpaired Unicode surrogate", ErrInvalid)
		default:
			i = end - 1
		}
	}
	return nil
}
func hex4(raw []byte, start int) (uint16, bool) {
	if start+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for _, character := range raw[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value += uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value += uint16(character - 'a' + 10)
		case character >= 'A' && character <= 'F':
			value += uint16(character - 'A' + 10)
		default:
			return 0, false
		}
	}
	return value, true
}

func checkFields(value any, target reflect.Type, depth int) error {
	if depth > MaxJSONDepth {
		return fmt.Errorf("%w: destination nesting", ErrLimit)
	}
	for pointers := 0; target.Kind() == reflect.Pointer; pointers++ {
		if pointers >= MaxJSONDepth {
			return fmt.Errorf("%w: destination pointer nesting", ErrLimit)
		}
		target = target.Elem()
	}
	if target.Kind() == reflect.Array && value == nil {
		return fmt.Errorf("%w: null fixed-size array", ErrInvalid)
	}
	if target == rawMessageType || target.Kind() == reflect.Interface {
		return nil
	}
	_, object := value.(map[string]any)
	_, array := value.([]any)
	if reflect.PointerTo(target).Implements(jsonUnmarshalerType) {
		if object || array {
			return fmt.Errorf("%w: custom container JSON decoders are unsupported", ErrInvalid)
		}
		return nil
	}
	switch node := value.(type) {
	case map[string]any:
		switch target.Kind() {
		case reflect.Struct:
			fields := make(map[string]reflect.Type)
			for i := 0; i < target.NumField(); i++ {
				field := target.Field(i)
				if field.PkgPath != "" {
					continue
				}
				name := field.Tag.Get("json")
				if comma := strings.IndexByte(name, ','); comma >= 0 {
					name = name[:comma]
				}
				if name == "-" {
					continue
				}
				if name == "" {
					if field.Anonymous {
						return fmt.Errorf("%w: embedded fields require explicit JSON names", ErrInvalid)
					}
					name = field.Name
				}
				if _, exists := fields[name]; exists {
					return fmt.Errorf("%w: ambiguous destination JSON fields", ErrInvalid)
				}
				fields[name] = field.Type
			}
			for name, child := range node {
				field, exists := fields[name]
				if !exists {
					return fmt.Errorf("%w: unknown or incorrectly cased JSON field", ErrInvalid)
				}
				if err := checkFields(child, field, depth+1); err != nil {
					return err
				}
			}
		case reflect.Map:
			if target.Key() != reflect.TypeFor[string]() {
				return fmt.Errorf("%w: JSON maps require string keys", ErrInvalid)
			}
			for _, child := range node {
				if err := checkFields(child, target.Elem(), depth+1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("%w: JSON object does not match destination", ErrInvalid)
		}
	case []any:
		if target.Kind() == reflect.Array && len(node) != target.Len() {
			return fmt.Errorf("%w: fixed-size array length mismatch", ErrInvalid)
		}
		if target.Kind() != reflect.Array && target.Kind() != reflect.Slice {
			return fmt.Errorf("%w: JSON array does not match destination", ErrInvalid)
		}
		for _, child := range node {
			if err := checkFields(child, target.Elem(), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
