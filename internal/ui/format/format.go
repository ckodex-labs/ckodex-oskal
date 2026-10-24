package format

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"sigs.k8s.io/yaml"
)

// OutputFormat represents the supported CLI rendering formats.
type OutputFormat string

const (
	FormatTable OutputFormat = "table"
	FormatTree  OutputFormat = "tree"
	FormatJSON  OutputFormat = "json"
	FormatYAML  OutputFormat = "yaml"
)

// NormalizeFormat parses and validates the requested output format.
func NormalizeFormat(raw string) (OutputFormat, error) {
	norm := strings.ToLower(strings.TrimSpace(raw))
	if norm == "" {
		return FormatTable, nil
	}
	switch norm {
	case "table", "tbl":
		return FormatTable, nil
	case "tree":
		return FormatTree, nil
	case "json":
		return FormatJSON, nil
	case "yaml", "yml":
		return FormatYAML, nil
	default:
		return "", fmt.Errorf("unsupported output format: %q (supported: table, tree, json, yaml)", raw)
	}
}

// RenderStructured writes data in json or yaml format.
func RenderStructured(w io.Writer, data interface{}, f OutputFormat) error {
	switch f {
	case FormatJSON:
		buf, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		_, err = fmt.Fprintln(w, string(buf))
		return err
	case FormatYAML:
		buf, err := yaml.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML: %w", err)
		}
		_, err = fmt.Fprint(w, string(buf))
		return err
	default:
		return fmt.Errorf("RenderStructured does not support format: %s", f)
	}
}

// TableColumn specifies table header and formatting.
type TableColumn struct {
	Title string
	Width int
}

// RenderTable writes a pure ASCII aligned table.
func RenderTable(w io.Writer, headers []string, rows [][]string) error {
	if len(headers) == 0 {
		return nil
	}

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}

	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header
	var hParts []string
	var sepParts []string
	for i, h := range headers {
		hParts = append(hParts, fmt.Sprintf("%-*s", widths[i], h))
		sepParts = append(sepParts, strings.Repeat("-", widths[i]))
	}
	_, _ = fmt.Fprintln(w, strings.Join(hParts, "   "))
	_, _ = fmt.Fprintln(w, strings.Join(sepParts, "   "))

	// Print rows
	for _, row := range rows {
		var rParts []string
		for i := 0; i < len(headers); i++ {
			val := ""
			if i < len(row) {
				val = row[i]
			}
			rParts = append(rParts, fmt.Sprintf("%-*s", widths[i], val))
		}
		_, _ = fmt.Fprintln(w, strings.Join(rParts, "   "))
	}
	return nil
}

// TreeNode represents a node in a hierarchical ASCII tree.
type TreeNode struct {
	Title    string
	Details  string
	Children []*TreeNode
}

// RenderTree writes an ASCII tree hierarchy (using pure ASCII '+--', '|--', `\--`).
func RenderTree(w io.Writer, root *TreeNode) error {
	if root == nil {
		return nil
	}
	title := root.Title
	if root.Details != "" {
		title = fmt.Sprintf("%s (%s)", title, root.Details)
	}
	_, _ = fmt.Fprintln(w, title)
	renderTreeChildren(w, root.Children, "")
	return nil
}

func renderTreeChildren(w io.Writer, children []*TreeNode, prefix string) {
	for i, child := range children {
		isLast := i == len(children)-1
		connector := "+-- "
		nextPrefix := prefix + "|   "
		if isLast {
			connector = "\\-- "
			nextPrefix = prefix + "    "
		}

		title := child.Title
		if child.Details != "" {
			title = fmt.Sprintf("%s: %s", title, child.Details)
		}
		_, _ = fmt.Fprintf(w, "%s%s%s\n", prefix, connector, title)
		renderTreeChildren(w, child.Children, nextPrefix)
	}
}
