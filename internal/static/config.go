package static

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"os"
	"strings"
)

func loadContentTypes(root *os.Root) (map[string]string, error) {
	file, err := root.Open("config.json")
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("content config.json: %w", err)
	}
	defer file.Close()
	var config *struct {
		ContentTypes map[string]string `json:"content_types"`
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("content config.json: %w", err)
	}
	if config == nil {
		return nil, fmt.Errorf("content config.json: expected a JSON object")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("content config.json: expected a single JSON object")
	}
	for key, value := range config.ContentTypes {
		if !strings.HasPrefix(key, "/") && !strings.HasPrefix(key, ".") {
			return nil, fmt.Errorf("content config.json: content-type key %q must be a URL path or extension", key)
		}
		if mediaType, _, err := mime.ParseMediaType(value); err != nil || !strings.Contains(mediaType, "/") || strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("content config.json: invalid content type %q for %q", value, key)
		}
	}
	if config.ContentTypes == nil {
		config.ContentTypes = map[string]string{}
	}
	return config.ContentTypes, nil
}
