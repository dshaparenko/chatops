package common

import (
	"errors"
	"fmt"
	"os"
	"text/template"

	"github.com/devopsext/utils"
	"gopkg.in/yaml.v2"
)

func LoadYaml(config string, obj interface{}) (bool, error) {

	if utils.IsEmpty(config) {
		return false, nil
	}

	raw := ""

	if _, err := os.Stat(config); errors.Is(err, os.ErrNotExist) {
		raw = config
	} else {
		r, err := os.ReadFile(config)
		if err != nil {
			return false, err
		}
		raw = string(r)
	}

	if utils.IsEmpty(raw) {
		return false, nil
	}

	err := yaml.Unmarshal([]byte(raw), obj)
	if err != nil {
		return false, err
	}
	return true, nil
}

func LoadTemplate(name, tmpl string) (*template.Template, error) {

	if utils.IsEmpty(tmpl) {
		return nil, nil
	}

	raw := ""

	if _, err := os.Stat(tmpl); errors.Is(err, os.ErrNotExist) {
		raw = tmpl
	} else {
		r, err := os.ReadFile(tmpl)
		if err != nil {
			return nil, err
		}
		raw = string(r)
	}

	if utils.IsEmpty(raw) {
		return nil, nil
	}

	t, err := template.New(fmt.Sprintf("%s_template", name)).Parse(raw)
	if err != nil {
		return nil, err
	}
	return t, nil
}
