package common

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"

	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
	"github.com/google/uuid"
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

func RemoveEmptyStrings(items []string) []string {

	r := []string{}

	for _, v := range items {
		if utils.IsEmpty(v) {
			continue
		}
		r = append(r, strings.TrimSpace(v))
	}

	return r
}

func InterfaceListAsStrings(items []interface{}) []string {

	r := []string{}

	for _, v := range items {
		r = append(r, fmt.Sprintf("%v", v))
	}

	return r
}

func GetStringKeys(arr map[string]interface{}) []string {
	var keys []string
	for k := range arr {
		keys = append(keys, k)
	}
	return keys
}

func MergeInterfaceMaps(maps ...map[string]interface{}) map[string]interface{} {

	r := make(map[string]interface{})
	for _, m := range maps {
		for k, v := range m {
			r[k] = v
		}
	}
	return r
}

func IfDef(cond bool, v1, v2 interface{}) interface{} {
	if cond {
		return v1
	}
	return v2
}

func RenderTemplate(tpl *toolsRender.TextTemplate, def string, obj interface{}) (string, error) {

	if tpl == nil {
		return def, nil
	}

	b, err := tpl.RenderObject(obj)
	if err != nil {
		return def, err
	}
	r := strings.TrimSpace(string(b))
	// simplify <no value> => empty string
	return strings.ReplaceAll(r, "<no value>", ""), nil
}

func Render(def string, obj interface{}, observability *Observability) string {

	logger := observability.Logs()
	tpl, err := toolsRender.NewTextTemplate(toolsRender.TemplateOptions{Content: def}, observability)
	if err != nil {
		logger.Error(err)
		return def
	}

	s, err := RenderTemplate(tpl, def, obj)
	if err != nil {
		logger.Error(err)
		return def
	}
	return s
}

func UUID() string {

	uuid := uuid.New()
	return uuid.String()
}

func Schedule(what func(), delay time.Duration) chan bool {
	stop := make(chan bool)

	go func() {
		for {
			what()
			select {
			case <-time.After(delay):
			case <-stop:
				return
			}
		}
	}()

	return stop
}

// template: tenplate-name:17:4: executing ... error calling ...
func TemplateShortError(err error) error {

	if err == nil {
		return nil
	}

	s := err.Error()
	if utils.IsEmpty(s) {
		return err
	}

	executing := ": executing"
	errorCalling := "error calling "

	eIdx := strings.Index(s, executing)
	ecIndx := strings.LastIndex(s, errorCalling)
	if eIdx < 0 || ecIndx < 0 || ecIndx < eIdx {
		return err
	}

	old := s[eIdx : ecIndx+len(errorCalling)]
	if utils.IsEmpty(old) {
		return err
	}

	new := strings.Replace(s, old, " ", 1)
	return errors.New(strings.TrimSpace(new))
}
