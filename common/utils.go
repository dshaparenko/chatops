package common

import (
	"errors"
	"fmt"
	"io/ioutil"
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
		r, err := ioutil.ReadFile(config)
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
		r, err := ioutil.ReadFile(tmpl)
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

/*func FileTree(dir, pattern string, level, max int) (map[string][]string, error) {

	if !utils.DirExists(dir) {
		return nil, fmt.Errorf("directory %s is not exists", dir)
	}
	r := make(map[string][]string)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
      info.Name()
			fmt.Println(path)
		}
		return nil
	})
	return r, err
}*/
