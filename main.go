package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

var (
	debug      bool
	excludeDir string
)

func init() {
	flag.StringVar(&excludeDir, "exclude", "vendor,node_modules,venv,env,__pycache__,tests,test,third_party,build", "comma-separated list of directories to exclude from language detection")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <path-to-repo>\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()
	if debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetOutput(new(strings.Builder))
	}
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	repo := flag.Arg(0)

	for _, b := range []string{"cloc", "semgrep", "docker"} {
		if _, err := exec.LookPath(b); err != nil {
			fmt.Printf("required binary %q not found in PATH\n", b)
			os.Exit(1)
		}
	}

	languages, err := detectLanguages(repo, excludeDir)
	if err != nil {
		fmt.Println("cloc error:", err)
	}
	frameworks := detectFrameworks(repo, languages)
	buildsystems := detectBuildSystems(repo)

	fmt.Println("Languages:")
	for _, l := range languages {
		fmt.Printf("- %s\n", l)
	}
	fmt.Println("Frameworks:")
	for lang, fws := range frameworks {
		if len(fws) == 0 {
			continue
		}
		fmt.Printf("%s: %v\n", lang, fws)
	}
	fmt.Println("Build Systems:")
	for lang, bs := range buildsystems {
		if len(bs) == 0 {
			continue
		}
		fmt.Printf("%s: %v\n", lang, bs)
	}

	findings := runAnalyses(repo, languages)
	if len(findings) > 0 {
		fmt.Println("Files with most findings:")
		rankAndPrint(findings)
	}
}

func detectLanguages(repo, exclude string) ([]string, error) {
	args := []string{"--json"}
	if exclude != "" {
		args = append(args, "--exclude-dir="+exclude)
	}
	args = append(args, repo)
	log.Printf("running cloc %v", args)
	cmd := exec.Command("cloc", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, err
	}
	langs := []string{}
	for k := range data {
		if k == "header" || k == "SUM" {
			continue
		}
		langs = append(langs, k)
	}
	return langs, nil
}

func detectFrameworks(repo string, languages []string) map[string][]string {
	result := make(map[string][]string)
	for _, lang := range languages {
		switch lang {
		case "Python":
			if runSemgrep(repo, "python", "import django") || runSemgrep(repo, "python", "from django import $X") {
				result["Python"] = append(result["Python"], "Django")
			}
			if runSemgrep(repo, "python", "import flask") || runSemgrep(repo, "python", "from flask import $X") {
				result["Python"] = append(result["Python"], "Flask")
			}
		case "JavaScript":
			if runSemgrep(repo, "js", "import express") || runSemgrep(repo, "js", "require('express')") {
				result["JavaScript"] = append(result["JavaScript"], "Express")
			}
			if runSemgrep(repo, "js", "import next") || runSemgrep(repo, "js", "require('next')") {
				result["JavaScript"] = append(result["JavaScript"], "Next.js")
			}
		case "Go":
			if runSemgrep(repo, "go", "import \"github.com/gin-gonic/gin\"") {
				result["Go"] = append(result["Go"], "Gin")
			}
			if runSemgrep(repo, "go", "import \"github.com/labstack/echo\"") {
				result["Go"] = append(result["Go"], "Echo")
			}
		case "Rust":
			cargo := filepath.Join(repo, "Cargo.toml")
			if hasInFile(cargo, "rocket") {
				result["Rust"] = append(result["Rust"], "Rocket")
			}
			if hasInFile(cargo, "actix-web") {
				result["Rust"] = append(result["Rust"], "Actix")
			}
		}
	}
	return result
}

func detectBuildSystems(repo string) map[string][]string {
	result := make(map[string][]string)
	if exists(filepath.Join(repo, "requirements.txt")) {
		result["Python"] = append(result["Python"], "pip")
	}
	if exists(filepath.Join(repo, "pyproject.toml")) {
		result["Python"] = append(result["Python"], "poetry")
	}
	if exists(filepath.Join(repo, "package.json")) {
		result["JavaScript"] = append(result["JavaScript"], "npm")
	}
	if exists(filepath.Join(repo, "yarn.lock")) {
		result["JavaScript"] = append(result["JavaScript"], "yarn")
	}
	if exists(filepath.Join(repo, "go.mod")) {
		result["Go"] = append(result["Go"], "go modules")
	}
	if exists(filepath.Join(repo, "Gopkg.toml")) {
		result["Go"] = append(result["Go"], "dep")
	}
	if exists(filepath.Join(repo, "Cargo.toml")) {
		result["Rust"] = append(result["Rust"], "cargo")
	}
	return result
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func hasInFile(p, substr string) bool {
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), substr)
}

func runSemgrep(repo, lang, pattern string) bool {
	cmd := exec.Command("semgrep", "--json", "--lang", lang, "-e", pattern, repo)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 && exitErr.ExitCode() != 0 {
				return false
			}
		} else {
			return false
		}
	}
	var data struct {
		Results []struct{} `json:"results"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		return false
	}
	return len(data.Results) > 0
}

func runAnalyses(repo string, languages []string) map[string]int {
	findings := map[string]int{}
	seen := map[string]bool{}
	for _, lang := range languages {
		if seen[lang] {
			continue
		}
		seen[lang] = true
		var (
			m   map[string]int
			err error
		)
		switch lang {
		case "Go":
			m, err = runGosec(repo)
		default:
			m, err = runSemgrepDocker(repo)
		}
		if err != nil {
			log.Printf("analysis for %s failed: %v", lang, err)
			continue
		}
		mergeMaps(findings, m)
	}
	return findings
}

func runSemgrepDocker(repo string) (map[string]int, error) {
	cmd := exec.Command("docker", "run", "--rm", "-v", repo+":/src", "returntocorp/semgrep", "semgrep", "--config=auto", "--json", "/src")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var data struct {
		Results []struct {
			Path string `json:"path"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, r := range data.Results {
		p := strings.TrimPrefix(r.Path, "/src/")
		counts[p]++
	}
	return counts, nil
}

func runGosec(repo string) (map[string]int, error) {
	cmd := exec.Command("docker", "run", "--rm", "-v", repo+":/src", "securego/gosec", "-fmt=json", "/src/...")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var data struct {
		Issues []struct {
			File string `json:"file"`
		} `json:"Issues"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, i := range data.Issues {
		p := strings.TrimPrefix(i.File, "/src/")
		counts[p]++
	}
	return counts, nil
}

func mergeMaps(dst, src map[string]int) {
	for k, v := range src {
		dst[k] += v
	}
}

func rankAndPrint(m map[string]int) {
	type kv struct {
		File  string
		Count int
	}
	list := make([]kv, 0, len(m))
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Count > list[j].Count })
	for _, kv := range list {
		fmt.Printf("%s: %d\n", kv.File, kv.Count)
	}
}
