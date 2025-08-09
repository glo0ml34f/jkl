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
	repo, err := filepath.Abs(repo)
	if err != nil {
		log.Fatalf("failed to resolve path: %v", err)
	}

	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Println("required binary \"docker\" not found in PATH")
		os.Exit(1)
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

	findings, analysisTools := runAnalyses(repo, languages, frameworks)
	depFindings, err := scanDependencies(repo)
	if err != nil {
		log.Printf("dependency scan failed: %v", err)
	}

	if len(findings) > 0 {
		fmt.Println("Files with most findings:")
		rankAndPrint(findings)
	}

	tools := append([]string{"cloc", "osv-scanner"}, analysisTools...)
	if err := writeSARIF(findings, depFindings, "report.sarif"); err != nil {
		log.Printf("failed to write SARIF: %v", err)
	}
	if err := writeMarkdown(languages, frameworks, buildsystems, findings, depFindings, tools, "report.md"); err != nil {
		log.Printf("failed to write markdown: %v", err)
	}
}

func detectLanguages(repo, exclude string) ([]string, error) {
	args := []string{"run", "--rm", "-v", repo + ":/src", "aldanial/cloc", "cloc"}
	if exclude != "" {
		args = append(args, "--exclude-dir="+exclude)
	}
	args = append(args, "--json", "/src")
	cmd := exec.Command("docker", args...)
	out, err := runCommand(cmd)
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
			if runSemgrepPatternDocker(repo, "python", "import django") || runSemgrepPatternDocker(repo, "python", "from django import $X") {
				result["Python"] = append(result["Python"], "Django")
			}
			if runSemgrepPatternDocker(repo, "python", "import flask") || runSemgrepPatternDocker(repo, "python", "from flask import $X") {
				result["Python"] = append(result["Python"], "Flask")
			}
		case "JavaScript":
			if runSemgrepPatternDocker(repo, "js", "import express") || runSemgrepPatternDocker(repo, "js", "require('express')") {
				result["JavaScript"] = append(result["JavaScript"], "Express")
			}
			if runSemgrepPatternDocker(repo, "js", "import next") || runSemgrepPatternDocker(repo, "js", "require('next')") {
				result["JavaScript"] = append(result["JavaScript"], "Next.js")
			}
		case "Go":
			if runSemgrepPatternDocker(repo, "go", "import \"github.com/gin-gonic/gin\"") {
				result["Go"] = append(result["Go"], "Gin")
			}
			if runSemgrepPatternDocker(repo, "go", "import \"github.com/labstack/echo\"") {
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

func runCommand(cmd *exec.Cmd, allowedExitCodes ...int) ([]byte, error) {
	log.Printf("running: %s", strings.Join(cmd.Args, " "))
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			allow := len(allowedExitCodes) == 0
			for _, c := range allowedExitCodes {
				if code == c {
					allow = true
					break
				}
			}
			if !allow {
				return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
			}
		} else {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return out, nil
}

func runSemgrepPatternDocker(repo, lang, pattern string) bool {
	args := []string{"run", "--rm", "-v", repo + ":/src", "returntocorp/semgrep", "--json", "--lang", lang, "-e", pattern, "/src"}
	cmd := exec.Command("docker", args...)
	out, err := runCommand(cmd, 0, 1)
	if err != nil {
		return false
	}
	var data struct {
		Results []struct{} `json:"results"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		return false
	}
	return len(data.Results) > 0
}

func runAnalyses(repo string, languages []string, frameworks map[string][]string) (map[string]int, []string) {
	findings := map[string]int{}
	seen := map[string]bool{}
	tools := map[string]bool{}
	for _, lang := range languages {
		if lang == "Text" {
			continue
		}
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
			if err == nil {
				tools["gosec"] = true
			}
		default:
			m, err = runSemgrepDocker(repo, "")
			if err == nil {
				tools["semgrep"] = true
			}
		}
		if err != nil {
			log.Printf("analysis for %s failed: %v", lang, err)
			continue
		}
		mergeMaps(findings, m)
		for _, fw := range frameworks[lang] {
			if rule := frameworkRule(fw); rule != "" {
				fm, err := runSemgrepDocker(repo, rule)
				if err != nil {
					log.Printf("framework scan %s failed: %v", fw, err)
					continue
				}
				tools["semgrep"] = true
				mergeMaps(findings, fm)
			}
		}
	}
	toolList := []string{}
	for t := range tools {
		toolList = append(toolList, t)
	}
	return findings, toolList
}

func runSemgrepDocker(repo, config string) (map[string]int, error) {
	args := []string{"run", "--rm", "-v", repo + ":/src", "returntocorp/semgrep", "semgrep", "scan", "--json", "-q"}
	if config != "" {
		args = append(args, "--config="+config)
	} else {
		args = append(args, "--config=auto")
	}
	args = append(args, "/src")
	cmd := exec.Command("docker", args...)
	out, err := runCommand(cmd, 0, 1)
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
	out, err := runCommand(cmd, 0, 1)
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

func scanDependencies(repo string) (map[string]int, error) {
	cmd := exec.Command("docker", "run", "--rm", "-v", repo+":/src", "ghcr.io/google/osv-scanner:latest", "--format", "json", "--call-analysis", "-r", "/src")
	out, err := runCommand(cmd, 0, 1)
	if err != nil {
		return nil, err
	}
	var data struct {
		Results []struct {
			Source          string     `json:"source"`
			Vulnerabilities []struct{} `json:"vulnerabilities"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, r := range data.Results {
		p := strings.TrimPrefix(r.Source, "/src/")
		counts[p] = len(r.Vulnerabilities)
	}
	return counts, nil
}

func frameworkRule(f string) string {
	switch strings.ToLower(f) {
	case "django":
		return "p/django"
	case "flask":
		return "p/flask"
	case "express":
		return "p/express"
	case "gin":
		return "p/gin"
	case "echo":
		return "p/echo"
	case "rocket":
		return "p/rocket"
	case "actix":
		return "p/actix"
	default:
		return ""
	}
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

func writeSARIF(code, deps map[string]int, path string) error {
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID  string `json:"ruleId"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []location `json:"locations"`
	}
	res := []result{}
	for f, c := range code {
		r := result{RuleID: "code"}
		r.Message.Text = fmt.Sprintf("%d issues", c)
		r.Locations = []location{{}}
		r.Locations[0].PhysicalLocation.ArtifactLocation.URI = f
		res = append(res, r)
	}
	for f, c := range deps {
		r := result{RuleID: "dependency"}
		r.Message.Text = fmt.Sprintf("%d vulnerabilities", c)
		r.Locations = []location{{}}
		r.Locations[0].PhysicalLocation.ArtifactLocation.URI = f
		res = append(res, r)
	}
	sarif := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool":    map[string]interface{}{"driver": map[string]string{"name": "jkl"}},
				"results": res,
			},
		},
	}
	b, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func writeMarkdown(langs []string, frameworks, builds map[string][]string, code, deps map[string]int, tools []string, path string) error {
	var b strings.Builder
	b.WriteString("# Scan Report\n\n")
	b.WriteString("## Tools Run\n")
	for _, t := range tools {
		b.WriteString("- " + t + "\n")
	}
	b.WriteString("\n## Languages\n")
	for _, l := range langs {
		b.WriteString("- " + l + "\n")
	}
	b.WriteString("\n## Frameworks\n")
	for lang, fws := range frameworks {
		if len(fws) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("- %s: %v\n", lang, fws))
	}
	b.WriteString("\n## Build Systems\n")
	for lang, bs := range builds {
		if len(bs) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("- %s: %v\n", lang, bs))
	}
	if len(code) > 0 {
		b.WriteString("\n## Code Findings\n\n| File | Findings |\n|---|---|\n")
		for f, c := range code {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", f, c))
		}
	}
	if len(deps) > 0 {
		b.WriteString("\n## Dependency Findings\n\n| Manifest | Vulnerabilities |\n|---|---|\n")
		for f, c := range deps {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", f, c))
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0644)
}
