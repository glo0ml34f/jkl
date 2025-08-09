package main

import (
	"bytes"
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

type Finding struct {
	File    string
	Line    int
	Rule    string
	Message string
}

type DepFinding struct {
	Manifest        string
	Vulnerabilities []string
}

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
	if len(depFindings) > 0 {
		fmt.Println("Dependency manifests with most vulnerabilities:")
		rankAndPrintDeps(depFindings)
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
	if err := parseJSON(out, &data); err != nil {
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
			if runSemgrepPatternDocker(repo, "python", "import flask") || runSemgrepPatternDocker(repo, "python", "from flask import Flask") {
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
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	}
	log.Printf("exit code: %d", code)
	if stdout.Len() > 0 {
		log.Printf("stdout: %s", strings.TrimSpace(stdout.String()))
	}
	if stderr.Len() > 0 {
		log.Printf("stderr: %s", strings.TrimSpace(stderr.String()))
	}
	if err != nil {
		allow := len(allowedExitCodes) == 0
		for _, c := range allowedExitCodes {
			if code == c {
				allow = true
				break
			}
		}
		if !allow {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
		}
	}
	return stdout.Bytes(), nil
}

func parseJSON(b []byte, v interface{}) error {
	if err := json.Unmarshal(b, v); err != nil {
		snippet := strings.TrimSpace(string(b))
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		return fmt.Errorf("invalid JSON: %w: %s", err, snippet)
	}
	return nil
}

func runSemgrepPatternDocker(repo, lang, pattern string) bool {
	args := []string{
		"run", "--rm", "-v", repo + ":/src",
		"returntocorp/semgrep", "semgrep", "scan",
		"--json", "-q", "--lang", lang, "-e", pattern, "/src",
	}
	cmd := exec.Command("docker", args...)
	out, err := runCommand(cmd, 0, 1)
	if err != nil {
		return false
	}
	var data struct {
		Results []struct{} `json:"results"`
	}
	if err := parseJSON(out, &data); err != nil {
		return false
	}
	return len(data.Results) > 0
}

func runAnalyses(repo string, languages []string, frameworks map[string][]string) ([]Finding, []string) {
	findings := []Finding{}
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
		switch lang {
		case "Go":
			fs, err := runGosec(repo)
			if err != nil {
				log.Printf("analysis for %s failed: %v", lang, err)
				continue
			}
			tools["gosec"] = true
			findings = append(findings, fs...)
		default:
			fs, err := runSemgrepDocker(repo, "p/owasp-top-ten")
			if err != nil {
				log.Printf("analysis for %s failed: %v", lang, err)
			} else {
				tools["semgrep"] = true
				findings = append(findings, fs...)
			}
			ci, err := runSemgrepDocker(repo, "p/command-injection")
			if err != nil {
				log.Printf("command scan failed: %v", err)
			} else {
				tools["semgrep"] = true
				findings = append(findings, ci...)
			}
		}
		for _, fw := range frameworks[lang] {
			if rule := frameworkRule(fw); rule != "" {
				fm, err := runSemgrepDocker(repo, rule)
				if err != nil {
					log.Printf("framework scan %s failed: %v", fw, err)
					continue
				}
				tools["semgrep"] = true
				findings = append(findings, fm...)
			}
		}
	}
	toolList := []string{}
	for t := range tools {
		toolList = append(toolList, t)
	}
	return findings, toolList
}

func runSemgrepDocker(repo, config string) ([]Finding, error) {
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
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			Extra struct {
				Message string `json:"message"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := parseJSON(out, &data); err != nil {
		return nil, err
	}
	findings := []Finding{}
	for _, r := range data.Results {
		p := strings.TrimPrefix(r.Path, "/src/")
		findings = append(findings, Finding{File: p, Line: r.Start.Line, Rule: r.CheckID, Message: r.Extra.Message})
	}
	return findings, nil
}

func runGosec(repo string) ([]Finding, error) {
	cmd := exec.Command("docker", "run", "--rm", "-v", repo+":/src", "securego/gosec", "-fmt=json", "/src/...")
	out, err := runCommand(cmd, 0, 1)
	if err != nil {
		return nil, err
	}
	var data struct {
		Issues []struct {
			File    string `json:"file"`
			RuleID  string `json:"rule_id"`
			Details string `json:"details"`
			Line    int    `json:"line"`
		} `json:"Issues"`
	}
	if err := parseJSON(out, &data); err != nil {
		return nil, err
	}
	findings := []Finding{}
	for _, i := range data.Issues {
		p := strings.TrimPrefix(i.File, "/src/")
		findings = append(findings, Finding{File: p, Line: i.Line, Rule: i.RuleID, Message: i.Details})
	}
	return findings, nil
}

func scanDependencies(repo string) ([]DepFinding, error) {
	cmd := exec.Command("docker", "run", "--rm", "-v", repo+":/src", "ghcr.io/google/osv-scanner:latest", "--format", "json", "--call-analysis", "-r", "/src")
	out, err := runCommand(cmd, 0, 1)
	if err != nil {
		return nil, err
	}
	var data struct {
		Results []struct {
			Source   json.RawMessage `json:"source"`
			Packages []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID string `json:"id"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := parseJSON(out, &data); err != nil {
		return nil, err
	}
	findings := []DepFinding{}
	for _, r := range data.Results {
		var src struct {
			Path string `json:"path"`
		}
		path := ""
		if err := json.Unmarshal(r.Source, &path); err != nil {
			if err := json.Unmarshal(r.Source, &src); err == nil {
				path = src.Path
			}
		}
		p := strings.TrimPrefix(path, "/src/")
		vulns := []string{}
		for _, pkg := range r.Packages {
			for _, v := range pkg.Vulnerabilities {
				vulns = append(vulns, v.ID)
			}
		}
		findings = append(findings, DepFinding{Manifest: p, Vulnerabilities: vulns})
	}
	return findings, nil
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

func rankAndPrint(findings []Finding) {
	counts := countFindings(findings)
	type kv struct {
		File  string
		Count int
	}
	list := make([]kv, 0, len(counts))
	for k, v := range counts {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Count > list[j].Count })
	for _, kv := range list {
		fmt.Printf("%s: %d\n", kv.File, kv.Count)
	}
}

func rankAndPrintDeps(findings []DepFinding) {
	counts := countDepFindings(findings)
	type kv struct {
		Manifest string
		Count    int
	}
	list := make([]kv, 0, len(counts))
	for k, v := range counts {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Count > list[j].Count })
	for _, kv := range list {
		fmt.Printf("%s: %d\n", kv.Manifest, kv.Count)
	}
}

func countFindings(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.File]++
	}
	return m
}

func countDepFindings(df []DepFinding) map[string]int {
	m := map[string]int{}
	for _, d := range df {
		m[d.Manifest] = len(d.Vulnerabilities)
	}
	return m
}

func writeSARIF(code []Finding, deps []DepFinding, path string) error {
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
			} `json:"region"`
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
	for _, f := range code {
		r := result{RuleID: f.Rule}
		r.Message.Text = f.Message
		loc := location{}
		loc.PhysicalLocation.ArtifactLocation.URI = f.File
		loc.PhysicalLocation.Region.StartLine = f.Line
		r.Locations = []location{loc}
		res = append(res, r)
	}
	for _, d := range deps {
		r := result{RuleID: "dependency"}
		r.Message.Text = strings.Join(d.Vulnerabilities, ", ")
		loc := location{}
		loc.PhysicalLocation.ArtifactLocation.URI = d.Manifest
		r.Locations = []location{loc}
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

func writeMarkdown(langs []string, frameworks, builds map[string][]string, code []Finding, deps []DepFinding, tools []string, path string) error {
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
		b.WriteString("\n## Code Findings\n\n| File | Line | Rule | Message |\n|---|---|---|---|\n")
		for _, f := range code {
			msg := strings.ReplaceAll(f.Message, "|", "\\|")
			b.WriteString(fmt.Sprintf("| %s | %d | %s | %s |\n", f.File, f.Line, f.Rule, msg))
		}
	}
	if len(deps) > 0 {
		b.WriteString("\n## Dependency Findings\n\n| Manifest | Vulnerabilities |\n|---|---|\n")
		for _, d := range deps {
			b.WriteString(fmt.Sprintf("| %s | %s |\n", d.Manifest, strings.Join(d.Vulnerabilities, ", ")))
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0644)
}
