package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: scout <path-to-repo>")
		os.Exit(1)
	}
	repo := os.Args[1]

	languages, err := detectLanguages(repo)
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
}

func detectLanguages(repo string) ([]string, error) {
	cmd := exec.Command("cloc", "--json", repo)
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
	return result
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
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
