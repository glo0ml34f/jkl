# jkl

Repository reconnaissance tool for vulnerability researchers.

The tool profiles a repository to detect languages, web frameworks, and build systems. It runs `cloc` and `semgrep` inside Docker containers to identify languages and framework usage. Support now covers Python, JavaScript, Go and Rust with basic framework and build system detection.

After profiling, common static analysis tools are executed inside Docker containers (e.g. Semgrep and Gosec) and their findings are aggregated with a ranking of files containing the most issues. Dependency manifests are scanned with `osv-scanner` for known vulnerabilities. Results are written to `report.sarif` and a detailed `report.md` describing all tools that were executed.

## Usage

```
go build
go run main.go [flags] /path/to/repository
```

The command line accepts:

* `-exclude` – comma separated list of directories to skip during language detection (defaults to common virtual environment and dependency folders).
* `-debug` – enable verbose logging.
* `-config` – path to a YAML configuration mapping languages and frameworks to Semgrep rule sets (defaults to `.jklrc`).

Only `docker` must be available in your `PATH`; all other tooling runs inside containers.

### Samples

Sample projects for integration testing are located in the `samples/` directory.
