# jkl

Repository reconnaissance tool for vulnerability researchers.

The tool profiles a repository to detect languages, web frameworks, and build systems. It uses `cloc` to identify languages and `semgrep` to search for framework usage. Support now covers Python, JavaScript, Go and Rust with basic framework and build system detection.

After profiling, common static analysis tools are executed inside Docker containers (e.g. Semgrep and Gosec) and their findings are aggregated with a ranking of files containing the most issues.

## Usage

```
go build
go run main.go [flags] /path/to/repository
```

The command line accepts:

* `-exclude` – comma separated list of directories to skip during language detection (defaults to common virtual environment and dependency folders).
* `-debug` – enable verbose logging.

`cloc`, `semgrep`, and `docker` must be available in your `PATH`.
