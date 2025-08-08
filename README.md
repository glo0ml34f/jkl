# jkl

Repository reconnaissance tool for vulnerability researchers.

This MVP scans a git repository to detect languages, web frameworks, and build systems. It uses `cloc` to identify languages and `semgrep` to search for framework usage. Currently it supports Python and JavaScript, detecting Django/Flask and Express/Next.js respectively. Build system detection covers `pip`/`poetry` for Python and `npm`/`yarn` for JavaScript.

## Usage

```
go build
go run main.go /path/to/repository
```

Ensure `cloc` and `semgrep` are installed and available in your `PATH`.
