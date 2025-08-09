# Sample Projects

These small projects are used for integration testing of the `jkl` tool and contain deliberate vulnerabilities for Semgrep to find.

- `python` – Flask application showcasing unsafe deserialization, command execution, and TLS issues with vulnerable dependencies in `requirements.txt`.
- `node` – Express application using `eval`, command execution and insecure TLS with vulnerable dependencies in `package.json`.
- `go` – Gin application with command injection and disabled TLS verification alongside vulnerable dependencies in `go.mod`.

Run the tool against any of these directories to exercise language, framework, and dependency scanning.
