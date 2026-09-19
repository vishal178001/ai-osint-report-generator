# Contributing

Thank you for your interest in contributing to AI-Assisted OSINT Report Generator.

## Development setup

1. Fork the repository.
2. Clone your fork.
3. Create a virtual environment.
4. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

5. Run the test suite:

```bash
python -m pytest -v
```

## Making changes

Please keep changes focused and modular.

When adding a collector or enrichment provider:

- Keep network operations bounded with timeouts.
- Handle failures without terminating the entire scan when practical.
- Return structured data that can be consumed by the analysis layer.
- Add tests for normal and failure paths.
- Avoid committing API keys, credentials, generated scan data, or personal information.

## Pull requests

Please include:

- A clear description of the change
- Why the change is useful
- Tests or validation performed
- Any new configuration requirements
- Any security or responsible-use considerations

Small, focused pull requests are easier to review.

## Code quality

Prefer readable Python, small functions, explicit error handling, and consistent data structures. Avoid introducing dependencies when the standard library or an existing project dependency is sufficient.
