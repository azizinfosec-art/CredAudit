# Publishing CredAudit

## Build locally

```bash
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
```

## Test the wheel

```bash
python -m pip install dist/credaudit-0.7.0-py3-none-any.whl
python -c "from credaudit import scan; print(scan('.').counts)"
```

## Publish

Create a PyPI account and API token, then upload the generated files:

```bash
python -m twine upload dist/*
```

Never commit the PyPI token to the repository. Create a new version in
`pyproject.toml` before each subsequent release.
