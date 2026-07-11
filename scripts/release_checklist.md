# Release Checklist

## Pre-release

- [ ] Update version in `hydra/__init__.py`
- [ ] Update version in `pyproject.toml`
- [ ] Update `CHANGELOG.md` with release notes
- [ ] Update Docker labels in `Dockerfile` (version)
- [ ] Run full test suite: `make test`
- [ ] Run linter: `make lint`
- [ ] Build distributions: `make build`
- [ ] Validate distributions: `make check`
- [ ] Run smoke test: `make smoke`
- [ ] Build Docker images: `make docker && make docker-slim`

## Release

- [ ] Create and push git tag: `git tag v1.0.0 && git push origin v1.0.0`
- [ ] Verify GitHub Actions release workflow completes
- [ ] Verify GitHub Release is created with artifacts
- [ ] (Optional) Publish to PyPI: `twine upload dist/*`

## Post-release

- [ ] Verify installation: `pip install hydra-security==1.0.0`
- [ ] Verify Docker images run correctly
- [ ] Update any external documentation
