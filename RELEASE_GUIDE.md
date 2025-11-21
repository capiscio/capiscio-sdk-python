# Release Guide - CapiscIO A2A Security

This guide explains how to release a new version of the package.

## Prerequisites

### 1. PyPI Trusted Publishing (Recommended)

Setup trusted publishing on PyPI to avoid managing API tokens:

1. Go to https://pypi.org/manage/account/publishing/
2. Add a new "pending publisher":
   - **PyPI Project Name:** `capiscio-sdk`
   - **Owner:** `capiscio`
   - **Repository:** `capiscio-sdk-python`
   - **Workflow:** `publish.yml`
   - **Environment:** (leave empty)

This allows GitHub Actions to publish directly without storing secrets.

### 2. Alternative: Manual Publishing

If not using trusted publishing, you'll need a PyPI API token:

1. Generate token at https://pypi.org/manage/account/token/
2. Add to GitHub Secrets as `PYPI_API_TOKEN`
3. Update `.github/workflows/publish.yml` to use password authentication

## Release Process

### Step 1: Prepare Release

1. **Update version** in `pyproject.toml`:
   ```toml
   version = "0.2.0"  # Increment appropriately
   ```

2. **Update CHANGELOG.md**:
   ```markdown
   ## [0.2.0] - 2025-10-11
   
   ### Added
   - New features
   
   ### Changed
   - Breaking changes
   
   ### Fixed
   - Bug fixes
   ```

3. **Update documentation** if needed (README, docs/)

4. **Run tests** to ensure everything works:
   ```bash
   pytest
   ```

5. **Commit changes**:
   ```bash
   git add pyproject.toml CHANGELOG.md
   git commit -m "Prepare v0.2.0 release"
   git push
   ```

### Step 2: Create Release Tag

1. **Tag the release**:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

2. **GitHub Action automatically**:
   - Builds the package
   - Runs checks
   - Publishes to PyPI
   - Creates GitHub release with notes

### Step 3: Verify Release

1. **Check PyPI**: https://pypi.org/project/capiscio-sdk/
2. **Test installation**:
   ```bash
   pip install capiscio-sdk==0.2.0
   python -c "import capiscio_sdk; print('✓ Works!')"
   ```
3. **Check GitHub Release**: https://github.com/capiscio/capiscio-sdk-python/releases

## Manual Release (If Automated Fails)

If the GitHub Action fails or you need to publish manually:

```bash
# 1. Clean previous builds
rm -rf dist/ build/

# 2. Build package
python -m build

# 3. Check package
python -m twine check dist/*

# 4. Upload to PyPI
python -m twine upload dist/*
# Enter your PyPI username and API token when prompted

# 5. Create GitHub release manually
# Go to: https://github.com/capiscio/capiscio-sdk-python/releases/new
# - Tag: v0.2.0
# - Title: Release v0.2.0
# - Description: Copy from CHANGELOG.md
# - Upload dist/* files
```

## Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (0.2.0): New features, backward compatible
- **PATCH** (0.1.1): Bug fixes, backward compatible

### Examples:
- `0.1.0` → `0.1.1`: Bug fix
- `0.1.0` → `0.2.0`: New feature (scoring system update)
- `0.1.0` → `1.0.0`: First stable release with API guarantees

## Pre-Release Versions

For testing releases before official:

```bash
# Alpha release
version = "0.2.0a1"
git tag v0.2.0a1

# Beta release
version = "0.2.0b1"
git tag v0.2.0b1

# Release candidate
version = "0.2.0rc1"
git tag v0.2.0rc1
```

## Rollback Process

If a release has critical issues:

### On PyPI:
1. You **cannot delete** a version from PyPI
2. Instead, release a new patch version with fixes
3. Update documentation to warn about the bad version

### On GitHub:
1. Delete the release (but not the tag if on PyPI)
2. Delete the tag locally: `git tag -d v0.2.0`
3. Delete remote tag: `git push origin :refs/tags/v0.2.0`

## Checklist

Before each release:

- [ ] Version bumped in `pyproject.toml`
- [ ] CHANGELOG.md updated
- [ ] Documentation updated (if needed)
- [ ] Smoke tests pass: `python smoke_test.py`
- [ ] All changes committed and pushed
- [ ] Tag created and pushed
- [ ] GitHub Action succeeded
- [ ] Package visible on PyPI
- [ ] Installation tested
- [ ] GitHub release created

## Troubleshooting

### "Package already exists on PyPI"
- You cannot re-upload the same version
- Increment version and create new release

### "Trusted publishing failed"
- Verify configuration at https://pypi.org/manage/account/publishing/
- Ensure workflow name matches exactly
- Check repository owner and name are correct

### "Build failed"
- Check GitHub Actions logs
- Verify pyproject.toml syntax
- Ensure all files are committed

### "Import failed after install"
- Check package structure with: `python -m zipfile -l dist/*.whl`
- Verify `__init__.py` exports are correct
- Test in clean virtual environment

## Support

- **Issues:** https://github.com/capiscio/capiscio-sdk-python/issues
- **Discussions:** https://github.com/capiscio/capiscio-sdk-python/discussions
- **PyPI:** https://pypi.org/project/capiscio-sdk/
