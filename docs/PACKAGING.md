# Clean Packaging for Sharing ARES

Do not share a manually compressed working folder. Working folders can contain
virtual environments, generated reports, local databases, audit logs, caches,
Git metadata, and macOS metadata.

Do not commit virtualenvs, generated reports, local databases, audit logs, or
macOS metadata.

Before sharing, run the complete test suite, then create the package:

```bash
./scripts/package_clean.sh
```

Share only the generated `dist/ares-clean-source-*.zip`.
