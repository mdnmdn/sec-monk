# Homebrew fixtures (collected 2026-11-07)

`prefix/` is a minimal Homebrew prefix (what `/opt/homebrew`, `/usr/local` or
`/home/linuxbrew/.linuxbrew` would contain). `casks/` holds real cask definitions.
Analysis: `_docs/references/homebrew.md`.

The bottle layer blobs (`pkg-containers.githubusercontent.com`) are blocked in the dev sandbox,
so the kegs were **reconstructed from real registry/API data**, not extracted from tarballs.

| Path | Provenance |
|---|---|
| `prefix/Cellar/<f>/<v>/INSTALL_RECEIPT.json` | Bottle `sh.brew.tab` annotation from the real ghcr.io `arm64_sequoia` manifest (REAL: `homebrew_version`, `changed_files`, `compiler`, `runtime_dependencies`, `arch`, `built_on`) + the fields `brew install` adds at pour time per `Library/Homebrew/formula_installer.rb#pour` (`source.*`, `poured_from_bottle`, `installed_on_request`, `time`, ...). The pour-time values (`time`, `installed_on_request`, `source.path`, `tap_git_head` = bottle commit) are SYNTHETIC. |
| `.../.brew/<f>.rb` | REAL formula text from `Homebrew/homebrew-core` at the commit recorded in the manifest (`org.opencontainers.image.revision`), `bottle do ... end` block stripped as Homebrew does. |
| `.../sbom.spdx.json` | RECONSTRUCTED following `Library/Homebrew/sbom.rb` (source `Archive-<f>-src` package, `File-<f>`, relationships) + the REAL `sh.brew.sbom.supplement` annotation merged exactly as `SBOM.update_pour_metadata` does (runtime deps with `pkg:brew` purls, compiler, `Bottle-<f>` package). `jq/1.8.1` (older bottle) has no supplement in the registry, so its SBOM has only the source archive. The `Archive` purl (`pkg:brew/homebrew/core/<f>@<v>`) is derived from the code, not observed. |
| `httpie/3.2.4_13/libexec/lib/python3.15/site-packages/*.dist-info/METADATA` | REAL PyPI wheel METADATA headers (body/long description dropped) for the exact versions pinned in the formula's `resource` stanzas. Homebrew builds these from sdists, so file lists differ but Name/Version/Requires-Dist are identical. `INSTALLER` and `homebrew_deps.pth` are hand-made. |
| `prefix/opt/<f>`, `var/homebrew/linked/<f>`, `var/homebrew/pinned/xz` | Relative symlinks created as Homebrew does (`opt -> ../Cellar/<f>/<v>`, `linked -> ../../../Cellar/<f>/<v>`). `jq` has TWO kegs (1.8.1, 1.8.2); `opt/jq` and `linked/jq` point to 1.8.2. `openssl@3` and `curl` are keg-only: `opt` link, no `linked` entry. The `xz` pin is synthetic. |
| `casks/*.rb` | REAL files from `Homebrew/homebrew-cask` (`google-chrome`: `auto_updates true`; `boop`: plain; `autodesk-fusion`: `version :latest`). |
| `prefix/Caskroom/<t>/.metadata/<ver>/<ts>/Casks/<t>.rb` | The same `.rb` placed where `brew` stores it (timestamps synthetic; `latest` is the literal dir name for `version :latest`). Real installs also have `Caskroom/<t>/<ver>/<App>.app` (absolute symlink into `/Applications`) and `.metadata/INSTALL_RECEIPT.json`, `config.json`; not included. |
| `real/` | REAL, trimmed and anonymized prefix + `brew info --json=v2` captured 2026-11-08 on macOS 26.5 arm64 (brew 6.0.21); see `real/README.md`. It corrects three assumptions of the reconstructed fixtures above: API-installed casks store a *minimal* `<token>.json` (often `{}`), not the `.rb`; the SBOM `Archive-<f>-src` package carries no purl (the `pkg:brew/homebrew/core/<f>@<v>` purl is on `Bottle-<f>`, also on the Archive in 44 of 398 real SBOMs, written by brew >= 5.1.14 or unversioned dev builds); source builds by brew >= 4.3 do have an SBOM. |
