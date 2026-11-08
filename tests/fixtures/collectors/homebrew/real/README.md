# Real Homebrew fixtures (captured 2026-11-08)

Real, trimmed and anonymized, captured 2026-11-08 on macOS 26.5 arm64 (Apple Silicon), `/opt/homebrew`,
Homebrew 6.0.21 (361 racks / 465 kegs / 10 Caskroom entries on the source machine). Files are byte copies except:
`/Users/<name>` replaced by `/Users/user` (receipt `source.path`, cask `config.json`); the cask `config.json`
`languages` list (the capture machine's locale) replaced by `["en-US"]`. Relative symlinks are recreated
exactly as Homebrew made them (`opt/`, `var/homebrew/linked/`, `Caskroom/aws-vault`). The absolute
`Caskroom/<t>/<v>/<App>.app -> /Applications/<App>.app` links are NOT committed (pytest would follow them into the real
`/Applications` while collecting); the tests create them in a copy (`.keep` holds the empty version dirs). Nothing else
in the prefix was copied (no binaries, no `lib/`).

| Path | What it shows |
|---|---|
| `prefix/Cellar/xz/5.8.3/` | bottle poured by brew 5.1.x: receipt (`loaded_from_api`, `source.path` = API cache), `.brew/xz.rb`, real `sbom.spdx.json` (`Archive-xz-src` without purl; `pkg:brew/homebrew/core/xz@5.8.3` on the `Bottle-xz` package; `Compiler` package). `opt` + `linked` |
| `prefix/Cellar/zlib/1.2.13/` | keg-only (`keg_only :provided_by_macos` in `.brew/zlib.rb`), receipt from brew 3.6, **no SBOM**; `opt` only |
| `prefix/Cellar/libpng/1.6.58/` | NOT keg-only but unlinked (`opt` only, no `linked` entry): regression for "unlinked != keg-only" |
| `prefix/Cellar/nomad/1.6.3/` | third-party tap `hashicorp/tap`, `poured_from_bottle: false`, `built_as_bottle: false`, brew 4.1, no SBOM; `url` only inside `if OS.mac? && Hardware::CPU.arm?` blocks |
| `prefix/Caskroom/kopiaui/` | API-installed cask: `.metadata/<v>/<ts>/Casks/kopiaui.json` is the **minimal** API JSON (`url_specs`, `artifacts` only: no `name`, `version`, `auto_updates`); no `INSTALL_RECEIPT.json` (older brew); `config.json` |
| `prefix/Caskroom/orbstack/` | API cask whose stored JSON is `{}`; `.metadata/INSTALL_RECEIPT.json` (brew 4.5: `loaded_from_api`, `source.tap`, `uninstall_artifacts`); version with comma `1.11.3,19358` |
| `prefix/Caskroom/redis-stack/` | third-party (untapped) cask stored as `.rb` |
| `prefix/Caskroom/aws-vault-binary/`, `aws-vault -> aws-vault-binary` | renamed cask: the old token is a symlink to the new token dir (skipped) |
| `brew-info.json` | `brew info --json=v2 --installed` from the same machine, trimmed to `xz`, `zlib`, `libpng`, `openssl@3` (two kegs, `linked_keg` 3.6.3) and casks `kopiaui`, `orbstack` (`variations` dropped) |
