---
title: .NET packages (NuGet)
summary: NuGet parsers for deps.json, packages.lock.json, project.assets.json, csproj and Directory.Packages.props, PURL casing, runtime pack mapping to OSV and gaps.
read_when: you change the .NET dependency parsers or need to know how NuGet packages and runtimes map to OSV
type: reference
context: references
status: implemented
tags: [package-format, dependencies, dotnet]
updated: 2026-11-07
verified: 2026-11-07
sample: mixed
fixtures: tests/fixtures/lang/dotnet/
code: src/secmonk/collectors/lang/dotnet.py
related: [tech/collectors/dependencies.md, references/vuln-sources/osv.md]
---

# .NET packages (NuGet)

## Summary
PURL `pkg:nuget/<Name>@<version>` maps to OSV ecosystem `NuGet`, package name = `<Name>`.
NuGet ids are case-insensitive. The **purl name is lowercased** (purl spec; OSV stores lowercase) while `Component.name` keeps the
original display casing, so case variants dedupe. `engine.purl.normalize_name` lowercases
for NuGet and the OSV importer lowercases `affected.package` the same way, so `Newtonsoft.Json`,
`newtonsoft.json` and OSV's mixed spellings (`Microsoft.NetCore.App.Runtime.*` vs `Microsoft.NETCore...`)
all meet.

## Parsers
| Parser | Matches | Evidence | Notes |
|---|---|---|---|
| `dotnet-deps-json` | `*.deps.json` | `installed` | published/runtime apps and shared frameworks; the key one inside images |
| `dotnet-packages-lock` | `packages.lock.json` | `lockfile` | `dependencies.<tfm>.<name>.resolved`; `meta.direct`, `meta.tfms`; `Project` entries skipped |
| `dotnet-project-assets` | `project.assets.json` | `lockfile` | `libraries` `Name/Version` of type `package`; `meta.direct` from `projectFileDependencyGroups` |
| `dotnet-packages-config` | `packages.config` | `lockfile` | legacy XML; `tfm`, `development` |
| `dotnet-project-file` | `*.csproj *.fsproj *.vbproj`, `Directory.Build.props/targets` | `manifest` | `PackageReference` Include/Update + `Version` attr or child element |
| `dotnet-central-packages` | `Directory.Packages.props` | `manifest` | `PackageVersion`, `GlobalPackageReference`; `meta.declared_only` |

### deps.json rules
Entries come from `targets[runtimeTarget.name]` (else the largest target, else `libraries`); the `type` is
read from `libraries`. `package` -> emitted; `project`, `reference`, `referenceassembly` -> skipped;
`runtimepack` (self-contained apps: `runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/8.0.4`) ->
prefix stripped and emitted. `meta.runtime_target` (e.g. `.NETCoreApp,Version=v8.0/linux-x64`) and `tfm` recorded.

### Project files
Literal versions, `[1.2.3]` (exact), and `$(Property)` resolved from the same file's `PropertyGroup`
(MSBuild property names are case-insensitive: `$(fooversion)` finds `<FooVersion>`).
`Update=` items without a matching `Include=` only modify an item declared elsewhere: emitted with
`meta.declared_only=true`. An item's own or its `ItemGroup`'s `Condition` is kept in `meta.condition`.
Skipped: floating (`1.*`, `1.0.0-*`), ranges (`[1.0,2.0)`), unresolved properties, and `PackageReference`
without a version (central package management: the version lives in `Directory.Packages.props`, which is
parsed separately; cross-file joining is a gap). A bare `1.0` is NuGet's *minimum* (>= 1.0) but is the version
restore picks in practice, so it is kept. `PrivateAssets="all"` -> `meta.development`.
`Directory.Packages.props` lists *available* versions and may include packages no project uses ->
`declared_only`.

## .NET runtime mapping (decision)
OSV records .NET runtime CVEs against the NuGet **runtime packs**, found by scanning the NuGet bucket
(`https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip`):

| OSV NuGet package name | records |
|---|---|
| `Microsoft.NETCore.App.Runtime.<rid>` (also spelled `Microsoft.NetCore.App.Runtime.<rid>`) | ~65 per rid, ranges like `introduced 8.0.0 / fixed 8.0.32` |
| `Microsoft.AspNetCore.App.Runtime.<rid>` | ~80 per rid |
| `Microsoft.WindowsDesktop.App.Runtime.<rid>` | ~80 (win only) |
| `Microsoft.NETCore.App`, `Microsoft.AspNetCore.App` (legacy 1.x-2.x) | 14 each |
| `Microsoft.NETCore.App.Runtime.Mono.*` | few |

rids: `linux-x64`, `linux-musl-x64`, `linux-arm`, `linux-arm64`, `linux-musl-arm64`, `win-*`, `osx-*`.

The runtime installed in a base image (`/usr/share/dotnet/shared/Microsoft.NETCore.App/<ver>/`) ships a
`Microsoft.NETCore.App.deps.json` whose only library is `Microsoft.NETCore.App.Runtime.<rid>/<ver>` (real
sample in fixtures), the same for `Microsoft.AspNetCore.App`. So the generic deps.json parser already
gives the right name **including the rid**; no directory-name rule is needed (a directory version alone
could not tell the rid). Self-contained apps list `runtimepack.<same name>`. These components are emitted as
`CAT_LIBRARY` with `meta.runtime=true`, **not** `CAT_RUNTIME`: `engine/match.py::match_asset` calls
`_match_package` only for library / os-package components; a runtime-category NuGet component would go to
CPE product matching and never see the OSV rows. NVD/CPE coverage for ".NET Runtime" is not emitted here.

## Gaps
`.nuspec`, `.nupkg`, `paket.lock`, assembly (`*.dll`) version scanning, `packages.config` transitive
resolution beyond what the file lists, MSBuild conditions/imports, central versions joined to projects.

## Fixtures (`tests/fixtures/lang/dotnet/`) - all real, from public GitHub repos
| File | Source |
|---|---|
| `published-loader.deps.json` | TehCheat/PoEHelper `Loader.deps.json` (published app, win-x64, 110 packages + 1 project) |
| `shared-Microsoft.NETCore.App.6.0.1.deps.json` | nxrighthere/UnrealCLR shared runtime for linux-x64 |
| `packages.lock.json` | ThreeMammals/Ocelot `unit/packages.lock.json` (3 tfms; Direct/Transitive/Project) |
| `legacy-cronos.packages.lock.json` | HangfireIO/Cronos `.nuget/packages.lock.json` (`Any,Version=v0.0`) |
| `project.assets.json` | mercethem/UAV_Tower `obj/project.assets.json` |
| `packages.config` | michaelweber/Macrome; `small.packages.config` from NuGet/NuGetGallery |
| `Catalog.API.csproj`, `Basket.API.csproj`, `Directory.Packages.props` | dotnet/eShop (central package management) |
| `osv-nuget-GHSA-5crp-9r3c-p9vr.json`, `osv-nuget-GHSA-555c-2p6r-68mm.json` | OSV NuGet bucket (Newtonsoft.Json; .NET runtime packs) |
Inline-synthetic (in the tests): the csproj variants, a self-contained `runtimepack` deps.json, an
ASP.NET runtime-pack deps.json.
