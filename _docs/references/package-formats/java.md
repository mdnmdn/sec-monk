---
title: Java packages (Maven, Gradle, JARs)
type: reference
context: references
status: implemented
tags: [package-format, dependencies, java]
updated: 2026-11-07
sample: mixed
fixtures: tests/fixtures/lang/java/
code: src/secmonk/collectors/lang/java.py
related: [tech/collectors/dependencies.md, references/vuln-sources/osv.md]
---

# Java packages (Maven, Gradle, JARs)

## Summary
PURL `pkg:maven/<group>/<artifact>@<version>` maps to OSV ecosystem `Maven`, package name
`group:artifact`. The Component name is `group:artifact` (set by `base.library()`), which is exactly what
`engine/match.py::_match_package` looks up (`normalize_name('Maven', name)` leaves it unchanged; Maven
names are case-sensitive).

The important case is a Java app in a container image: a Spring Boot fat jar, a shaded/uber jar or a
war/ear. These are read directly from the archive; nothing needs to be extracted to disk.

## Parsers
| Parser | Matches | Evidence | Notes |
|---|---|---|---|
| `java-archive` | `.jar .war .ear .hpi .jpi .par` (+ zip magic `PK\x03\x04`, `binary=True`) | `binary` | reads archive from bytes, recurses into nested archives |
| `maven-pom` | `pom.xml` | `manifest` | literal and `${property}` versions only |
| `gradle-lockfile` | `gradle.lockfile`, `buildscript-gradle.lockfile`, `gradle/dependency-locks/*.lockfile` | `lockfile` | `g:a:v=conf1,conf2` and legacy `g:a:v` |
| `gradle-verification-metadata` | `gradle/verification-metadata.xml` | `lockfile` | `<component group name version>` |

## Archive identification rules (strongest first)
1. **`META-INF/maven/<g>/<a>/pom.properties`** (`groupId`, `artifactId`, `version`): exact. One entry per
   embedded artifact, so shaded jars yield every shaded dependency (`meta.shaded=true` when the artifactId
   does not appear in the jar's own filename). `identified_by=pom.properties`, `confidence=1.0`.
   If any pom.properties yields a result the manifest and filename are not consulted for that jar.
2. **`META-INF/MANIFEST.MF`** (continuation lines handled): version = `Implementation-Version` else
   `Bundle-Version`; artifactId = filename artifact if the filename version agrees with the manifest
   version, else `Implementation-Title` (single token only) else last segment of `Bundle-SymbolicName` /
   `Automatic-Module-Name`; group = `Implementation-Vendor-Id` (must be dotted), or a
   `Bundle-SymbolicName` whose last segment equals the artifactId (`com.acme.widgets` for `widgets`).
   `identified_by=manifest`, `confidence=0.7`.
   **Group unknown** (the common case, e.g. `org.apache.commons.lang3` for `commons-lang3` is not
   derivable): the component is still emitted, purl `pkg:maven/<artifact>@<v>` without namespace,
   `confidence=0.4`, `meta.needs_identification=true`. Such components never match OSV (name has no
   `group:`); they exist so the inventory shows the library. We deliberately do not guess groups.
3. **Filename** `artifact-1.2.3.jar` (first `-<digit>` splits name/version; `-sources/-javadoc/-tests`
   ignored): `identified_by=filename`, `confidence=0.4`, always `needs_identification=true`.

`meta.confidence` is a float (1.0 / 0.7 / 0.4); the engine ignores it today.

## Nesting and safety
- Nested archives (`BOOT-INF/lib/*.jar`, `WEB-INF/lib/*.jar`, `lib/*.jar`, wars in ears, ...) are opened
  recursively, **depth <= 3** below the outer archive. `source_path` is
  `outer.jar!/BOOT-INF/lib/x.jar` (`!/` chains for deeper levels); `meta.parent` is the containing archive.
- Zip-bomb guards: an archive whose *declared* uncompressed sizes sum to > 512 MB is refused (warning for
  the top level, silently skipped when nested); entries > 128 MB are skipped; at most 200k entries; total
  bytes read per tree capped at 512 MB. Python's zipfile never returns more than the declared size, so
  forged headers cannot expand beyond it.
- Memory: nested jars are read fully into memory (<= 128 MB each).

## pom.xml
Reads `<dependencies>` only (not `dependencyManagement`, plugins or profiles). Versions resolve from the
same file: `<properties>`, `project.version`/`pom.version` (own or `<parent>`), `project.groupId`,
`project.parent.*`. Skipped: missing version (managed elsewhere), unresolved `${...}`, ranges `[1,2)`,
`LATEST/RELEASE`. `scope` is recorded in `meta.scope` (test scope is emitted, not dropped); `type` /
`classifier` become purl qualifiers.

## Gradle
`gradle.lockfile` lines `group:artifact:version=conf,...`; `meta.configurations`; `meta.scope=test` when all
configurations are test ones; `empty=` and comment lines ignored. `verification-metadata.xml` lists every
downloaded component (including plugin/build dependencies and artifacts not shipped): lockfile-grade but
over-inclusive.

## Gaps (documented, not implemented)
- Parent POM / BOM (`dependencyManagement`, `import` scope) resolution across files; transitive Maven
  dependencies from `pom.xml` alone (use shaded/fat jars or `gradle.lockfile`).
- `build.gradle(.kts)` / `libs.versions.toml` (no resolved versions).
- `~/.m2/repository/<g path>/<a>/<v>/*.pom` and Gradle caches: a cache is not what is installed; skipped.
- Group inference for manifest/filename-only jars (idea: engine-side lookup of artifactId among OSV Maven
  package names).
- Embedded native libs / jars repackaged without `META-INF/maven` (relocated + stripped) are not found.

## Fixtures (`tests/fixtures/lang/java/`)
| File | Origin |
|---|---|
| `shaded-demo-app-1.0.0.jar` | **real**: built with maven-shade-plugin from `pom.xml` (log4j-core 2.14.1, jackson-databind 2.9.8, commons-lang3 3.12.0); `.class`/resources stripped, metadata kept |
| `springboot-app-0.1.0.jar` | **constructed**: Spring Boot `BOOT-INF/lib` layout (zipfile) containing the real (stripped) Maven Central jars log4j-core/api 2.14.1, jackson-databind/core 2.9.8, annotations 2.9.0 |
| `commons-lang3-3.12.0.jar` | **real** from Maven Central, classes stripped |
| `pom.xml` | **real** (the project used to build the shaded jar; `${log4j.version}`) |
| `gradle.lockfile` | **real**, bwaldvogel/liblinear-java |
| `jmeter-verification-metadata.xml` | **real**, apache/jmeter `gradle/verification-metadata.xml` |
Manifest-only, filename-only, war/ear nesting and zip-bomb cases are built in memory in the tests
(synthetic). The OSV match test reuses `tests/fixtures/sources/osv/maven-GHSA-jfh8-c2jp-5v3q.json`.
