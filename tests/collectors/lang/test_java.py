"""Java parsers: jars (plain, shaded, Spring Boot, war/ear), pom.xml, Gradle lockfiles.

Fixtures in tests/fixtures/lang/java/ (see _docs/references/package-formats/java.md): real Maven Central
metadata (class files stripped); the shaded jar was built with maven-shade-plugin from pom.xml.
"""

from __future__ import annotations

import io
import json
import struct
import zipfile
from pathlib import Path

import pytest

from secmonk.collectors.lang import java, parse_file, parsers_for, wants
from secmonk.collectors.lang.base import EV_BINARY, EV_LOCKFILE, EV_MANIFEST
from secmonk.engine.inventory import save_inventory
from secmonk.engine.match import match_asset
from secmonk.models import Asset, Inventory
from secmonk.sources.osv import import_record

FX = Path(__file__).parents[2] / "fixtures" / "lang" / "java"
OSV = Path(__file__).parents[2] / "fixtures" / "sources" / "osv"


def by_purl(comps):
    return {c.purl: c for c in comps}


def make_zip(entries: dict[str, bytes | str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in entries.items():
            z.writestr(n, d)
    return buf.getvalue()


def pom_props(g, a, v):
    return f"#Created by Apache Maven\nversion={v}\ngroupId={g}\nartifactId={a}\n"


# --------------------------------------------------------------------------- jars
def test_plain_jar_pom_properties():
    comps, warns = parse_file("lib/commons-lang3-3.12.0.jar", (FX / "commons-lang3-3.12.0.jar").read_bytes())
    assert not warns and len(comps) == 1
    c = comps[0]
    assert c.name == "org.apache.commons:commons-lang3" and c.version == "3.12.0"
    assert c.purl == "pkg:maven/org.apache.commons/commons-lang3@3.12.0" and c.ecosystem == "Maven"
    assert c.meta["evidence"] == EV_BINARY and c.meta["identified_by"] == "pom.properties"
    assert c.meta["confidence"] == 1.0 and c.source_path == "lib/commons-lang3-3.12.0.jar"


def test_shaded_jar_emits_every_embedded_artifact():
    comps, warns = parse_file("app/demo.jar", (FX / "shaded-demo-app-1.0.0.jar").read_bytes())
    assert not warns
    p = by_purl(comps)
    assert set(p) == {
        "pkg:maven/com.example/demo-app@1.0.0",
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1",
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8",
        "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.9.8",
        "pkg:maven/com.fasterxml.jackson.core/jackson-annotations@2.9.0",
        "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
    }
    assert all(c.meta["evidence"] == EV_BINARY and c.source_path == "app/demo.jar" for c in comps)
    # filename is 'demo.jar' -> nothing is "its own" artifact, all flagged shaded
    assert p["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"].meta["shaded"] is True
    assert "shaded" not in by_purl(parse_file("shaded-demo-app-1.0.0.jar",
                                              (FX / "shaded-demo-app-1.0.0.jar").read_bytes())[0]
                                   )["pkg:maven/com.example/demo-app@1.0.0"].meta


def test_spring_boot_fat_jar_nested_paths():
    comps, _ = parse_file("app.jar", (FX / "springboot-app-0.1.0.jar").read_bytes())
    p = by_purl(comps)
    own = p["pkg:maven/com.example/springboot-app@0.1.0"]
    assert own.source_path == "app.jar" and "parent" not in own.meta
    log4j = p["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"]
    assert log4j.source_path == "app.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar"
    assert log4j.meta["parent"] == "app.jar" and log4j.meta["identified_by"] == "pom.properties"
    assert p["pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8"].version == "2.9.8"
    assert len(comps) == 6


def test_manifest_fallback_with_vendor_id():
    mf = ("Manifest-Version: 1.0\r\nImplementation-Title: Log4j Core\r\nImplementation-Version: 2.14.1\r\n"
          "Implementation-Vendor-Id: org.apache.logging.log4j\r\n\r\n")
    data = make_zip({"META-INF/MANIFEST.MF": mf, "a/B.class": b"x"})
    (c,) = parse_file("log4j-core-2.14.1.jar", data)[0]
    # Implementation-Vendor-Id names the vendor, not necessarily the groupId: hint only
    assert c.purl == "pkg:maven/log4j-core@2.14.1"
    assert c.meta["identified_by"] == "manifest" and c.meta["confidence"] == 0.4
    assert c.meta["needs_identification"] is True and c.meta["vendor_id"] == "org.apache.logging.log4j"


def test_manifest_fallback_unknown_group_and_continuation_lines():
    mf = ("Manifest-Version: 1.0\r\nBundle-SymbolicName: org.apache.commons.lang3\r\n"
          "Bundle-Name: Apache Commons\r\n Lang\r\nBundle-Version: 3.12.0\r\n\r\n")
    (c,) = parse_file("commons-lang3-3.12.0.jar", make_zip({"META-INF/MANIFEST.MF": mf}))[0]
    assert c.name == "commons-lang3" and c.version == "3.12.0"
    assert c.purl == "pkg:maven/commons-lang3@3.12.0"
    assert c.meta["identified_by"] == "manifest" and c.meta["confidence"] == 0.4
    assert c.meta["needs_identification"] is True


def test_manifest_group_from_symbolic_name_ending_in_artifact():
    mf = "Manifest-Version: 1.0\nBundle-SymbolicName: com.acme.widgets;singleton:=true\nBundle-Version: 1.2.3\n"
    (c,) = parse_file("widgets-1.2.3.jar", make_zip({"META-INF/MANIFEST.MF": mf}))[0]
    assert c.purl == "pkg:maven/com.acme/widgets@1.2.3" and c.meta["confidence"] == 0.7


def test_filename_fallback_lowest_confidence():
    comps, _ = parse_file("lib/guava-31.1-jre.jar", make_zip({"com/google/Foo.class": b"x"}))
    (c,) = comps
    assert (c.name, c.version) == ("guava", "31.1-jre")
    assert c.meta["identified_by"] == "filename" and c.meta["confidence"] == 0.4
    assert c.meta["needs_identification"] is True


def test_unidentifiable_and_source_jars_emit_nothing():
    assert parse_file("app.jar", make_zip({"A.class": b"x"}))[0] == []
    assert parse_file("foo-1.0-sources.jar", make_zip({"A.java": b"x"}))[0] == []


def test_war_and_ear_nested_depth():
    inner = make_zip({"META-INF/maven/org.x/inner/pom.properties": pom_props("org.x", "inner", "1.0")})
    war = make_zip({
        "META-INF/maven/org.acme/shop/pom.properties": pom_props("org.acme", "shop", "2.0"),
        "WEB-INF/lib/inner-1.0.jar": inner,
        "WEB-INF/lib/guava-30.0.jar": make_zip({"x": b"1"}),
    })
    ear = make_zip({"lib/util-1.1.jar": make_zip({"META-INF/maven/o/util/pom.properties": pom_props("o", "util", "1.1")}),
                    "shop.war": war})
    comps, _ = parse_file("deploy/shop.ear", ear)
    p = {c.name: c for c in comps}
    assert p["o:util"].source_path == "deploy/shop.ear!/lib/util-1.1.jar"
    assert p["org.acme:shop"].source_path == "deploy/shop.ear!/shop.war"
    assert p["org.x:inner"].source_path == "deploy/shop.ear!/shop.war!/WEB-INF/lib/inner-1.0.jar"
    assert p["org.x:inner"].meta["parent"] == "deploy/shop.ear!/shop.war"
    assert p["guava"].meta["identified_by"] == "filename"


def test_nesting_depth_limit():
    data = make_zip({"META-INF/maven/o/leaf/pom.properties": pom_props("o", "leaf", "1")})
    for i in range(5):
        data = make_zip({f"lib/l{i}.jar": data})
    assert parse_file("a.jar", data)[0] == []          # leaf is 5 levels down
    data = make_zip({"META-INF/maven/o/leaf/pom.properties": pom_props("o", "leaf", "1")})
    for i in range(java.MAX_DEPTH):
        data = make_zip({f"lib/l{i}.jar": data})
    assert [c.name for c in parse_file("a.jar", data)[0]] == ["o:leaf"]


def _declare_size(zip_bytes: bytes, entry: str, size: int) -> bytes:
    """Forge the uncompressed size of one entry in the central directory (zip-bomb stand-in)."""
    b = bytearray(zip_bytes)
    pos = 0
    while (pos := b.find(b"PK\x01\x02", pos)) != -1:
        n = struct.unpack_from("<H", b, pos + 28)[0]
        if bytes(b[pos + 46:pos + 46 + n]).decode() == entry:
            struct.pack_into("<I", b, pos + 24, size)
        pos += 4
    return bytes(b)


def test_zip_bomb_archive_total_is_refused():
    data = _declare_size(make_zip({"big.bin": b"0" * 100, "META-INF/maven/o/a/pom.properties": pom_props("o", "a", "1")}),
                         "big.bin", 600 * 1024 * 1024)
    comps, warns = parse_file("bomb.jar", data)
    assert comps == [] and warns and "uncompressed" in warns[0]


def test_oversized_nested_entry_is_skipped_but_rest_survives():
    good = make_zip({"META-INF/maven/o/ok/pom.properties": pom_props("o", "ok", "1")})
    outer = make_zip({"BOOT-INF/lib/huge-1.jar": good, "BOOT-INF/lib/ok-1.jar": good,
                      "META-INF/maven/o/app/pom.properties": pom_props("o", "app", "1")})
    outer = _declare_size(outer, "BOOT-INF/lib/huge-1.jar", 200 * 1024 * 1024)
    comps, warns = parse_file("app.jar", outer)
    assert len(warns) == 1 and "huge-1.jar" in warns[0]
    assert {c.source_path for c in comps} == {"app.jar", "app.jar!/BOOT-INF/lib/ok-1.jar"}


def test_corrupt_zip_warns():
    comps, warns = parse_file("x.jar", b"PK\x03\x04" + b"garbage" * 10)
    assert comps == [] and warns and "BadZipFile" in warns[0]


def test_archive_registration_and_sniff():
    assert wants("opt/app/app.war") and wants("x/plugin.hpi") and wants("a.JAR")
    assert not wants("a.zip")
    names = [p.name for p in parsers_for("a.jar", b"PK\x03\x04rest")]
    assert "java-archive" in names
    assert "java-archive" not in [p.name for p in parsers_for("a.jar", b"\x7fELF")]
    p = next(p for p in parsers_for("a.jar", b"PK\x03\x04"))
    assert p.binary is True


# --------------------------------------------------------------------------- pom.xml
def test_pom_fixture_property_resolution():
    comps, warns = parse_file("pom.xml", (FX / "pom.xml").read_bytes())
    assert not warns
    p = by_purl(comps)
    assert "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" in p      # ${log4j.version}
    assert p["pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8"].meta["evidence"] == EV_MANIFEST
    assert len(comps) == 3


def test_pom_edge_cases():
    pom = b"""<project xmlns="http://maven.apache.org/POM/4.0.0">
      <parent><groupId>org.parent</groupId><artifactId>p</artifactId><version>5.0</version></parent>
      <artifactId>child</artifactId>
      <properties><a.ver>${b.ver}</a.ver><b.ver>1.2.3</b.ver></properties>
      <dependencyManagement><dependencies>
        <dependency><groupId>g</groupId><artifactId>managed</artifactId><version>9.9</version></dependency>
      </dependencies></dependencyManagement>
      <dependencies>
        <dependency><groupId>g</groupId><artifactId>nested-prop</artifactId><version>${a.ver}</version></dependency>
        <dependency><groupId>${project.parent.groupId}</groupId><artifactId>same-parent</artifactId><version>${project.version}</version></dependency>
        <dependency><groupId>g</groupId><artifactId>unmanaged</artifactId></dependency>
        <dependency><groupId>g</groupId><artifactId>unresolved</artifactId><version>${nope}</version></dependency>
        <dependency><groupId>g</groupId><artifactId>ranged</artifactId><version>[1.0,2.0)</version></dependency>
        <dependency><groupId>g</groupId><artifactId>t</artifactId><version>1</version><scope>test</scope></dependency>
        <dependency><groupId>g</groupId><artifactId>w</artifactId><version>1</version><type>war</type><classifier>x</classifier></dependency>
      </dependencies>
      <build><plugins><plugin><groupId>pl</groupId><artifactId>plug</artifactId><version>1</version>
        <dependencies><dependency><groupId>g</groupId><artifactId>plugdep</artifactId><version>1</version></dependency></dependencies>
      </plugin></plugins></build></project>"""
    comps, _ = parse_file("svc/pom.xml", pom)
    p = {c.name: c for c in comps}
    assert set(p) == {"g:nested-prop", "org.parent:same-parent", "g:t", "g:w"}
    assert p["g:nested-prop"].version == "1.2.3"
    assert p["org.parent:same-parent"].version == "5.0"       # project.version inherited from <parent>
    assert p["g:t"].meta["scope"] == "test"
    assert p["g:w"].purl == "pkg:maven/g/w@1?classifier=x&type=war"


# --------------------------------------------------------------------------- gradle
def test_gradle_lockfile_real():
    comps, warns = parse_file("gradle.lockfile", (FX / "gradle.lockfile").read_bytes())
    assert not warns and comps
    p = by_purl(comps)
    lb = p["pkg:maven/ch.qos.logback/logback-classic@1.5.15"]
    assert lb.meta["evidence"] == EV_LOCKFILE
    assert lb.meta["configurations"] == ["jmhRuntimeClasspath", "testRuntimeClasspath"]
    assert all(c.ecosystem == "Maven" and c.version for c in comps)


def test_gradle_lockfile_synthetic_variants():
    text = b"# comment\ng:a:1.0=compileClasspath,runtimeClasspath\ng:t:2.0=testCompileClasspath,testRuntimeClasspath\nempty=annotationProcessor\n"
    p = {c.name: c for c in parse_file("sub/gradle.lockfile", text)[0]}
    assert set(p) == {"g:a", "g:t"} and "scope" not in p["g:a"].meta and p["g:t"].meta["scope"] == "test"
    legacy = parse_file("gradle/dependency-locks/compileClasspath.lockfile", b"g:l:3.1\n")[0]
    assert legacy[0].meta["configurations"] == ["compileClasspath"]
    assert wants("buildscript-gradle.lockfile")


def test_gradle_verification_metadata_real():
    comps, warns = parse_file("gradle/verification-metadata.xml", (FX / "jmeter-verification-metadata.xml").read_bytes())
    assert not warns and len(comps) > 50
    assert all(c.meta["evidence"] == EV_LOCKFILE and c.purl.startswith("pkg:maven/") for c in comps)
    assert ":" in comps[0].name


# --------------------------------------------------------------------------- matching
@pytest.fixture
def osv_log4j(conn):
    assert import_record(conn, json.loads((OSV / "maven-GHSA-jfh8-c2jp-5v3q.json").read_text()))
    conn.commit()


def test_parsed_components_match_osv_maven(conn, osv_log4j):
    comps, _ = parse_file("app.jar", (FX / "springboot-app-0.1.0.jar").read_bytes())
    save_inventory(conn, Inventory(Asset("img1", "container-image", "demo"), "test", comps))
    match_asset(conn, "img1")
    rows = conn.execute("""SELECT c.name, c.version, f.vuln_id FROM finding f JOIN component c ON c.id=f.component_id
                           WHERE f.asset_id='img1'""").fetchall()
    assert [(r["name"], r["version"]) for r in rows] == [("org.apache.logging.log4j:log4j-core", "2.14.1")]
    # a fixed version is not reported
    fixed = java.parse_gradle_lockfile("gradle.lockfile", b"org.apache.logging.log4j:log4j-core:2.17.1=x\n")
    save_inventory(conn, Inventory(Asset("img2", "repo", "fixed"), "test", fixed))
    match_asset(conn, "img2")
    assert conn.execute("SELECT count(*) FROM finding WHERE asset_id='img2'").fetchone()[0] == 0


# --------------------------------------------------------------------------- review fixes
import zlib


@pytest.mark.parametrize("name,expected", [
    ("netty-transport-native-epoll-4.1.100.Final-linux-x86_64.jar", ("netty-transport-native-epoll", "4.1.100.Final")),
    ("shadow-demo-1.2.3-all.jar", ("shadow-demo", "1.2.3")),
    ("app-1.0-shaded.jar", ("app", "1.0")),
    ("app-1.0-jar-with-dependencies.jar", ("app", "1.0")),
    ("asm-9.5-no_aop.jar", ("asm", "9.5")),
    ("guice-5.1.0-jdk8.jar", ("guice", "5.1.0")),
    ("lib-2.0-osx-aarch_64.jar", ("lib", "2.0")),
    ("lib-2.0-windows-x86_64.jar", ("lib", "2.0")),
    ("lib-2.0-native.jar", ("lib", "2.0")),
    ("plain-1.0.0-beta.1.jar", ("plain", "1.0.0-beta.1")),       # real pre-release qualifier stays
])
def test_filename_classifiers_stripped_from_version(name, expected):
    assert java._filename_ga(name) == expected


def test_vendor_id_is_a_hint_unless_last_segment_is_the_artifact():
    mf = "Manifest-Version: 1.0\r\nImplementation-Version: 31.1\r\nImplementation-Vendor-Id: com.google.guava\r\n\r\n"
    (c,) = parse_file("guava-31.1.jar", make_zip({"META-INF/MANIFEST.MF": mf}))[0]
    assert c.purl == "pkg:maven/com.google.guava/guava@31.1" and c.meta["confidence"] == 0.7
    mf = ("Manifest-Version: 1.0\r\nImplementation-Version: 2.14.1\r\n"
          "Implementation-Vendor-Id: org.apache.logging.log4j\r\n\r\n")
    (c,) = parse_file("log4j-api-2.14.1.jar", make_zip({"META-INF/MANIFEST.MF": mf}))[0]
    assert c.purl == "pkg:maven/log4j-api@2.14.1"
    assert c.meta["needs_identification"] is True and c.meta["confidence"] == 0.4
    assert c.meta["vendor_id"] == "org.apache.logging.log4j"


def _corrupt_entry(data: bytes, name: str) -> bytes:
    """Overwrite the deflate payload of one entry (the central directory stays valid, so
    zipfile opens the archive but reading that entry raises zlib.error / BadZipFile)."""
    info = zipfile.ZipFile(io.BytesIO(data)).getinfo(name)
    # local header: 30 bytes + name + extra
    start = info.header_offset + 30 + len(info.filename.encode())
    buf = bytearray(data)
    buf[start:start + info.compress_size] = b"\xff" * info.compress_size
    return bytes(buf)


def test_corrupt_pom_properties_entry_keeps_the_other_components():
    """L4: one unreadable pom.properties (zlib.error ...) must not discard the rest."""
    entries = {"META-INF/maven/o/bad/pom.properties": pom_props("o", "bad", "1") * 20,
               "META-INF/maven/o/good/pom.properties": pom_props("o", "good", "2")}
    data = _corrupt_entry(make_zip(entries), "META-INF/maven/o/bad/pom.properties")
    with pytest.raises((zlib.error, zipfile.BadZipFile)):
        zipfile.ZipFile(io.BytesIO(data)).read("META-INF/maven/o/bad/pom.properties")
    comps, warns = parse_file("fat.jar", data)
    assert {c.purl for c in comps} == {"pkg:maven/o/good@2"}
    assert len(warns) == 1 and "bad/pom.properties" in warns[0]


def test_corrupt_nested_archive_entry_keeps_found_components():
    inner_ok = make_zip({"META-INF/maven/o/ok/pom.properties": pom_props("o", "ok", "1")})
    inner_bad = _corrupt_entry(make_zip({"META-INF/maven/o/x/pom.properties": pom_props("o", "x", "1") * 20}),
                               "META-INF/maven/o/x/pom.properties")
    outer = make_zip({"BOOT-INF/lib/ok-1.jar": inner_ok, "BOOT-INF/lib/bad-1.jar": inner_bad,
                      "BOOT-INF/lib/junk-1.jar": b"PK\x03\x04" + b"junk" * 50,
                      "META-INF/maven/o/app/pom.properties": pom_props("o", "app", "1")})
    comps, warns = parse_file("app.jar", outer)
    assert {c.purl for c in comps} >= {"pkg:maven/o/app@1", "pkg:maven/o/ok@1"}
    assert warns
