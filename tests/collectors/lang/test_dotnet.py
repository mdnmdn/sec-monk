"""NuGet parsers. Fixtures in tests/fixtures/lang/dotnet/ are real files from public repos
(see _docs/references/package-formats/dotnet.md); the csproj variants here are inline synthetic XML."""

from __future__ import annotations

import json
from pathlib import Path

from secmonk.collectors.lang import REGISTRY, parse_file, parsers_for, wants
from secmonk.collectors.lang.base import EV_INSTALLED, EV_LOCKFILE, EV_MANIFEST
from secmonk.engine import purl as purls
from secmonk.engine.inventory import save_inventory
from secmonk.engine.match import match_asset
from secmonk.models import Asset, Inventory
from secmonk.sources.osv import import_record

FX = Path(__file__).parents[2] / "fixtures" / "lang" / "dotnet"


def fx(name: str) -> bytes:
    return (FX / name).read_bytes()


def by_name(comps):
    return {c.name: c for c in comps}


# --------------------------------------------------------------------------- deps.json
def test_deps_json_package_vs_project():
    comps, warns = parse_file("app/Loader.deps.json", fx("published-loader.deps.json"))
    assert not warns
    p = by_name(comps)
    assert "Loader" not in p                                   # type "project" is the app itself
    assert p["Newtonsoft.Json"].version == "13.0.3"
    assert p["Newtonsoft.Json"].purl == "pkg:nuget/Newtonsoft.Json@13.0.3" and p["Newtonsoft.Json"].ecosystem == "NuGet"
    assert p["Newtonsoft.Json"].meta["evidence"] == EV_INSTALLED
    assert p["Newtonsoft.Json"].meta["runtime_target"] == ".NETCoreApp,Version=v8.0/win-x64"
    assert len(comps) == 110


def test_deps_json_self_contained_runtimepack():
    doc = {"runtimeTarget": {"name": ".NETCoreApp,Version=v8.0/linux-musl-x64"},
           "targets": {".NETCoreApp,Version=v8.0/linux-musl-x64": {
               "App/1.0.0": {"dependencies": {"Serilog": "3.1.1"}},
               "Serilog/3.1.1": {},
               "runtimepack.Microsoft.NETCore.App.Runtime.linux-musl-x64/8.0.4": {}}},
           "libraries": {"App/1.0.0": {"type": "project"}, "Serilog/3.1.1": {"type": "package"},
                         "runtimepack.Microsoft.NETCore.App.Runtime.linux-musl-x64/8.0.4": {"type": "runtimepack"},
                         "Ref/1.0.0": {"type": "reference"}}}
    p = by_name(parse_file("x.deps.json", json.dumps(doc).encode())[0])
    assert set(p) == {"Serilog", "Microsoft.NETCore.App.Runtime.linux-musl-x64"}
    rt = p["Microsoft.NETCore.App.Runtime.linux-musl-x64"]
    assert rt.purl == "pkg:nuget/Microsoft.NETCore.App.Runtime.linux-musl-x64@8.0.4" and rt.meta["runtime"] is True
    assert "runtime" not in p["Serilog"].meta


def test_shared_framework_deps_json_is_the_runtime_component():
    path = "usr/share/dotnet/shared/Microsoft.NETCore.App/6.0.1/Microsoft.NETCore.App.deps.json"
    (c,) = parse_file(path, fx("shared-Microsoft.NETCore.App.6.0.1.deps.json"))[0]
    assert c.purl == "pkg:nuget/Microsoft.NETCore.App.Runtime.linux-x64@6.0.1"
    assert c.meta["runtime"] is True and c.source_path == path


def test_aspnetcore_runtime_name_flagged():
    doc = {"libraries": {"Microsoft.AspNetCore.App.Runtime.linux-arm64/8.0.2": {"type": "package"}}}
    (c,) = parse_file("Microsoft.AspNetCore.App.deps.json", json.dumps(doc).encode())[0]
    assert c.meta["runtime"] is True


# --------------------------------------------------------------------------- lock / assets / config
def test_packages_lock_direct_transitive_project():
    comps, _ = parse_file("packages.lock.json", fx("packages.lock.json"))
    p = by_name(comps)
    assert p["coverlet.MTP"].meta["direct"] is True and p["coverlet.MTP"].version == "10.1.0"
    assert p["coverlet.MTP"].meta["evidence"] == EV_LOCKFILE
    assert sorted(p["coverlet.MTP"].meta["tfms"]) == ["net10.0", "net8.0", "net9.0"]
    assert any(c.meta["direct"] is False for c in comps)               # transitive entries kept
    raw = json.loads(fx("packages.lock.json"))
    projects = {n for t in raw["dependencies"].values() for n, i in t.items() if i["type"] == "Project"}
    assert projects and not projects & set(p)                          # Project entries skipped
    assert len(comps) == 94


def test_packages_lock_legacy_any_tfm():
    comps = parse_file("a/packages.lock.json", fx("legacy-cronos.packages.lock.json"))[0]
    assert {(c.name, c.version) for c in comps} == {("Hangfire.Build", "0.6.0"), ("psake", "4.4.1")}


def test_project_assets_json():
    comps, _ = parse_file("obj/project.assets.json", fx("project.assets.json"))
    p = by_name(comps)
    assert p["Accelergreat.EntityFramework.PostgreSql"].meta["direct"] is True
    assert p["Accelergreat"].meta["direct"] is False
    assert len(comps) == 82 and all(c.meta["evidence"] == EV_LOCKFILE for c in comps)
    assert parse_file("obj/project.assets.json", b'{"version":3,"libraries":{"P/1.0.0":{"type":"project"}}}')[0] == []


def test_packages_config_with_bom():
    comps, warns = parse_file("packages.config", fx("packages.config"))
    assert not warns
    assert {(c.name, c.version) for c in comps} >= {("NPOI", "2.5.1"), ("SharpZipLib", "1.2.0")}
    assert comps[0].meta["tfm"] == "net472"
    legacy = parse_file("web/packages.config", fx("small.packages.config"))[0]
    assert [(c.name, c.version) for c in legacy] == [("MicroBuild.Core", "0.3.0"), ("xunit.runner.console", "2.9.0")]


# --------------------------------------------------------------------------- project files
CSPROJ = b"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework><SerilogVersion>3.1.1</SerilogVersion></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Child.Version"><Version>1.2.0</Version></PackageReference>
    <PackageReference Include="Serilog" Version="$(SerilogVersion)" />
    <PackageReference Include="Exact.Bracket" Version="[2.0.1]" />
    <PackageReference Include="Floating" Version="1.*" />
    <PackageReference Include="Floating.Pre" Version="1.0.0-*" />
    <PackageReference Include="Ranged" Version="[1.0,2.0)" />
    <PackageReference Include="Open.Range" Version="1.0" />
    <PackageReference Include="Unresolved" Version="$(NotDefined)" />
    <PackageReference Include="Central.Managed" />
    <PackageReference Include="Analyzer.Dev" Version="4.0.0" PrivateAssets="all" />
    <PackageReference Update="Override.Me" Version="7.7.7" />
    <ProjectReference Include="..\\Other\\Other.csproj" />
  </ItemGroup>
</Project>"""


def test_csproj_variants():
    comps, warns = parse_file("src/App/App.csproj", CSPROJ)
    assert not warns
    p = by_name(comps)
    assert {n: c.version for n, c in p.items()} == {
        "Newtonsoft.Json": "13.0.3", "Child.Version": "1.2.0", "Serilog": "3.1.1",
        "Exact.Bracket": "2.0.1", "Open.Range": "1.0", "Analyzer.Dev": "4.0.0", "Override.Me": "7.7.7"}
    # note: Open.Range "1.0" means ">= 1.0" to NuGet; it is a literal minimum, kept (lowest version restored)
    assert p["Newtonsoft.Json"].meta["evidence"] == EV_MANIFEST
    assert p["Analyzer.Dev"].meta["development"] is True
    assert wants("a/b.fsproj") and wants("x.vbproj") and wants("Directory.Build.props")


def test_real_eshop_csproj_with_central_versions_yields_nothing():
    for f in ("Catalog.API.csproj", "Basket.API.csproj"):
        assert parse_file(f, fx(f))[0] == []           # versions live in Directory.Packages.props


def test_directory_packages_props_real():
    comps, warns = parse_file("Directory.Packages.props", fx("Directory.Packages.props"))
    assert not warns and len(comps) == 70
    p = by_name(comps)
    assert p["Aspire.Hosting.PostgreSQL"].version == "13.6.0"
    assert p["Aspire.Hosting.PostgreSQL"].meta["central"] is True and p["Aspire.Hosting.PostgreSQL"].meta["declared_only"] is True
    assert [x.name for x in parsers_for("Directory.Packages.props")] == ["dotnet-central-packages"]


def test_central_props_with_properties_and_pre_release():
    xml = b"""<Project><PropertyGroup><V>6.0.2</V></PropertyGroup><ItemGroup>
      <PackageVersion Include="A" Version="$(V)" /><PackageVersion Include="B" Version="1.0.0-beta.2" />
      <GlobalPackageReference Include="StyleCop.Analyzers" Version="1.2.0-beta.556" /></ItemGroup></Project>"""
    assert {(c.name, c.version) for c in parse_file("Directory.Packages.props", xml)[0]} == {
        ("A", "6.0.2"), ("B", "1.0.0-beta.2"), ("StyleCop.Analyzers", "1.2.0-beta.556")}


# --------------------------------------------------------------------------- purl case / matching
def test_purl_keeps_case_and_engine_lowercases():
    (c,) = parse_file("x.deps.json", json.dumps({"libraries": {"Newtonsoft.Json/13.0.3": {"type": "package"}}}).encode())[0]
    assert c.purl == "pkg:nuget/Newtonsoft.Json@13.0.3"
    assert purls.normalize_name(c.ecosystem, c.name) == "newtonsoft.json"


def _save(conn, asset_id, comps):
    save_inventory(conn, Inventory(Asset(asset_id, "container-image", asset_id), "test", comps))
    match_asset(conn, asset_id)
    return conn.execute("""SELECT c.name, c.version FROM finding f JOIN component c ON c.id=f.component_id
                           WHERE f.asset_id=?""", (asset_id,)).fetchall()


def test_nuget_library_matches_osv(conn):
    import_record(conn, json.loads(fx("osv-nuget-GHSA-5crp-9r3c-p9vr.json")))      # Newtonsoft.Json < 13.0.1
    conn.commit()
    comps = parse_file("a.deps.json", json.dumps({"libraries": {"Newtonsoft.Json/12.0.3": {"type": "package"},
                                                                "Serilog/3.1.1": {"type": "package"}}}).encode())[0]
    assert [(r["name"], r["version"]) for r in _save(conn, "a", comps)] == [("Newtonsoft.Json", "12.0.3")]
    fixed = parse_file("packages.config", b'<packages><package id="newtonsoft.json" version="13.0.3"/></packages>')[0]
    assert _save(conn, "b", fixed) == []


def test_runtime_component_matches_osv_runtime_pack(conn):
    import_record(conn, json.loads(fx("osv-nuget-GHSA-555c-2p6r-68mm.json")))      # Microsoft.NETCore.App.Runtime.*
    conn.commit()
    comps = parse_file("dotnet/shared/Microsoft.NETCore.App/6.0.1/Microsoft.NETCore.App.deps.json",
                       fx("shared-Microsoft.NETCore.App.6.0.1.deps.json"))[0]
    rows = _save(conn, "img", comps)
    assert [(r["name"], r["version"]) for r in rows] == [("Microsoft.NETCore.App.Runtime.linux-x64", "6.0.1")]


def test_module_exports():
    assert {p.name for p in REGISTRY if p.ecosystem == "NuGet"} >= {
        "dotnet-deps-json", "dotnet-packages-lock", "dotnet-project-assets", "dotnet-packages-config",
        "dotnet-project-file", "dotnet-central-packages"}
