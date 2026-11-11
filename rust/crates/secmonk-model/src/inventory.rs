//! Inventory (`secmonk-inventory/1`): what a collector returns, and the items of the `collector.collect`
//! stream. Schemas: `rust/contracts/schemas/inventory/`. Python: `secmonk/models.py`.

use serde::{Deserialize, Serialize};

use crate::JsonMap;

/// Value of the `schema` key of an inventory document.
pub const INVENTORY_SCHEMA: &str = "secmonk-inventory/1";

/// Component category (`models.CATEGORIES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// The operating system itself.
    Os,
    /// A distro package (deb/rpm/apk).
    OsPackage,
    /// A language package (pypi, npm, maven, ...).
    Library,
    /// An end-user application.
    Application,
    /// An application shipped with the OS.
    SystemApp,
    /// A package-manager tool or formula.
    Package,
    /// An embedded runtime or framework.
    Runtime,
    /// A running binary without package identity (never matched).
    Executable,
}

impl Category {
    /// The wire string (`"os-package"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Os => "os",
            Category::OsPackage => "os-package",
            Category::Library => "library",
            Category::Application => "application",
            Category::SystemApp => "system-app",
            Category::Package => "package",
            Category::Runtime => "runtime",
            Category::Executable => "executable",
        }
    }
}

/// A target that was scanned (`models.Asset`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    /// Stable id with a collector prefix (`dir:/work/x`, `macos:<host>`, `image:<repo>@<digest>`).
    pub id: String,
    /// `desktop`, `server`, `container-image`, `container`, `repo`, `directory`, ...
    #[serde(rename = "type")]
    pub kind: String,
    /// Display name.
    pub name: String,
    /// Operating system name, when known.
    #[serde(default)]
    pub os_name: Option<String>,
    /// Operating system version, when known.
    #[serde(default)]
    pub os_version: Option<String>,
    /// `linux/amd64`, `darwin/arm64`, ...
    #[serde(default)]
    pub platform: Option<String>,
    /// Free-form facts (labels, image facts, process tree). Redacted by the collector.
    #[serde(default)]
    pub meta: JsonMap,
}

/// A piece of software found on an asset (`models.Component`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    /// Name as found.
    pub name: String,
    /// Version as found.
    pub version: Option<String>,
    /// Category.
    pub category: Category,
    /// Package URL, if any (also the component key).
    #[serde(default)]
    pub purl: Option<String>,
    /// CPE 2.3, if known (set by classify).
    #[serde(default)]
    pub cpe: Option<String>,
    /// Vendor, if known.
    #[serde(default)]
    pub vendor: Option<String>,
    /// OSV ecosystem used for matching.
    #[serde(default)]
    pub ecosystem: Option<String>,
    /// Where it was found on the target (extra locations: `meta.paths`).
    #[serde(default)]
    pub source_path: Option<String>,
    /// Identity facts (shared per key) and per-asset facts.
    #[serde(default)]
    pub meta: JsonMap,
}

impl Component {
    /// The stable component key (`Component.key` in Python): the purl if any, else
    /// `name:<category>/<vendor lowercase>/<name lowercase>@<version>`.
    pub fn key(&self) -> String {
        if let Some(p) = self.purl.as_deref().filter(|p| !p.is_empty()) {
            return p.to_string();
        }
        let vendor = self.vendor.as_deref().unwrap_or("").to_lowercase();
        format!(
            "name:{}/{}/{}@{}",
            self.category.as_str(),
            vendor,
            self.name.to_lowercase(),
            self.version.as_deref().unwrap_or("")
        )
    }

    /// A string value of `meta` (promoted columns: `product`, `product_source`, `bundle_id`).
    pub fn meta_str(&self, key: &str) -> Option<&str> {
        self.meta.get(key).and_then(|v| v.as_str())
    }
}

/// Output of a collector run (`models.Inventory`, plus the `schema` / `classified` keys of the contract).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    /// `secmonk-inventory/1`; absent in legacy `collect -O` files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// Whether `engine.classify` already ran; absent means legacy (= classified).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classified: Option<bool>,
    /// The scanned asset.
    pub asset: Asset,
    /// Collector name.
    pub collector: String,
    /// Components found.
    #[serde(default)]
    pub components: Vec<Component>,
    /// Collector warnings (shown to the user).
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Known to be incomplete: never the reference for removal.
    #[serde(default)]
    pub partial: bool,
    /// Why it is partial.
    #[serde(default)]
    pub partial_reason: Option<String>,
}

impl Inventory {
    /// Whether the components are classified (a document without `schema` is a legacy, classified file).
    pub fn is_classified(&self) -> bool {
        match (&self.schema, self.classified) {
            (None, _) => true,
            (Some(_), c) => c.unwrap_or(false),
        }
    }

    /// `Inventory.mark_partial`: set `partial` and append the reason.
    pub fn mark_partial(&mut self, reason: &str) {
        self.partial = true;
        self.partial_reason = Some(match self.partial_reason.take() {
            Some(prev) => format!("{prev}; {reason}"),
            None => reason.to_string(),
        });
    }
}

/// Params of `collector.collect` and `collector.expand_targets`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectParams {
    /// Collector name.
    pub collector: String,
    /// Target spec (`None` for host collectors).
    pub target: Option<String>,
    /// Raw `key=value` options, parsed by the module.
    #[serde(default)]
    pub options: Vec<String>,
}

/// Result of `collector.expand_targets`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpandResult {
    /// The targets to collect, one `collector.collect` each.
    pub targets: Vec<Option<String>>,
}

/// One item (`event.data`) of the `collector.collect` stream.
// One `Asset` item per stream and items are short-lived: boxing it would only make construction noisier.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum CollectItem {
    /// First item: the asset.
    Asset {
        /// `secmonk-inventory/1`.
        schema: String,
        /// Collector name.
        collector: String,
        /// Always `false` on the wire (classify runs in the engine).
        classified: bool,
        /// The asset.
        asset: Asset,
    },
    /// A chunk of at most 1000 components.
    Components {
        /// The components.
        components: Vec<Component>,
    },
    /// A collector warning.
    Warning {
        /// The message (at most 2000 chars).
        message: String,
    },
}

/// `end.result` of `collector.collect`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectEnd {
    /// The inventory is incomplete.
    pub partial: bool,
    /// Why.
    pub partial_reason: Option<String>,
    /// Number of components streamed.
    pub components: u64,
    /// Number of warnings streamed.
    pub warnings: u64,
}
