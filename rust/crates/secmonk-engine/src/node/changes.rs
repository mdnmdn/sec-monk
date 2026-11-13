//! One answer to "what changed -> which components" (proposal §3.3), used by both consumers of `match.changes`:
//! the mirror node's re-match after a sync (`sync_hooks`) and the state-only node's [`NodeMatcher`] poll.
//!
//! A component is **affected** by a `match.changes` answer when
//!
//! - one of its lookup keys is a changed key (`Changed.changed_keys`), or
//! - it has a match on a changed id (`Changed.changed_ids`, the caller knows its matches), or
//! - a source that answered `resync` covers it by **family**: `osv:<Eco>` -> components with a `pkg:<eco>/…` key,
//!   `osv` -> any `pkg:` key, `debian-tracker` -> `pkg:debian…` keys, `kev` / `epss` -> none (enrichment: no match
//!   set changes), any other source -> every component.
//!
//! A component's lookup keys are, by preference, the ones the match service stored with its answer
//! (`NodeCacheStore::stored_lookup_keys`), else [`component_lookup_keys`](super::component_lookup_keys) (a
//! component never answered; on a mirror node the service is this process, so both are the same function).
//!
//! [`NodeMatcher`]: super::NodeMatcher

use std::collections::{BTreeMap, BTreeSet};

use secmonk_model::node::SourceChanges;

/// Which components a `resync` of a source concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Family {
    /// Enrichment only (`kev`, `epss`): no match set changes; the facts of existing findings may.
    Enrichment,
    /// Components with a lookup key starting with one of these prefixes.
    Prefixes(Vec<String>),
    /// Every component.
    All,
}

/// The family of `source` (a base or a qualified source name).
pub fn family(source: &str) -> Family {
    match source.split_once(':') {
        Some(("osv", eco)) => Family::Prefixes(vec![format!("pkg:{}/", eco.to_lowercase())]),
        _ => match source {
            "kev" | "epss" => Family::Enrichment,
            "osv" => Family::Prefixes(vec!["pkg:".into()]),
            "debian-tracker" => Family::Prefixes(vec!["pkg:debian".into()]),
            _ => Family::All,
        },
    }
}

/// Whether a resync of `source` concerns a component with these lookup keys.
pub fn in_family(source: &str, keys: &[String]) -> bool {
    match family(source) {
        Family::Enrichment => false,
        Family::All => true,
        Family::Prefixes(p) => keys.iter().any(|k| p.iter().any(|p| k.starts_with(p))),
    }
}

/// A `match.changes` answer summed over its sources.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeSummary {
    /// Changed lookup keys (every `Changed` source).
    pub keys: BTreeSet<String>,
    /// Changed vulnerability ids (every `Changed` source).
    pub ids: BTreeSet<String>,
    /// Sources that answered `resync`, with the reason.
    pub resynced: Vec<(String, String)>,
    /// Sources that answered anything but `unchanged`.
    pub changed_sources: usize,
}

impl ChangeSummary {
    /// The summary of `sources` (`ChangesResponse::sources`).
    pub fn of(sources: &BTreeMap<String, SourceChanges>) -> ChangeSummary {
        let mut s = ChangeSummary::default();
        for (name, c) in sources {
            match c {
                SourceChanges::Unchanged => {}
                SourceChanges::Changed {
                    changed_keys,
                    changed_ids,
                } => {
                    s.changed_sources += 1;
                    s.keys.extend(changed_keys.iter().cloned());
                    s.ids.extend(changed_ids.iter().cloned());
                }
                SourceChanges::Resync(r) => {
                    s.changed_sources += 1;
                    s.resynced.push((name.clone(), r.clone()));
                }
            }
        }
        s
    }

    /// Nothing that can concern a component: no changed key or id, no resync.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.ids.is_empty() && self.resynced.is_empty()
    }

    /// Resynced sources whose family can change match sets (not `kev` / `epss`).
    pub fn match_resyncs(&self) -> impl Iterator<Item = &str> {
        self.resynced
            .iter()
            .map(|(s, _)| s.as_str())
            .filter(|s| family(s) != Family::Enrichment)
    }

    /// Whether an enrichment source (`kev`, `epss`) answered `resync`: the facts of every finding may have changed
    /// (no match set did).
    pub fn enrichment_resync(&self) -> bool {
        self.resynced
            .iter()
            .any(|(s, _)| family(s) == Family::Enrichment)
    }
}

/// The components (by component key) of `components` (component key -> its lookup keys) that `changes`
/// concerns; `with_changed_ids` are the components known to have a match on one of `changes.ids` (the caller
/// reads them from its findings or its match cache; they are returned when they are in `components`).
pub fn affected_components<'a, I>(
    changes: &ChangeSummary,
    components: I,
    with_changed_ids: &BTreeSet<String>,
) -> BTreeSet<String>
where
    I: IntoIterator<Item = (&'a String, &'a Vec<String>)>,
{
    let resyncs: Vec<&str> = changes.match_resyncs().collect();
    components
        .into_iter()
        .filter(|(key, lookup)| {
            with_changed_ids.contains(*key)
                || lookup.iter().any(|k| changes.keys.contains(k))
                || resyncs.iter().any(|s| in_family(s, lookup))
        })
        .map(|(key, _)| key.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn families_follow_the_proposal() {
        assert!(in_family("osv:PyPI", &v(&["pkg:pypi/requests"])));
        assert!(!in_family("osv:PyPI", &v(&["pkg:npm/x", "prod:requests"])));
        assert!(in_family("osv", &v(&["pkg:npm/x"])));
        assert!(!in_family("osv", &v(&["prod:x"])));
        assert!(in_family("debian-tracker", &v(&["pkg:debian:12/openssl"])));
        assert!(!in_family(
            "debian-tracker",
            &v(&["pkg:ubuntu:22.04/openssl"])
        ));
        assert!(!in_family("kev", &v(&["prod:x"])));
        assert!(!in_family("epss", &v(&["prod:x"])));
        assert!(in_family("nvd", &v(&["pkg:npm/x"])));
    }

    #[test]
    fn affected_components_by_key_id_and_family() {
        let changes = ChangeSummary::of(&BTreeMap::from([
            (
                "osv:npm".to_owned(),
                SourceChanges::Changed {
                    changed_keys: v(&["pkg:npm/left-pad"]),
                    changed_ids: v(&["GHSA-1"]),
                },
            ),
            (
                "osv:PyPI".to_owned(),
                SourceChanges::Resync("importer".into()),
            ),
            ("kev".to_owned(), SourceChanges::Resync("no diff".into())),
            ("nvd".to_owned(), SourceChanges::Unchanged),
        ]));
        assert_eq!(changes.changed_sources, 3);
        assert!(changes.enrichment_resync());
        assert_eq!(changes.match_resyncs().collect::<Vec<_>>(), ["osv:PyPI"]);
        let comps: BTreeMap<String, Vec<String>> = BTreeMap::from([
            ("a".to_owned(), v(&["pkg:npm/left-pad"])),
            ("b".to_owned(), v(&["pkg:pypi/requests"])),
            ("c".to_owned(), v(&["prod:firefox"])),
            ("d".to_owned(), v(&["pkg:npm/other"])),
        ]);
        let got = affected_components(&changes, &comps, &BTreeSet::from(["d".to_owned()]));
        assert_eq!(got, BTreeSet::from(["a".into(), "b".into(), "d".into()]));
        // an enrichment resync alone affects no component
        let only_kev = ChangeSummary::of(&BTreeMap::from([(
            "epss".to_owned(),
            SourceChanges::Resync("no diff".into()),
        )]));
        assert!(affected_components(&only_kev, &comps, &BTreeSet::new()).is_empty());
        assert!(!only_kev.is_empty());
        assert!(ChangeSummary::default().is_empty());
    }
}
