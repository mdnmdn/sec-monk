//! Mirror-node services in process (proposal `_docs/inbox/2026-11-12-mirror-nodes-feed-match-service.md` §3-4,
//! brief `rust/_docs/plans/node-server-design.md` §6; `rust/_docs/tech/engine-service.md` "Node services").
//!
//! - [`component_lookup_keys`]: the `pkg:` / `prod:` keys of a component (a superset of what the matcher reads);
//! - [`LocalNode`]: `MatchService`, `VulnInfo` and `Feed` of a node with a mirror, over the mirror's
//!   `MirrorNodeStore`, the engine's `Matcher` (an ephemeral match of a synthetic inventory, regrouped per component
//!   key) and its `Reporter`;
//! - [`NodeMatcher`]: the `Matcher` of a state-only node, over a (remote) `MatchService` and `VulnInfo`, the state's
//!   node cache and the version oracle's `scoring.priority`;
//! - [`CachedVulnInfo`]: `VulnInfo` over the state's node cache, the (remote) service on a miss;
//! - [`affected_components`]: which components a `match.changes` answer concerns (both consumers use it);
//! - [`matcher_version`] / [`default_importer_module`]: the versions of this build (`versions`).
//!
//! The engine's sync job records each source's served version after a complete run and re-matches the stored assets
//! a sync affected (`sync_hooks`).

mod cached_info;
mod changes;
mod keys;
mod local;
mod matcher;
pub(crate) mod sync_hooks;
mod versions;

pub use cached_info::CachedVulnInfo;
pub use changes::{ChangeSummary, Family, affected_components, family, in_family};
pub use keys::{KEYS_VERSION, component_lookup_keys};
pub use local::{
    CHANGES_LIMIT, DEFAULT_MATCH_CONCURRENCY, DIFF_UNKNOWN_KEY, FEED_DEFAULT_LIMIT, FEED_MAX_LIMIT,
    LocalNode, LocalNodeSettings, MATCH_ASSET_ID, MATCH_PERMIT_WAIT,
};
pub use matcher::{NodeMatcher, PollStats, SYNC_AS_OF, SYNC_EPOCH, SYNC_LOCAL, SYNC_RESYNC};
pub use sync_hooks::{DEFAULT_IMPORTER_NATIVE, SNAPSHOT_DIFF_MAX_ROWS};
pub use versions::{default_importer_module, matcher_version, secmonk_version};

/// Most finding rows one match returns in its view (`view_limit`, py-engine's bound): `LocalNode` asks for this
/// many per ephemeral match, `NodeMatcher` refuses more.
pub const MAX_VIEW_LIMIT: u32 = 5_000;
