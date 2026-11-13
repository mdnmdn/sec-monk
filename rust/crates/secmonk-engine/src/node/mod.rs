//! Mirror-node services in process (proposal `_docs/inbox/2026-11-12-mirror-nodes-feed-match-service.md` §3-4,
//! brief `rust/_docs/plans/node-server-design.md` §6; `rust/_docs/tech/engine-service.md` "Node services").
//!
//! - [`component_lookup_keys`]: the `pkg:` / `prod:` keys of a component (a superset of what the matcher reads);
//! - [`LocalNode`]: `MatchService`, `VulnInfo` and `Feed` of a node with a mirror, over the mirror's
//!   `MirrorNodeStore`, the engine's `Matcher` (an ephemeral match of a synthetic inventory, regrouped per component
//!   key) and its `Reporter`;
//! - [`NodeMatcher`]: the `Matcher` of a state-only node, over a (remote) `MatchService` and `VulnInfo`, the state's
//!   node cache and the version oracle's `scoring.priority`.
//!
//! The engine's sync job records each source's served version after a complete run and re-matches the stored assets
//! a sync affected (`sync_hooks`).

mod keys;
mod local;
mod matcher;
pub(crate) mod sync_hooks;

pub use keys::component_lookup_keys;
pub use local::{
    CHANGES_LIMIT, DIFF_UNKNOWN_KEY, FEED_DEFAULT_LIMIT, FEED_MAX_LIMIT, LocalNode,
    LocalNodeSettings, MATCH_ASSET_ID,
};
pub use matcher::{NodeMatcher, PollStats, SYNC_AS_OF, SYNC_EPOCH, SYNC_RESYNC};
pub use sync_hooks::{DEFAULT_IMPORTER_MODULE, DEFAULT_IMPORTER_NATIVE, SNAPSHOT_DIFF_MAX_ROWS};
