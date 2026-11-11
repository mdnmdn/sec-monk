//! Assemble a `collector.collect` stream into an [`Inventory`] with the ingest caps of
//! `rust/_docs/tech/contracts.md` (c).

use futures_util::StreamExt;

use crate::{CollectEnd, CollectItem, Inventory, ResultStream, StepResult, StreamMsg, WireError};

/// Ingest caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Components per inventory (500 000).
    pub max_components: usize,
    /// Warnings per inventory (1 000; more are dropped and counted).
    pub max_warnings: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            max_components: 500_000,
            max_warnings: 1_000,
        }
    }
}

/// Collect the stream into an unclassified inventory. Fails when the first item is not the asset, an asset
/// repeats, a cap is exceeded or the stream ends without `End`; the end summary's `partial` is applied.
pub async fn assemble(
    mut stream: ResultStream<CollectItem, CollectEnd>,
    caps: Caps,
) -> StepResult<Inventory> {
    let mut inv: Option<Inventory> = None;
    let mut dropped_warnings = 0usize;
    while let Some(msg) = stream.next().await {
        match msg? {
            StreamMsg::Item(CollectItem::Asset {
                schema,
                collector,
                asset,
                ..
            }) => {
                if inv.is_some() {
                    return Err(WireError::protocol("collect stream: second asset item"));
                }
                inv = Some(Inventory {
                    schema: Some(schema),
                    classified: Some(false),
                    asset,
                    collector,
                    components: Vec::new(),
                    warnings: Vec::new(),
                    partial: false,
                    partial_reason: None,
                });
            }
            StreamMsg::Item(CollectItem::Components { components }) => {
                let inv = inv.as_mut().ok_or_else(|| {
                    WireError::protocol("collect stream: components before asset")
                })?;
                if inv.components.len() + components.len() > caps.max_components {
                    return Err(WireError::invalid_params(format!(
                        "inventory exceeds {} components",
                        caps.max_components
                    )));
                }
                inv.components.extend(components);
            }
            StreamMsg::Item(CollectItem::Warning { message }) => {
                let inv = inv
                    .as_mut()
                    .ok_or_else(|| WireError::protocol("collect stream: warning before asset"))?;
                if inv.warnings.len() < caps.max_warnings {
                    inv.warnings.push(message);
                } else {
                    dropped_warnings += 1;
                }
            }
            StreamMsg::End(end) => {
                let mut inv = inv
                    .ok_or_else(|| WireError::protocol("collect stream ended without an asset"))?;
                if end.partial {
                    inv.mark_partial(end.partial_reason.as_deref().unwrap_or("partial"));
                }
                if dropped_warnings > 0 {
                    inv.warnings
                        .push(format!("{dropped_warnings} more warnings dropped"));
                }
                return Ok(inv);
            }
        }
    }
    Err(WireError::protocol("collect stream ended without end"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secmonk_model::{Asset, Category, Component};

    fn asset() -> CollectItem {
        CollectItem::Asset {
            schema: "secmonk-inventory/1".into(),
            collector: "fs".into(),
            classified: false,
            asset: Asset {
                id: "dir:/x".into(),
                kind: "directory".into(),
                name: "x".into(),
                os_name: None,
                os_version: None,
                platform: None,
                meta: Default::default(),
            },
        }
    }

    fn comp(n: &str) -> Component {
        Component {
            name: n.into(),
            version: Some("1".into()),
            category: Category::Library,
            purl: None,
            cpe: None,
            vendor: None,
            ecosystem: None,
            source_path: None,
            meta: Default::default(),
        }
    }

    fn stream(
        items: Vec<StepResult<StreamMsg<CollectItem, CollectEnd>>>,
    ) -> ResultStream<CollectItem, CollectEnd> {
        Box::pin(futures_util::stream::iter(items))
    }

    fn end(partial: bool) -> CollectEnd {
        CollectEnd {
            partial,
            partial_reason: partial.then(|| "aborted".into()),
            components: 2,
            warnings: 0,
        }
    }

    #[tokio::test]
    async fn assembles_and_marks_partial() {
        let s = stream(vec![
            Ok(StreamMsg::Item(asset())),
            Ok(StreamMsg::Item(CollectItem::Components {
                components: vec![comp("a"), comp("b")],
            })),
            Ok(StreamMsg::Item(CollectItem::Warning {
                message: "w".into(),
            })),
            Ok(StreamMsg::End(end(true))),
        ]);
        let inv = assemble(s, Caps::default()).await.unwrap();
        assert_eq!(inv.components.len(), 2);
        assert!(inv.partial);
        assert_eq!(inv.partial_reason.as_deref(), Some("aborted"));
        assert!(!inv.is_classified());
    }

    #[tokio::test]
    async fn rejects_bad_streams() {
        let no_asset = stream(vec![Ok(StreamMsg::Item(CollectItem::Components {
            components: vec![comp("a")],
        }))]);
        assert!(assemble(no_asset, Caps::default()).await.is_err());
        let no_end = stream(vec![Ok(StreamMsg::Item(asset()))]);
        assert!(assemble(no_end, Caps::default()).await.is_err());
        let too_many = stream(vec![
            Ok(StreamMsg::Item(asset())),
            Ok(StreamMsg::Item(CollectItem::Components {
                components: vec![comp("a"), comp("b")],
            })),
            Ok(StreamMsg::End(end(false))),
        ]);
        let caps = Caps {
            max_components: 1,
            max_warnings: 1,
        };
        assert_eq!(
            assemble(too_many, caps).await.unwrap_err().code,
            crate::ErrorCode::InvalidParams
        );
    }
}
