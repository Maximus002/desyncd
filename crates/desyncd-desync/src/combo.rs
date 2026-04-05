//! Combo technique: chain multiple desync techniques together.
//!
//! A combo applies techniques in sequence. Each technique transforms
//! the payload, and the result is fed into the next technique.
//!
//! For example: `[tls_record_frag, tcp_split]` first fragments at the
//! TLS record layer, then splits the result into TCP segments.
//!
//! Special handling for different DesyncAction types:
//! - `Replace` → next technique gets the new payload
//! - `Split` → each chunk can be further processed
//! - `InjectBefore` → fakes are prepended, next technique processes original
//! - `PassThrough` → try next technique on original

use crate::PayloadContext;
use crate::technique::TechniqueConfig;
use desyncd_types::{DesyncAction, Result, SplitPosition};
use tracing::debug;

/// Apply a chain of techniques in sequence.
///
/// Each technique is specified as (name, split_position).
/// Returns the combined result.
pub fn apply_chain(
    ctx: &PayloadContext,
    techniques: &[(&str, SplitPosition)],
) -> Result<DesyncAction> {
    if techniques.is_empty() {
        return Ok(DesyncAction::PassThrough);
    }

    let mut current_payload = ctx.payload.clone();
    let mut accumulated_prefix: Vec<Vec<u8>> = Vec::new();
    let mut final_split: Option<Vec<Vec<u8>>> = None;

    for (i, (name, split_pos)) in techniques.iter().enumerate() {
        let inner_ctx = PayloadContext::new(current_payload.clone());

        let config = TechniqueConfig {
            name: name.to_string(),
            split_position: Some(split_pos.clone()),
            enabled: true,
            fake_type: None,
            sni_mode: None,
            host_mode: None,
            stealth: None,
            l7_filter: None,
        };

        let action = match crate::apply_technique(name, &inner_ctx, split_pos, None, &config) {
            Ok(a) => a,
            Err(desyncd_types::Error::NotApplicable(_)) => {
                debug!(technique = name, step = i, "combo: technique not applicable, skipping");
                continue;
            }
            Err(e) => return Err(e),
        };

        match action {
            DesyncAction::PassThrough => {
                // No change, continue to next technique.
            }
            DesyncAction::Replace(new_data) => {
                debug!(technique = name, step = i, "combo: payload replaced");
                current_payload = new_data;
            }
            DesyncAction::Split(chunks) => {
                debug!(
                    technique = name,
                    step = i,
                    num_chunks = chunks.len(),
                    "combo: payload split"
                );
                if i == techniques.len() - 1 {
                    final_split = Some(chunks);
                } else {
                    current_payload = chunks.into_iter().flatten().collect();
                }
            }
            DesyncAction::InjectBefore(fakes) => {
                debug!(
                    technique = name,
                    step = i,
                    num_fakes = fakes.len(),
                    "combo: fakes injected"
                );
                accumulated_prefix.extend(fakes);
            }
        }
    }

    // Build final result.
    if !accumulated_prefix.is_empty() {
        if let Some(splits) = final_split {
            let mut all = accumulated_prefix;
            all.extend(splits);
            Ok(DesyncAction::Split(all))
        } else {
            Ok(DesyncAction::InjectBefore(accumulated_prefix))
        }
    } else if let Some(splits) = final_split {
        Ok(DesyncAction::Split(splits))
    } else if current_payload != ctx.payload {
        Ok(DesyncAction::Replace(current_payload))
    } else {
        Ok(DesyncAction::PassThrough)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_chain() {
        let payload = b"Hello".to_vec();
        let ctx = PayloadContext {
            protocol: desyncd_types::AppProtocol::Unknown,
            payload,
        };
        let result = apply_chain(&ctx, &[]).unwrap();
        assert!(matches!(result, DesyncAction::PassThrough));
    }

    #[test]
    fn test_single_technique_chain() {
        let payload = crate::testutil::build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply_chain(&ctx, &[("tcp_split", SplitPosition::Sni)]).unwrap();
        match result {
            DesyncAction::Split(chunks) => {
                assert_eq!(chunks.len(), 2);
                assert_eq!(chunks[0].len() + chunks[1].len(), payload.len());
            }
            _ => panic!("expected Split"),
        }
    }

    #[test]
    fn test_tls_frag_then_split() {
        let payload = crate::testutil::build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload);

        let result = apply_chain(
            &ctx,
            &[
                ("tls_record_frag", SplitPosition::Sni),
                ("tcp_split", SplitPosition::Absolute(20)),
            ],
        )
        .unwrap();

        match result {
            DesyncAction::Split(chunks) => {
                assert_eq!(chunks.len(), 2);
            }
            _ => panic!("expected Split from combo"),
        }
    }
}
