use crate::settings::Settings;
use anyhow::anyhow;
use log::{debug, error, info, warn};
use nostr_relay_pool::prelude::*;
use nostr_sdk::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::{self, JoinHandle};

/// Constant for the Nostr event kind used for group membership (NIP-29).
const GROUP_MEMBERSHIP_KIND: Kind = Kind::Custom(39002);

/// Constant for the Nostr event kind used for group admins (NIP-29).
const GROUP_ADMINS_KIND: Kind = Kind::Custom(39001);

/// Default timeout duration for fetching events from the relay.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Represents the role of a public key within a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupRole {
    Member,
    Admin,
}

/// Caches the state of NIP-29 groups.
#[derive(Default)]
pub struct GroupStateCache {
    /// Maps Group ID (d tag) -> (PubKey Hex -> Role)
    cache: HashMap<String, HashMap<String, GroupRole>>,
}

impl GroupStateCache {
    fn new() -> Self {
        Default::default()
    }

    fn update_role(&mut self, group_id: &str, pubkey_hex: &str, role: GroupRole) {
        self.cache
            .entry(group_id.to_string())
            .or_default()
            .insert(pubkey_hex.to_string(), role);
    }

    fn get_role(&self, group_id: &str, pubkey_hex: &str) -> Option<GroupRole> {
        self.cache
            .get(group_id)
            .and_then(|group| group.get(pubkey_hex))
            .copied()
    }

    fn get_admins(&self, group_id: &str) -> HashSet<String> {
        self.cache
            .get(group_id)
            .map(|group| {
                group
                    .iter()
                    .filter(|(_, role)| **role == GroupRole::Admin)
                    .map(|(pk, _)| pk.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Processes the tags of a NIP-29 event to extract the group ID and member pubkeys.
fn process_event_tags(event: &Event) -> Option<(String, HashSet<PublicKey>)> {
    let group_id = event.tags.iter().find_map(|tag| {
        let slice = tag.as_slice();
        if slice.len() >= 2 && slice[0] == "d" {
            Some(slice[1].clone())
        } else {
            None
        }
    })?;

    let members = event
        .tags
        .iter()
        .filter_map(|tag| {
            let slice = tag.as_slice();
            if slice.len() >= 2 && slice[0] == "p" {
                PublicKey::from_hex(&slice[1]).ok()
            } else {
                None
            }
        })
        .collect::<HashSet<PublicKey>>();

    if members.is_empty() {
        None // Need at least one member tag
    } else {
        Some((group_id, members))
    }
}

/// Updates the cache based on a single NIP-29 event.
async fn update_cache_entry(event: &Event, cache: &mut GroupStateCache, relay_pubkey: &PublicKey) {
    // Ensure the event author matches the relay's pubkey
    if event.pubkey != *relay_pubkey {
        warn!(
            "Ignoring NIP-29 event {} from wrong author: {}",
            event.id,
            event.pubkey.to_hex()
        );
        return;
    }

    if let Some((group_id, members)) = process_event_tags(event) {
        let role = match event.kind {
            kind if kind == GROUP_ADMINS_KIND => GroupRole::Admin,
            kind if kind == GROUP_MEMBERSHIP_KIND => GroupRole::Member,
            _ => return, // Ignore other kinds
        };

        // Add a minimal log message for the update
        debug!(
            "NIP-29 Cache updated: Group='{}' via event {}",
            group_id, event.id
        );

        // Apply the update to the cache
        for member_pk in members {
            // Still need to iterate over the original HashSet
            cache.update_role(&group_id, &member_pk.to_hex(), role);
        }
    } else {
        warn!(
            "Could not process tags for NIP-29 event {}: Missing 'd' or 'p' tags?",
            event.id
        );
    }
}

/// Client for interacting with NIP-29 group information, primarily through a cache
/// updated by a background task.
pub struct Nip29Client {
    cache: Arc<RwLock<GroupStateCache>>,
}

impl Nip29Client {
    /// Determines if a public key is a member of a specified group by checking the cache.
    pub async fn is_group_member(&self, group_id: &str, pubkey: &PublicKey) -> bool {
        let cache = self.cache.read().await;
        cache
            .get_role(group_id, &pubkey.to_hex())
            .map_or(false, |role| {
                role == GroupRole::Member || role == GroupRole::Admin
            })
    }

    /// Determines if a public key is an admin of a specified group by checking the cache.
    pub async fn is_group_admin(&self, group_id: &str, pubkey: &PublicKey) -> bool {
        let cache = self.cache.read().await;
        cache
            .get_role(group_id, &pubkey.to_hex())
            .map_or(false, |role| role == GroupRole::Admin)
    }

    // Helper to get admin set (if needed elsewhere)
    pub async fn get_group_admins(&self, group_id: &str) -> HashSet<String> {
        let cache = self.cache.read().await;
        cache.get_admins(group_id)
    }
}

/// Initializes the NIP-29 client, populates the initial cache, and starts the background task.
///
/// Returns both the client handle (for cache access) and the background task JoinHandle.
pub async fn init_nip29_client(
    settings: &Settings,
    keys: Keys,
) -> anyhow::Result<(Arc<Nip29Client>, JoinHandle<()>)> {
    let relay_url = settings.nip29_relay.url.clone();
    let relay_pubkey = keys.public_key();

    info!("Initializing NIP-29 client for relay: {}", relay_url);
    info!("NIP-29 Relay PubKey: {}", relay_pubkey.to_hex());

    let opts = Options::default();
    let client = Client::builder().signer(keys.clone()).opts(opts).build();

    if let Err(e) = client.add_relay(relay_url.clone()).await {
        return Err(anyhow!("Failed to add NIP-29 relay {}: {}", relay_url, e));
    }
    client.connect().await;

    let cache = Arc::new(RwLock::new(GroupStateCache::new()));

    let initial_filter = Filter::new()
        .author(relay_pubkey)
        .kinds(vec![GROUP_ADMINS_KIND, GROUP_MEMBERSHIP_KIND]);

    info!("Fetching initial NIP-29 events via pagination...");
    const INITIAL_PAGE_SIZE: u64 = 200;
    match fetch_paginated_events_from(
        &client,
        initial_filter.clone(),
        INITIAL_PAGE_SIZE,
        FETCH_TIMEOUT,
    )
    .await
    {
        Ok(events) => {
            info!("Fetched {} initial NIP-29 events", events.len());
            let mut cache_writer = cache.write().await;
            for event in events {
                update_cache_entry(&event, &mut cache_writer, &relay_pubkey).await;
            }

            // Log the cache state directly using the write lock guard
            // before it's released.
            info!(
                "NIP-29 Cache state after initial load ({} groups):",
                cache_writer.cache.len()
            );
            for (group_id, members) in cache_writer.cache.iter() {
                info!("  Group: {}", group_id);
                let mut admins = Vec::new();
                let mut regular_members = Vec::new();

                for (pubkey, role) in members.iter() {
                    match role {
                        GroupRole::Admin => admins.push(pubkey.as_str()),
                        GroupRole::Member => regular_members.push(pubkey.as_str()),
                    }
                }

                if !admins.is_empty() {
                    info!("    Admins: {}", admins.join(", "));
                }
                if !regular_members.is_empty() {
                    info!("    Members: {}", regular_members.join(", "));
                }
            }
            // Write lock (`cache_writer`) is released when it goes out of scope here
        }
        Err(e) => {
            warn!(
                "Error during paginated fetch of initial NIP-29 events from {}: {}. Cache might be incomplete.",
                relay_url, e
            );
            // Note: Continue initialization even if fetch fails, the cache will just be empty/incomplete.
        }
    }

    // Spawn background task to listen for updates
    let background_client = client.clone();
    let background_cache = cache.clone();
    let background_relay_url = relay_url.clone();

    let join_handle: JoinHandle<()> = task::spawn(async move {
        info!(
            "Starting NIP-29 background notification handler for {}...",
            background_relay_url
        );

        // Subscribe to future updates
        let sub_opts = SubscribeAutoCloseOptions::default();
        let subscription_filter = Filter::new()
            .author(relay_pubkey)
            .kinds(vec![GROUP_ADMINS_KIND, GROUP_MEMBERSHIP_KIND]);

        if let Err(e) = background_client
            .subscribe_to(
                vec![background_relay_url.clone()],
                subscription_filter,
                Some(sub_opts),
            )
            .await
        {
            error!(
                "Failed to subscribe to NIP-29 updates on {}: {}",
                background_relay_url, e
            );
            return;
        }
        info!("Subscribed to NIP-29 updates on {}.", background_relay_url);

        // Handle notifications (rest of the handler remains the same)
        if let Err(e) = background_client
            .handle_notifications(|notification| {
                let cache_clone = background_cache.clone();
                let relay_pk = relay_pubkey;

                async move {
                    match notification {
                        RelayPoolNotification::Event { event, .. } => {
                            if event.kind == GROUP_ADMINS_KIND
                                || event.kind == GROUP_MEMBERSHIP_KIND
                            {
                                debug!(
                                    "Received NIP-29 update event: kind={}, id={}",
                                    event.kind, event.id
                                );
                                let mut cache_writer = cache_clone.write().await;
                                update_cache_entry(&event, &mut cache_writer, &relay_pk).await;
                            }
                        }
                        RelayPoolNotification::Shutdown => {
                            info!("NIP-29 notification handler received shutdown signal.");
                            return Ok(true);
                        }
                        _ => {}
                    }
                    Ok(false)
                }
            })
            .await
        {
            error!("NIP-29 notification handler error: {}", e);
        }
        info!(
            "NIP-29 background notification handler finished for {}.",
            background_relay_url
        );
    });

    let nip29_client_instance = Nip29Client { cache };

    info!("NIP-29 client initialized successfully.");
    Ok((Arc::new(nip29_client_instance), join_handle))
}

/// Fetches events from the client's connected relays, handling pagination automatically.
///
/// This function repeatedly queries the client's relays for events matching
/// the `initial_filter`, fetching them in batches (`page_size`). It continues
/// fetching older batches until no more events are returned, effectively
/// retrieving all historical events matching the filter from those relays.
///
/// # Arguments
/// * `client` - The nostr_sdk Client instance.
/// * `initial_filter` - The base filter specifying the desired events (kinds, authors, tags, etc.).
///                      Do **not** set `limit` or `until` on this filter; the function manages them.
/// * `page_size` - The number of events to request per batch (relay `limit`).
/// * `timeout_per_page` - The timeout duration to wait for each individual page request.
///
/// # Returns
/// * `Result<Events, Error>` - On success, returns a `Events` struct containing all
///                             fetched, sorted, and deduplicated events. On failure, returns
///                             a `nostr_sdk::client::Error`.
pub async fn fetch_paginated_events_from(
    client: &Client,
    initial_filter: Filter,
    page_size: u64,
    timeout_per_page: Duration,
) -> Result<Events, Error> {
    debug!(
        "Starting paginated fetch with filter: {:?}, page_size: {}, timeout: {:?}",
        initial_filter, page_size, timeout_per_page
    );

    let mut combined_events = Events::new(&initial_filter);
    let mut current_until: Option<Timestamp> = None;
    let mut last_oldest_event_id: Option<EventId> = None; // Track the ID to detect timestamp collisions

    loop {
        // Prepare the filter for the current page request
        let mut page_filter = initial_filter.clone();
        page_filter = page_filter.limit(page_size as usize);
        if let Some(until_ts) = current_until {
            page_filter = page_filter.until(until_ts);
        }

        debug!("Fetching page with filter: {:?}", page_filter);

        let page_result: Result<Events, Error> = client
            .fetch_events(page_filter.clone(), timeout_per_page)
            .await;

        match page_result {
            Ok(fetched_page_events) => {
                if fetched_page_events.is_empty() {
                    debug!("Fetched empty page, stopping pagination.");
                    break; // No more events found for this filter range
                }

                let num_fetched = fetched_page_events.len();
                debug!("Fetched {} events for this page.", num_fetched);

                // Find the event with the *minimum* timestamp in the current page
                let oldest_event_in_page = fetched_page_events.iter().min_by_key(|e| e.created_at);

                if let Some(oldest_event) = oldest_event_in_page {
                    let oldest_ts = oldest_event.created_at;
                    let oldest_id = oldest_event.id;
                    debug!(
                        "Oldest event in this page: id={}, timestamp={}",
                        oldest_id.to_hex(),
                        oldest_ts
                    );

                    // Log size before merge for deduplication info
                    let size_before_merge = combined_events.len();

                    // Merge events *before* calculating next 'until'
                    combined_events = combined_events.merge(fetched_page_events);

                    let size_after_merge = combined_events.len();
                    debug!(
                        "Combined events size: {} -> {} ({} new unique events added)",
                        size_before_merge,
                        size_after_merge,
                        size_after_merge - size_before_merge
                    );

                    // Determine the 'until' timestamp for the *next* iteration.
                    let next_until_ts = if Some(oldest_id) == last_oldest_event_id {
                        // We fetched the same oldest event as the last page (timestamp collision).
                        // Decrement the timestamp slightly to force progress past this exact second.
                        debug!("Oldest event ID {} matches previous page's oldest; decrementing timestamp from {}.", oldest_id.to_hex(), oldest_ts);
                        Timestamp::from(oldest_ts.as_u64().saturating_sub(1))
                    } else {
                        // Use the exact timestamp of the oldest event found in this page.
                        oldest_ts
                    };

                    // Update the oldest ID tracker for the next iteration's collision check.
                    last_oldest_event_id = Some(oldest_id);

                    // Set the timestamp for the next request.
                    current_until = Some(next_until_ts);

                    // Add a small safeguard: If the timestamp isn't decreasing, break.
                    // This helps prevent infinite loops if the relay behaves unexpectedly.
                    // Note: We compare against the *next* 'until', not the current oldest_ts.
                    // Also need to check if the oldest ID actually changed, otherwise decrementing is valid.
                    if let Some(prev_until) = current_until {
                        // Check only if the oldest ID is different from the last iteration
                        if next_until_ts >= prev_until && Some(oldest_id) != last_oldest_event_id {
                            warn!("Pagination 'until' timestamp did not decrease ({:?} -> {:?}) despite different oldest event ID. Stopping pagination to prevent potential loop.", prev_until, next_until_ts);
                            break;
                        }
                    }
                } else {
                    // This case should ideally not be reached if fetched_page_events wasn't empty,
                    // but we handle it defensively.
                    debug!(
                        "Fetched non-empty Events list, but couldn't find oldest event via min_by_key. Stopping."
                    );
                    break;
                }
            }
            Err(e) => {
                error!("Error fetching page: {}", e);
                return Err(e);
            }
        }
    }

    debug!(
        "Pagination finished. Final combined_events count (after deduplication): {}",
        combined_events.len()
    );
    Ok(combined_events)
}
