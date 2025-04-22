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
        let group = self.cache.entry(group_id.to_string()).or_default();

        match group.entry(pubkey_hex.to_string()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                // Only update the role if the new role is Admin (i.e., upgrade Member to Admin).
                // Do not downgrade an existing Admin to Member.
                if role == GroupRole::Admin {
                    entry.insert(role);
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                // If the pubkey wasn't in the group map yet, insert the new role.
                entry.insert(role);
            }
        }
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
        None // NIP-29 requires at least one 'p' tag for a valid group definition
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

    if let Some((group_id, event_members)) = process_event_tags(event) {
        debug!(
            "Processing NIP-29 event: Group='{}', Kind={}, EventId={}",
            group_id, event.kind, event.id
        );

        let group = cache.cache.entry(group_id.clone()).or_default();
        let event_members_hex: HashSet<String> =
            event_members.iter().map(|pk| pk.to_hex()).collect();

        match event.kind {
            kind if kind == GROUP_ADMINS_KIND => {
                // Replace the admin list for this group
                let current_group_keys: HashSet<String> = group.keys().cloned().collect();
                let admin_keys_in_event: &HashSet<String> = &event_members_hex; // Alias for clarity

                // Find users to downgrade (admins in cache, absent in event)
                let keys_to_downgrade: Vec<String> = current_group_keys
                    .iter()
                    .filter(|pk_hex| {
                        group.get(*pk_hex) == Some(&GroupRole::Admin)
                            && !admin_keys_in_event.contains(*pk_hex)
                    })
                    .cloned()
                    .collect();

                // Downgrade old admins to Member
                for pk_hex in keys_to_downgrade {
                    debug!(
                        "Downgrading admin {} to Member in group {} (removed via Kind 39001 event {})",
                        pk_hex,
                        group_id,
                        event.id.to_hex()
                    );
                    group.insert(pk_hex.clone(), GroupRole::Member);
                }

                // Add/update admins from the event
                for pk_hex in admin_keys_in_event {
                    // Check if the role needs updating to avoid unnecessary debug logs
                    if group.get(pk_hex) != Some(&GroupRole::Admin) {
                        debug!(
                            "Setting/Updating {} as Admin for group {} (from Kind 39001 event {})",
                            pk_hex,
                            group_id,
                            event.id.to_hex()
                        );
                    }
                    group.insert(pk_hex.clone(), GroupRole::Admin);
                }
            }
            kind if kind == GROUP_MEMBERSHIP_KIND => {
                // Kind 39002 lists *all* members (including admins).
                // It defines the complete set of pubkeys that should be in the group.
                // Remove anyone currently in the cache who isn't in this event.
                // Add anyone in this event who isn't already in the cache (as Member),
                // preserving existing Admins.

                let current_group_keys: HashSet<String> = group.keys().cloned().collect();
                let keys_in_event: &HashSet<String> = &event_members_hex; // Alias for clarity

                // Find users to remove (present in cache, absent in event)
                let keys_to_remove = current_group_keys.difference(keys_in_event);

                for pk_hex in keys_to_remove {
                    debug!(
                        "Removing user {} from group {} (no longer in Kind 39002 event {}",
                        pk_hex,
                        group_id,
                        event.id.to_hex()
                    );
                    group.remove(pk_hex);
                }

                // Find users to add/ensure exist (present in event)
                // Use or_insert to avoid overwriting existing Admins with Member role.
                for pk_hex in keys_in_event {
                    group.entry(pk_hex.clone()).or_insert_with(|| {
                        debug!(
                            "Adding user {} as Member to group {} (from Kind 39002 event {})",
                            pk_hex,
                            group_id,
                            event.id.to_hex()
                        );
                        GroupRole::Member // Only inserted if the key was not present
                    });
                }
            }
            _ => {
                // Should not happen due to filter, but good practice
                warn!(
                    "Received unexpected event kind {} in update_cache_entry for group {}",
                    event.kind, group_id
                );
                return;
            }
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

            // Log the cache state while holding the write lock
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
        }
        Err(e) => {
            warn!(
                "Error during paginated fetch of initial NIP-29 events from {}: {}. Cache might be incomplete.",
                relay_url, e
            );
            // Continue initialization even if fetch fails, cache will be incomplete.
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

        // Handle notifications
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
    let mut last_oldest_event_id: Option<EventId> = None; // Track last oldest ID to detect timestamp collisions

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

                // Find the event with the minimum timestamp; relays might not guarantee order.
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

                    // Determine the 'until' timestamp for the next page request.
                    let next_until_ts = if Some(oldest_id) == last_oldest_event_id {
                        // Timestamp collision: Decrement timestamp by 1s to avoid getting stuck.
                        debug!(
                            "Oldest event ID {} matches previous; decrementing timestamp from {}.",
                            oldest_id.to_hex(),
                            oldest_ts
                        );
                        Timestamp::from(oldest_ts.as_u64().saturating_sub(1))
                    } else {
                        oldest_ts
                    };

                    // Update the oldest ID tracker for the next iteration's collision check.
                    last_oldest_event_id = Some(oldest_id);

                    // Set the timestamp for the next request.
                    current_until = Some(next_until_ts);

                    // Safeguard against potential infinite loops if timestamp logic fails
                    if let Some(prev_until) = current_until {
                        // Check only if the oldest ID is different from the last iteration.
                        // If the ID is the same, decrementing the timestamp is expected.
                        if next_until_ts >= prev_until && Some(oldest_id) != last_oldest_event_id {
                            warn!("Pagination 'until' timestamp did not decrease ({:?} -> {:?}) despite different oldest event ID. Stopping.", prev_until, next_until_ts);
                            break;
                        }
                    }
                } else {
                    // Should not happen if fetched_page_events wasn't empty
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
        "Pagination finished. Total unique events fetched: {}",
        combined_events.len()
    );
    Ok(combined_events)
}

/// Helper to create a NIP-29 event
fn create_nip29_event(
    kind: Kind,
    group_id: &str,
    p_tags_pks: &[PublicKey],
    relay_keys: &Keys,
) -> Event {
    let p_tags: Vec<Tag> = p_tags_pks.iter().map(|pk| Tag::public_key(*pk)).collect();
    let d_tag = Tag::identifier(group_id.to_string());

    let mut tags = p_tags;
    tags.push(d_tag);

    // Use the corrected nostr-sdk 0.40.0 API
    EventBuilder::new(kind, "") // Content is typically empty for these kinds
        .tags(tags)
        .sign_with_keys(relay_keys)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from the parent module
    use nostr_sdk::prelude::*;
    use std::str::FromStr;

    // Helper function to create a dummy relay key
    fn relay_keys() -> Keys {
        Keys::generate()
    }

    // Helper function to create a user public key from a hex string
    fn user_pk(hex: &str) -> PublicKey {
        PublicKey::from_hex(hex).unwrap()
    }

    // Helper to create a NIP-29 event
    fn create_nip29_event(
        kind: Kind,
        group_id: &str,
        p_tags_pks: &[PublicKey],
        relay_keys: &Keys,
    ) -> Event {
        let p_tags: Vec<Tag> = p_tags_pks.iter().map(|pk| Tag::public_key(*pk)).collect();
        let d_tag = Tag::identifier(group_id.to_string());

        let mut tags = p_tags;
        tags.push(d_tag);

        // Use the corrected nostr-sdk 0.40.0 API
        EventBuilder::new(kind, "") // Content is typically empty for these kinds
            .tags(tags)
            .sign_with_keys(relay_keys)
            .unwrap()
    }

    #[tokio::test]
    async fn test_initial_load_admins_and_members() {
        let relay_keys = relay_keys();
        let relay_pubkey = relay_keys.public_key();
        let mut cache = GroupStateCache::new();
        let group_id = "test_group";

        let admin1 = user_pk("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let admin2 = user_pk("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let member1 = user_pk("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

        // Event 1: Define Admins
        let admin_event =
            create_nip29_event(GROUP_ADMINS_KIND, group_id, &[admin1, admin2], &relay_keys);
        super::update_cache_entry(&admin_event, &mut cache, &relay_pubkey).await;

        // Event 2: Define Members (including one admin)
        let member_event = create_nip29_event(
            GROUP_MEMBERSHIP_KIND,
            group_id,
            &[admin1, member1],
            &relay_keys,
        );
        super::update_cache_entry(&member_event, &mut cache, &relay_pubkey).await;

        // Assertions
        assert_eq!(
            cache.get_role(group_id, &admin1.to_hex()),
            Some(GroupRole::Admin)
        );
        assert_eq!(
            cache.get_role(group_id, &admin2.to_hex()), // Admin2 was defined but not in member list
            None                                        // Correctly removed by member event
        );
        assert_eq!(
            cache.get_role(group_id, &member1.to_hex()),
            Some(GroupRole::Member)
        );
        assert_eq!(cache.cache.get(group_id).map(|g| g.len()), Some(2)); // Only admin1 and member1 should remain
    }

    #[tokio::test]
    async fn test_member_event_does_not_overwrite_admin() {
        let relay_keys = relay_keys();
        let relay_pubkey = relay_keys.public_key();
        let mut cache = GroupStateCache::new();
        let group_id = "test_group";
        let admin1 = user_pk("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        // Setup: Make admin1 an admin
        let admin_event = create_nip29_event(GROUP_ADMINS_KIND, group_id, &[admin1], &relay_keys);
        super::update_cache_entry(&admin_event, &mut cache, &relay_pubkey).await;
        assert_eq!(
            cache.get_role(group_id, &admin1.to_hex()),
            Some(GroupRole::Admin)
        );

        // Action: Send a member event listing the admin
        let member_event =
            create_nip29_event(GROUP_MEMBERSHIP_KIND, group_id, &[admin1], &relay_keys);
        super::update_cache_entry(&member_event, &mut cache, &relay_pubkey).await;

        // Assertion: Role should still be Admin
        assert_eq!(
            cache.get_role(group_id, &admin1.to_hex()),
            Some(GroupRole::Admin)
        );
    }

    #[tokio::test]
    async fn test_remove_admin() {
        let relay_keys = relay_keys();
        let relay_pubkey = relay_keys.public_key();
        let mut cache = GroupStateCache::new();
        let group_id = "test_group";
        let admin1 = user_pk("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let admin2 = user_pk("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        // Setup: Add admin1 and admin2
        let initial_admin_event =
            create_nip29_event(GROUP_ADMINS_KIND, group_id, &[admin1, admin2], &relay_keys);
        super::update_cache_entry(&initial_admin_event, &mut cache, &relay_pubkey).await;
        // Setup: Add them to member list too
        let initial_member_event = create_nip29_event(
            GROUP_MEMBERSHIP_KIND,
            group_id,
            &[admin1, admin2],
            &relay_keys,
        );
        super::update_cache_entry(&initial_member_event, &mut cache, &relay_pubkey).await;
        assert_eq!(
            cache.get_role(group_id, &admin1.to_hex()),
            Some(GroupRole::Admin)
        );
        assert_eq!(
            cache.get_role(group_id, &admin2.to_hex()),
            Some(GroupRole::Admin)
        );

        // Action 1: Remove admin1 via admin event
        let remove_admin1_event =
            create_nip29_event(GROUP_ADMINS_KIND, group_id, &[admin2], &relay_keys);
        super::update_cache_entry(&remove_admin1_event, &mut cache, &relay_pubkey).await;

        // Assertion 1: admin1 should no longer be admin, admin2 still is
        assert_eq!(
            cache.get_role(group_id, &admin1.to_hex()),
            Some(GroupRole::Member)
        ); // Still Member from last 39002
        assert_eq!(
            cache.get_role(group_id, &admin2.to_hex()),
            Some(GroupRole::Admin)
        );

        // Action 2: Send member event *without* admin1
        let remove_admin1_member_event = create_nip29_event(
            GROUP_MEMBERSHIP_KIND,
            group_id,
            &[admin2], // Only admin2 remains
            &relay_keys,
        );
        super::update_cache_entry(&remove_admin1_member_event, &mut cache, &relay_pubkey).await;

        // Assertion 2: admin1 should be completely gone
        assert_eq!(cache.get_role(group_id, &admin1.to_hex()), None);
        assert_eq!(
            cache.get_role(group_id, &admin2.to_hex()),
            Some(GroupRole::Admin)
        );
        assert_eq!(cache.cache.get(group_id).map(|g| g.len()), Some(1)); // Only admin2 remains
    }

    #[tokio::test]
    async fn test_remove_member() {
        let relay_keys = relay_keys();
        let relay_pubkey = relay_keys.public_key();
        let mut cache = GroupStateCache::new();
        let group_id = "test_group";
        let member1 = user_pk("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        let member2 = user_pk("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

        // Setup: Add member1 and member2
        let initial_member_event = create_nip29_event(
            GROUP_MEMBERSHIP_KIND,
            group_id,
            &[member1, member2],
            &relay_keys,
        );
        super::update_cache_entry(&initial_member_event, &mut cache, &relay_pubkey).await;
        assert_eq!(
            cache.get_role(group_id, &member1.to_hex()),
            Some(GroupRole::Member)
        );
        assert_eq!(
            cache.get_role(group_id, &member2.to_hex()),
            Some(GroupRole::Member)
        );

        // Action: Send member event without member1
        let remove_member1_event =
            create_nip29_event(GROUP_MEMBERSHIP_KIND, group_id, &[member2], &relay_keys);
        super::update_cache_entry(&remove_member1_event, &mut cache, &relay_pubkey).await;

        // Assertion: member1 should be gone, member2 remains
        assert_eq!(cache.get_role(group_id, &member1.to_hex()), None);
        assert_eq!(
            cache.get_role(group_id, &member2.to_hex()),
            Some(GroupRole::Member)
        );
        assert_eq!(cache.cache.get(group_id).map(|g| g.len()), Some(1)); // Only member2 remains
    }

    #[tokio::test]
    async fn test_add_new_member() {
        let relay_keys = relay_keys();
        let relay_pubkey = relay_keys.public_key();
        let mut cache = GroupStateCache::new();
        let group_id = "test_group";
        let member1 = user_pk("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

        // Action: Send member event with a new member
        let add_member_event =
            create_nip29_event(GROUP_MEMBERSHIP_KIND, group_id, &[member1], &relay_keys);
        super::update_cache_entry(&add_member_event, &mut cache, &relay_pubkey).await;

        // Assertion: member1 should be added as Member
        assert_eq!(
            cache.get_role(group_id, &member1.to_hex()),
            Some(GroupRole::Member)
        );
        assert_eq!(cache.cache.get(group_id).map(|g| g.len()), Some(1));
    }

    #[tokio::test]
    async fn test_ignore_event_wrong_author() {
        let relay_keys = relay_keys();
        let wrong_keys = Keys::generate(); // Different keys
        let relay_pubkey = relay_keys.public_key();
        let mut cache = GroupStateCache::new();
        let group_id = "test_group";
        let member1 = user_pk("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

        // Action: Create event with wrong keys
        let event = create_nip29_event(
            GROUP_MEMBERSHIP_KIND,
            group_id,
            &[member1],
            &wrong_keys, // Signed by wrong key
        );
        super::update_cache_entry(&event, &mut cache, &relay_pubkey).await;

        // Assertion: Cache should be empty
        assert!(cache.cache.is_empty());
    }

    #[tokio::test]
    async fn test_ignore_event_missing_d_tag() {
        let relay_keys = relay_keys();
        let relay_pubkey = relay_keys.public_key();
        let mut cache = GroupStateCache::new();
        let member1 = user_pk("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

        // Action: Create event without d tag
        let p_tag = Tag::public_key(member1);
        let event = EventBuilder::new(GROUP_MEMBERSHIP_KIND, "")
            .tags(vec![p_tag]) // Only p_tag
            .sign_with_keys(&relay_keys)
            .unwrap();

        super::update_cache_entry(&event, &mut cache, &relay_pubkey).await;

        // Assertion: Cache should be empty
        assert!(cache.cache.is_empty());
    }

    #[tokio::test]
    async fn test_ignore_event_missing_p_tags() {
        let relay_keys = relay_keys();
        let relay_pubkey = relay_keys.public_key();
        let mut cache = GroupStateCache::new();
        let group_id = "test_group";

        // Action: Create event without p tags
        let d_tag = Tag::identifier(group_id.to_string());
        let event = EventBuilder::new(GROUP_MEMBERSHIP_KIND, "")
            .tags(vec![d_tag]) // Only d_tag
            .sign_with_keys(&relay_keys)
            .unwrap();

        super::update_cache_entry(&event, &mut cache, &relay_pubkey).await;

        // Assertion: Cache should be empty
        assert!(cache.cache.is_empty());
    }
}
