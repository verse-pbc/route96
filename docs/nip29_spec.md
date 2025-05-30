NIP-29
======

Relay-based Groups
------------------

`draft` `optional`

This NIP defines a standard for groups that are only writable by a closed set of users. They can be public for reading by external users or not.

Groups are identified by a random string of any length that serves as an _id_.

There is no way to create a group, what happens is just that relays (most likely when asked by users) will create rules around some specific ids so these ids can serve as an actual group, henceforth messages sent to that group will be subject to these rules.

Normally a group will originally belong to one specific relay, but the community may choose to move the group to other relays or even fork the group so it exists in different forms -- still using the same _id_ -- across different relays.

## Relay-generated events

Relays are supposed to generate the events that describe group metadata and group admins. These are _addressable_ events signed by the relay keypair directly, with the group _id_ as the `d` tag.

## Group identifier

A group may be identified by a string in the format `<host>'<group-id>`. For example, a group with _id_ `abcdef` hosted at the relay `wss://groups.nostr.com` would be identified by the string `groups.nostr.com'abcdef`.

Group identifiers must be strings restricted to the characters `a-z0-9-_`, and SHOULD be random in order to avoid name collisions.

When encountering just the `<host>` without the `'<group-id>`, clients MAY infer `_` as the group id, which is a special top-level group dedicated to relay-local discussions.

## The `h` tag

Events sent by users to groups (chat messages, text notes, moderation events etc) MUST have an `h` tag with the value set to the group _id_.

## Timeline references

In order to not be used out of context, events sent to these groups may contain references to previous events seen from the same relay in the `previous` tag. The choice of which previous events to pick belongs to the clients. The references are to be made using the first 8 characters (4 bytes) of any event in the last 50 events seen by the user in the relay, excluding events by themselves. There can be any number of references (including zero), but it's recommended that clients include at least 3 and that relays enforce this.

This is a hack to prevent messages from being broadcasted to external relays that have forks of one group out of context. Relays are expected to reject any events that contain timeline references to events not found in their own database. Clients should also check these to keep relays honest about them.

## Late publication

Relays should prevent late publication (messages published now with a timestamp from days or even hours ago) unless they are open to receive a group forked or moved from another relay.

## Group management

Groups can have any number of users with elevated access. These users are identified by role labels which are arbitrarily defined by the relays (see also the description of `kind:39003`). What each role is capable of not defined in this NIP either, it's a relay policy that can vary. Roles can be assigned by other users (as long as they have the capability to add roles) by publishing a `kind:9000` event with that user's pubkey in a `p` tag and the roles afterwards (even if the user is already a group member a `kind:9000` can be issued and the user roles must just be updated).

The roles supported by the group as to having some special privilege assigned to them should be accessible on the event `kind:39003`, but the relay may also accept other role names, arbitrarily defined by clients, and just not do anything with them.

Users with any roles that have any privilege can be considered _admins_ in a broad sense and be returned in the `kind:39001` event for a group.

## Unmanaged groups

Unmanaged groups are impromptu groups that can be used in any public relay unaware of NIP-29 specifics. They piggyback on relays' natural white/blacklists (or lack of) but aside from that are not actively managed and won't have any admins, group state or metadata events.

In `unmanaged` groups, everybody is considered to be a member.

Unmanaged groups can transition to managed groups, in that case the relay master key just has to publish moderation events setting the state of all groups and start enforcing the rules they choose to.

## Event definitions

These are the events expected to be found in NIP-29 groups.

### Normal user-created events

Groups may accept any event kind, including chats, threads, long-form articles, calendar, livestreams, market announcements and so on. These should be as defined in their respective NIPs, with the addition of the `h` tag.

### User-related group management events

These are events that can be sent by users to manage their situation in a group, they also require the `h` tag.

- *join request* (`kind:9021`)

Any user can send a kind `9021` event to the relay in order to request admission to the group. Relays MUST reject the request if the user has not been added to the group. The accompanying error message SHOULD explain whether the rejection is final, if the request is pending review, or if some other special handling is relevant (e.g. if payment is required). If a user is already a member, the event MUST be rejected with `duplicate: ` as the error message prefix.

```json
{
  "kind": 9021,
  "content": "optional reason",
  "tags": [
    ["h", "<group-id>"],
    ["code", "<optional-invite-code>"]
  ]
}
```

The optional `code` tag may be used by the relay to preauthorize acceptances in `closed` groups, together with the `kind:9009` `create-invite` moderation event.

- *leave request* (`kind:9022`)

Any user can send one of these events to the relay in order to be automatically removed from the group. The relay will automatically issue a `kind:9001` in response removing this user.

```json
{
  "kind": 9022,
  "content": "optional reason",
  "tags": [
    ["h", "<group-id>"]
  ]
}
```

### Group state -- or moderation

These are events expected to be sent by the relay master key or by group admins -- and relays should reject them if they don't come from an authorized admin. They also require the `h` tag.

- *moderation events* (`kinds:9000-9020`) (optional)

Clients can send these events to a relay in order to accomplish a moderation action. Relays must check if the pubkey sending the event is capable of performing the given action based on its role and the relay's internal policy (see also the description of `kind:39003`).

```jsonc
{
  "kind": 90xx,
  "content": "optional reason",
  "tags": [
    ["h", "<group-id>"],
    ["previous", /*...*/]
  ]
}
```

Each moderation action uses a different kind and requires different arguments, which are given as tags. These are defined in the following table:

| kind | name                | tags                                           |
| ---  | ---                 | ---                                            |
| 9000 | `put-user`          | `p` with pubkey hex and optional roles         |
| 9001 | `remove-user`       | `p` with pubkey hex                            |
| 9002 | `edit-metadata`     | fields from `kind:39000` to be modified        |
| 9005 | `delete-event`      | `e` with event id hex                          |
| 9007 | `create-group`      |                                                |
| 9008 | `delete-group`      |                                                |
| 9009 | `create-invite`     |                                                |

It's expected that the group state (of who is an allowed member or not, who is an admin and with which permission or not, what are the group name and picture etc) can be fully reconstructed from the canonical sequence of these events.

### Group metadata events

These events contain the group id in a `d` tag instead of the `h` tag. They MUST be created by the relay master key only and a single instance of each (or none) should exist at all times for each group. They are merely informative but should reflect the latest group state (as it was changed by moderation events over time).

- *group metadata* (`kind:39000`) (optional)

This event defines the metadata for the group -- basically how clients should display it. It must be generated and signed by the relay in which is found. Relays shouldn't accept these events if they're signed by anyone else.

If the group is forked and hosted in multiple relays, there will be multiple versions of this event in each different relay and so on.

When this event is not found, clients may still connect to the group, but treat it as having a different status, `unmanaged`,

```jsonc
{
  "kind": 39000,
  "content": "",
  "tags": [
    ["d", "<group-id>"],
    ["name", "Pizza Lovers"],
    ["picture", "https://pizza.com/pizza.png"],
    ["about", "a group for people who love pizza"],
    ["public"], // or ["private"]
    ["open"] // or ["closed"]
  ]
  // other fields...
}
```

`name`, `picture` and `about` are basic metadata for the group for display purposes. `public` signals the group can be _read_ by anyone, while `private` signals that only AUTHed users can read. `open` signals that anyone can request to join and the request will be automatically granted, while `closed` signals that members must be pre-approved or that requests to join will be manually handled.

- *group admins* (`kind:39001`) (optional)

Each admin is listed along with one or more roles. These roles SHOULD have a correspondence with the roles supported by the relay, as advertised by the `kind:39003` event.

```jsonc
{
  "kind": 39001,
  "content": "list of admins for the pizza lovers group",
  "tags": [
    ["d", "<group-id>"],
    ["p", "<pubkey1-as-hex>", "ceo"],
    ["p", "<pubkey2-as-hex>", "secretary", "gardener"],
    // other pubkeys...
  ],
  // other fields...
}
```

- *group members* (`kind:39002`) (optional)

It's a list of pubkeys that are members of the group. Relays might choose to not to publish this information, to restrict what pubkeys can fetch it or to only display a subset of the members in it.

Clients should not assume this will always be present or that it will contain a full list of members.

```jsonc
{
  "kind": 39002,
  "content": "list of members for the pizza lovers group",
  "tags": [
    ["d", "<group-id>"],
    ["p", "<admin1>"],
    ["p", "<member-pubkey1>"],
    ["p", "<member-pubkey2>"],
    // other pubkeys...
  ],
  // other fields...
}
```

- *group roles* (`kind:39003`) (optional)

This is an event that MAY be published by the relay informing users and clients about what are the roles supported by this relay according to its internal logic.

For example, a relay may choose to support the roles `"admin"` and `"moderator"`, in which the `"admin"` will be allowed to edit the group metadata, delete messages and remove users from the group, while the `"moderator"` can only delete messages (or the relay may choose to call these roles `"ceo"` and `"secretary"` instead, the exact role name is not relevant).

The process through which the relay decides what roles to support and how to handle moderation events internally based on them is specific to each relay and not specified here.

```jsonc
{
  "kind": 39003,
  "content": "list of roles supported by this group",
  "tags": [
    ["d", "<group-id>"],
    ["role", "<role-name>", "<optional-description>"],
    ["role", "<role-name>", "<optional-description>"],
    // other roles...
  ],
  // other fields...
}
```

## Implementation quirks

### Checking your own membership in a group

The latest of either `kind:9000` or `kind:9001` events present in a group should tell a user that they are currently members of the group or if they were removed. In case none of these exist the user is assumed to not be a member of the group -- unless the group is `unmanaged`, in which case the user is assumed to be a member.

### Adding yourself to a group

When a group is `open`, anyone can send a `kind:9021` event to it in order to be added, then expect a `kind:9000` event to be emitted confirming that the user was added. The same happens with `closed` groups, except in that case a user may only send a `kind:9021` if it has an invite code.

### Storing your list of groups

A definition for `kind:10009` was included in [NIP-51](51.md) that allows clients to store the list of groups a user wants to remember being in.

### Using `unmanaged` relays

To prevent event leakage, when using `unmanaged` relays, clients should include the [NIP-70](70.md) `-` tag, as just the `previous` tag won't be checked by other `unmanaged` relays.

Groups MAY be named without relay support by adding a `name` to the corresponding tag in a user's `kind 10009` group list.