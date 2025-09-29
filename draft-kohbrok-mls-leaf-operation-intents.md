---
title: "Leaf Operation Intents"
abbrev: "LOI"
category: info

docname: draft-kohbrok-mls-leaf-operation-intents-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
 - mls
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "kkohbrok/draft-kohbrok-mls-leaf-operation-intents"
  latest: "https://kkohbrok.github.io/draft-kohbrok-mls-leaf-operation-intents/draft-kohbrok-mls-leaf-operation-intents.html"

author:
 -
    fullname: "Konrad Kohbrok"
    organization: Phoenix R&D
    email: "konrad@ratchet.ing"

contributor:
 - name: Raphael Robert
   org:  Phoenix R&D
   email:  ietf@raphaelrobert.com

normative:

informative:

...

--- abstract

The Messaging Layer Security (MLS) protocol defined in {{!RFC9420}} is an
asynchronous secure group messaging protocol, which allows group members to
propose their removal from a group.

However, in some cases MLS clients can't reliably use regular Remove or
SelfRemove proposals to leave a group because they don't have an up-to-date
group state.

This document specifies a LeafOperationIntent, which does not need an up-to-date
group state but which retains sufficient binding to the client's current state
to avoid replay attacks.

--- middle

# Introduction

To leave an MLS group, a member cannot create a commit, but rather has to
propose its own removal. This can create difficulties, some of which have been
solved by the introduction of the SelfRemove proposal, which may be included in
external commits.

One drawback of Remove and SelfRemove proposals is that they (like other
proposals) are bound to a specific group epoch. This means that authors of such
proposals must have an up-to-date group state to send such a proposal and
continue to keep track of that group state both to re-send the proposal if
necessary.

This can be a problem if an application wants to cleanly leave a group and
immediately delete the associated group state, e.g., to erase the associated
metadata. The deletion of the group state makes it impossible for the client to
re-send the proposal in case it's not covered by the next commit. Similarly, the
client might be offline at the time and the group state might not be up-to-date.

The LeafOperationIntent specified in this document allows a client to bind an
intent to leave a group to the leaf's current state. That intent can then be
proposed by any party (e.g. an external sender) in any subsequent epoch,
provided the leaf remains unchanged

As users often have more than one client that needs to be removed from the group
as part of the user leaving, the intent allows expanding the leaf operation to
associated leaves.

# LeafOperationIntent

A LeafOperationIntent can be created by clients and distributed either to other
group members or to one or more external senders.

~~~ tls
HashReference LeafNodeRef;

MakeLeafNodeRef(value)
  = RefHash("MLS 1.0 LeafNode Reference", value)

enum {
  reserved(0),
  sender_removal_only(1),
  remove_associated_members(2),
  (255)
} RemovalMode

struct {
  opaque group_id<V>;
  uint32 sender_index;
  LeafNodeRef sender_leaf_ref;
  RemovalMode removal_mode;
} LeafOperationIntentTBS

struct {
  opaque group_id<V>;
  uint32 sender_index;
  LeafNodeRef sender_leaf_ref;
  RemovalMode removal_mode;
  /* SignWithLabel(., "LeafOperationIntentTBS", LeafOperationIntentTBS) */
  opaque signature<V>;
} LeafOperationIntent

struct {
  LeafOperationIntent intent;
} LeafOperationProposal
~~~

RefHash and SignWithLabel are as defined in {{!RFC9420}}.

- `group_id`: The ID of the MLS group in which context the LeafOperationIntent
  was sent
- `sender_index`: The index of the sender's leaf in the group
- `sender_leaf_ref`: Hash computed over the LeafNode of the sending client using the
  MakeLeafNodeRef function
- `removal_mode`: Indicates whether only the sender should be removed, or
  whether additionally any other, associated members should be removed as well.
- `signature`: A signature over all fields except the signature itself using the
  sender's leaf signature key

The purpose of the `removal_mode` is to allow the sender to signal that other
members associated with the sender should be removed as part of this operation.
This can be useful if the sender is part of a group of associated devices, e.g.,
multiple devices belonging to the same user, to facilitate the leaving of the
entire user as opposed to just the sending client.

## Creating and proposing a LeafOperationIntent

A group member creates a LeafOperationIntent by populating the `group_id`,
`sender_index` and `sender_leaf_ref` according to the current state of the group
and the sender's leaf.

If the sender wants to signal the removal of any associated members, it can set
the `removal_mode` accordingly.

Finally the sender creates the signature by calling `SignWithLabel` on the
LeafOperationIntentTBS populated as described above with
"LeafOperationIntentTBS" as label.

Recipients of a LeafOperationIntent can include it in a LeafOperationProposal.

## Processing a LeafOperationProposal

Recipients of a LeafOperationProposal MUST perform the following steps on the
`intent` contained in the proposal.

- Verify that the `group_id` matches the group in which the proposal was sent
- Verify that the `sender_leaf_ref` is the LeafRef of the leaf at the
  `sender_index`
- Verify the `signature` over the `intent` using the signature public key in the
  leaf at the `sender_index`
- If `removal_mode` is `remove_associated_members`, check with the
  authentication service (AS, see {{!RFC9750}}) whether any other members of the
  group are associated with the sender

If any of the validation steps fail, the recipient MUST consider the proposal
invalid.

After that, the proposal MUST be validated and processed as if it were a Remove
proposal targeting the sender's leaf.

If `removal_mode` is `remove_associated_members`, the proposal MUST additionally
be validated and processed as if it were a set of Remove proposals targeting the
members identified as associated clients by the AS.

All Remove proposals MUST be treated as if they originated from the sender of
the intent (not the sender of the LeafOperationProposal).

External commits may include one or more LeafOperationProposals. Any Removes
validated as described above MUST thus be considered valid in this context.

Open questions:

- Do we want to have an MLS wire format for LeafOperationIntent?

## Additional AS role

When using LeafOperationIntents, the AS gains the additional role of having to
identify other members in a group that are associated with the sender of a
LeafOperationIntent.

The association could, for example, be that multiple clients belong to the same
user. In most cases, the association will be determined by Credentials of the
individual group members.

# Security Considerations

In contrast to proposals, LeafOperationIntents are not bound to an epoch and
thus remain valid as long as the creator's leaf doesn't change its state.

Each LeafOperationIntent can thus be proposed and committed to until the sender
is either removed from the group or updates its own leaf.

This allows scenarios, where, for example, members get added to or removed from
a group in the time between the creation and the proposal of the intent.

If a tighter bound to the epoch, i.e. the current group state is required,
clients should use regular Remove or SelfRemove proposals instead.

Epoch independence incurs a certain risk of replay attacks. The bound of the
intent to the hash of the sender's LeafNode limits that risk significantly.
However, a replay is possible, for example, if the sender's leaf still contains
the LeafNode from a KeyPackage. In that case, if the sender is later added again
with the same KeyPackage, the intent can be replayed.

# IANA Considerations

This document requests the addition of a new Proposal Type under the heading of
"Messaging Layer Security".

The `leaf_operation_intent` MLS Proposal Type is used to allow members or
external senders to convey the intent of a leaf owner to perform an operation on
their leaf.

* Value: TBD
* Name: leaf_operation_intent
* Recommended: Y
* External: Y
* Path Required: Y

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
