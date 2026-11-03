---
title: OpenID Shared Signals Event Actions Profile 1.0

abbrev: SSF-Event-Actions
docname: openid-ssf-event-actions-1_0
date: 2026-11-02

ipr: none
cat: std
wg: Shared Signals

coding: us-ascii
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes
  private: yes

author:
      -
        ins: A. Deshpande
        name: Apoorva Deshpande
        org: Okta
        email: apoorva.deshpande@okta.com

normative:
  RFC2119:
  RFC8174:
  RFC7519: # JSON Web Token
  RFC8417: # Security Event Token
  RFC8935: # Push delivery
  RFC8936: # Poll delivery
  RFC9110: # HTTP Semantics
  SSF:
    target: https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html
    title: OpenID Shared Signals Framework Specification 1.0
    author:
      -
        ins: A. Tulshibagwale
        name: Atul Tulshibagwale
      -
        ins: T. Cappalli
        name: Tim Cappalli
      -
        ins: M. Scurtescu
        name: Marius Scurtescu
      -
        ins: A. Backman
        name: Annabelle Backman
      -
        ins: J. Bradley
        name: John Bradley
      -
        ins: S. Miel
        name: Shayne Miel
  MULTI-SET-PUSH:
    target: https://datatracker.ietf.org/doc/draft-deshpande-secevent-http-multi-set-push/
    title: Push-Based Delivery For Multiple Security Event Tokens (SET) Using HTTP
    author:
      -
        ins: A. Deshpande
        name: Apoorva Deshpande
      -
        ins: A. Parecki
        name: Aaron Parecki

informative:
  CAEP:
    target: https://openid.net/specs/openid-caep-1_0-final.html
    title: OpenID Continuous Access Evaluation Profile 1.0
    author:
      -
        ins: T. Cappalli
        name: Tim Cappalli
      -
        ins: A. Tulshibagwale
        name: Atul Tulshibagwale
  RISC:
    target: https://openid.net/specs/openid-risc-1_0-final.html
    title: OpenID RISC Profile Specification 1.0
    author:
      -
        ins: M. Scurtescu
        name: Marius Scurtescu
      -
        ins: A. Backman
        name: Annabelle Backman
      -
        ins: P. Hunt
        name: Phil Hunt
      -
        ins: J. Bradley
        name: John Bradley
  MLE:
    target: https://github.com/soosproject/MLE
    title: Mandate Lifecycle Events
    author:
      -
        ins: T. Sato
        name: Tom Sato

--- abstract

This specification defines an extension to the OpenID Shared Signals Framework
({{SSF}}) that allows an Event Transmitter to request that an Event Receiver
enforce specific actions in response to a Security Event Token (SET), and allows
the Receiver to report, per action, whether each requested action was enforced.
It defines how Transmitters and Receivers advertise and negotiate the action
types they support, how actions are expressed inside an event, and how
enforcement outcomes are reported using the acknowledgement and error mechanisms
of existing SET delivery methods.

--- middle

# Introduction {#introduction}

An SSF event is a statement of fact: something happened to a subject, as
observed by the Transmitter. The Receiver decides what to do about it under its
own policy. For many events this is sufficient. For others, a reasonable
Receiver could respond in several ways, and the Transmitter has a legitimate
need to state which outcome it expects and to learn whether that outcome was
achieved. Examples include:

* A credential compromise, where the Transmitter needs derived tokens revoked
  and not merely the credential noted.
* A revoked delegation to an AI agent, where in-flight work and tokens issued
  under that delegation must stop, including at sub-agents.
* An incident response workflow that must record which downstream systems
  confirmed containment.

Today, acknowledgement mechanisms in {{RFC8935}}, {{RFC8936}} and
{{MULTI-SET-PUSH}} confirm only that a SET was received and validated. They do
not convey whether the Receiver acted on it.

This specification adds:

1. Capability advertisement for action types by Transmitters and Receivers
   ({{discovery}}).
2. Per-stream negotiation of the action types the Transmitter requests the
   Receiver to enforce ({{stream-config}}).
3. An `actions` member inside an event payload ({{actions-member}}).
4. Per-action enforcement outcomes in delivery acknowledgements
   ({{outcomes}}).
5. A template for defining action types, and an initial set of action types
   ({{action-definition}}, {{initial-actions}}).

An action is a request, not a command. A Receiver remains in control of its
enforcement points and MAY decline any action under local policy. What this
specification adds is an explicit, reportable outcome for each request.

## Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

## Terminology

Action
: A request, carried in an event, that the Receiver bring about a defined end
  state for the subject of that event.

Action Type
: A URI that identifies the kind of action and its definition
  ({{action-definition}}).

Enforcement Outcome
: The final result reported by a Receiver for a single action, either
  enforced or one of the error codes defined in {{action-error-codes}}.

This specification also uses the terms "Transmitter", "Receiver", "Event
Stream" and "Stream Configuration" as defined in {{SSF}}.

# Design Principles {#principles}

Events state facts; actions state required end states.
: An action type is justified only when Receivers could reasonably respond to
  the carrying event in more than one way. An action that merely restates its
  event (for example, a session revocation event carrying a "terminate
  sessions" action) SHOULD NOT be defined.

Actions are defined by postcondition, not by procedure.
: Each action type defines what must be true once it is enforced. It does not
  define how a Receiver achieves that state.

Actions apply to the subject of the carrying event.
: An action has no target of its own. This prevents an action from reaching
  a resource that the event never named.

Enforcement is scoped to the Receiver.
: An `enforced` outcome covers only the Receiver's own enforcement points. It
  makes no claim about systems the Receiver does not operate.

# Capability Discovery {#discovery}

## Transmitter Configuration Metadata

This specification defines the following member of the Transmitter
Configuration Metadata defined in {{SSF}}:

transmitter_actions_supported

> OPTIONAL. An array of Action Type URIs that the Transmitter can include in
  the `actions` member of events it sends. If omitted, the Transmitter does not
  support this specification.

The following is a non-normative example of Transmitter Configuration Metadata:

~~~ json
{
  "spec_version": "1_0",
  "issuer": "https://tr.example.com",
  "jwks_uri": "https://tr.example.com/jwks.json",
  "delivery_methods_supported": [
    "urn:ietf:rfc:8936"
  ],
  "configuration_endpoint": "https://tr.example.com/ssf/stream",
  "transmitter_actions_supported": [
    "https://schemas.openid.net/secevent/ssf/action-type/revoke-tokens",
    "https://schemas.openid.net/secevent/ssf/action-type/terminate-sessions",
    "https://schemas.openid.net/secevent/ssf/action-type/require-reauthentication"
  ]
}
~~~
{: title="Example: Transmitter Configuration Metadata with actions"}

# Stream Configuration {#stream-config}

## Stream Configuration Properties

This specification defines the following properties of the Stream
Configuration defined in {{SSF}}:

transmitter_actions_supported

> **Transmitter-Supplied**, OPTIONAL. An array of Action Type URIs the
  Transmitter can send to this Receiver. If present in the Transmitter
  Configuration Metadata, it SHOULD be echoed in the Stream Configuration, and
  MAY be narrower for a specific Receiver.

receiver_actions_supported

> **Receiver-Supplied**, OPTIONAL. An array of Action Type URIs the Receiver
  can enforce on this stream. By including an Action Type, the Receiver commits
  to reporting an Enforcement Outcome ({{outcomes}}) for every action of that
  type the Transmitter sends on this stream. A Receiver SHOULD include only
  Action Types whose definitions it implements. A Transmitter MUST ignore array
  values it does not understand.

actions_enforcement_requested

> **Transmitter-Supplied**. REQUIRED if the Receiver supplied
  `receiver_actions_supported`, otherwise OPTIONAL. An array of Action Type URIs
  the Transmitter requests the Receiver to enforce on this stream. This MUST be
  a subset (not necessarily a proper subset) of the intersection of
  `transmitter_actions_supported` and `receiver_actions_supported`. An empty
  array means no actions will be sent on this stream. The Transmitter MUST
  persist this value as part of the stream's state. Both parties MUST rely on
  this value as the agreed set of Action Types for the stream.

A Transmitter SHOULD NOT include in `actions_enforcement_requested` an Action
Type that applies to none of the event types in `events_delivered`.

## Delivery Method Requirements {#delivery-requirements}

Enforcement Outcomes are reported using the acknowledgement mechanism of the
stream's delivery method. A Transmitter MUST NOT return a non-empty
`actions_enforcement_requested` unless the stream's delivery method can carry
Enforcement Outcomes. The delivery methods that can carry them are:

* Poll-Based Delivery {{RFC8936}}, where the Receiver reports outcomes in poll
  requests.
* Multi-SET Push-Based Delivery {{MULTI-SET-PUSH}}, where the Receiver reports
  outcomes in push responses.

Push-Based Delivery {{RFC8935}} acknowledges a single SET synchronously with an
HTTP status code and cannot report a later outcome. A Transmitter MUST return an
empty `actions_enforcement_requested` for streams using that method.

## Creating a Stream

A Receiver MAY include `receiver_actions_supported` in the request to create a
stream, alongside the other Receiver-Supplied properties defined in {{SSF}}.
The Transmitter computes `actions_enforcement_requested` and returns it in the
"201 Created" response.

The following is a non-normative example request to create a stream:

~~~ http
POST /ssf/stream HTTP/1.1
Host: tr.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=
Content-Type: application/json

{
  "events_requested": [
    "https://schemas.openid.net/secevent/caep/event-type/credential-change"
  ],
  "receiver_actions_supported": [
    "https://schemas.openid.net/secevent/ssf/action-type/revoke-tokens",
    "https://schemas.openid.net/secevent/ssf/action-type/terminate-sessions"
  ],
  "delivery": {
    "method": "urn:ietf:rfc:8936"
  }
}
~~~
{: title="Example: Create Stream request with receiver_actions_supported"}

The following is a non-normative example response:

~~~ http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "iss": "https://tr.example.com",
  "aud": "https://rv.example.com",
  "events_supported": [
    "https://schemas.openid.net/secevent/caep/event-type/credential-change",
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
  ],
  "events_requested": [
    "https://schemas.openid.net/secevent/caep/event-type/credential-change"
  ],
  "events_delivered": [
    "https://schemas.openid.net/secevent/caep/event-type/credential-change"
  ],
  "transmitter_actions_supported": [
    "https://schemas.openid.net/secevent/ssf/action-type/revoke-tokens",
    "https://schemas.openid.net/secevent/ssf/action-type/terminate-sessions",
    "https://schemas.openid.net/secevent/ssf/action-type/require-reauthentication"
  ],
  "receiver_actions_supported": [
    "https://schemas.openid.net/secevent/ssf/action-type/revoke-tokens",
    "https://schemas.openid.net/secevent/ssf/action-type/terminate-sessions"
  ],
  "actions_enforcement_requested": [
    "https://schemas.openid.net/secevent/ssf/action-type/revoke-tokens",
    "https://schemas.openid.net/secevent/ssf/action-type/terminate-sessions"
  ],
  "delivery": {
    "method": "urn:ietf:rfc:8936",
    "endpoint_url": "https://tr.example.com/ssf/poll/f67e39a0"
  }
}
~~~
{: title="Example: Create Stream response with actions_enforcement_requested"}

## Reading, Updating and Replacing a Stream

`receiver_actions_supported` is handled in the same way as `events_requested`
when reading, updating (PATCH) or replacing (PUT) a stream's configuration, as
defined in {{SSF}}. On every successful update or replace, the Transmitter MUST
recompute `actions_enforcement_requested` and return it in the response.

A change to `actions_enforcement_requested` applies only to SETs the
Transmitter sends after it has returned the updated configuration. The Receiver
remains obligated to report Enforcement Outcomes for actions in SETs it received
before the change.

# The actions Member {#actions-member}

An event payload, as defined in {{Section 2.2 of RFC8417}}, MAY contain an
`actions` member when the event's type definition, or this specification
through {{action-definition}}, permits it for that event type. Placing actions
inside the event payload ensures they are covered by the SET's signature and
are bound to the event that motivated them.

actions

> OPTIONAL. A non-empty array of Action objects. Each Action object has the
  following members:

id

> REQUIRED. A string that identifies the action. It MUST be unique among all
  actions in all events of the SET. Enforcement Outcomes refer to the action
  using this value.

type

> REQUIRED. An Action Type URI. It MUST be a member of the stream's
  `actions_enforcement_requested`.

enforce_by

> OPTIONAL. A NumericDate {{RFC7519}} by which the Transmitter requests the
  action to be enforced.

params

> OPTIONAL. A JSON object containing parameters defined by the Action Type.
  A Receiver MUST ignore members it does not understand.

{{SSF}} requires Receivers to ignore fields they do not understand in SSF
events. A Receiver that does not implement this specification therefore ignores
the `actions` member and processes the event normally. Such a Receiver will
not have supplied `receiver_actions_supported`, so the Transmitter will not
send actions to it.

The following is a non-normative example of a SET carrying actions:

~~~ json
{
  "iss": "https://tr.example.com",
  "jti": "4d3559ec67504aaba65d40b0363faad8",
  "iat": 1793000000,
  "aud": "https://rv.example.com",
  "txn": "8675309",
  "sub_id": {
    "format": "email",
    "email": "user@example.com"
  },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/credential-change": {
      "credential_type": "password",
      "change_type": "revoke",
      "event_timestamp": 1792999990,
      "actions": [
        {
          "id": "a1",
          "type": "https://schemas.openid.net/secevent/ssf/action-type/revoke-tokens",
          "enforce_by": 1793000060
        },
        {
          "id": "a2",
          "type": "https://schemas.openid.net/secevent/ssf/action-type/terminate-sessions"
        }
      ]
    }
  }
}
~~~
{: title="Example: SET with actions in the event payload"}

# Enforcement Outcomes {#outcomes}

## Two-Phase Reporting

A SET that carries actions is reported in two phases:

1. **Delivery.** The Receiver acknowledges receipt and validation of the SET
   using the `ack` or `setErrs` mechanism of the delivery method, exactly as it
   would for a SET without actions.
2. **Enforcement.** The Receiver reports exactly one Enforcement Outcome for
   each action `id`, using the members defined in this section.

Both phases MAY be reported in the same message. Reporting an Enforcement
Outcome for any action in a SET implies acknowledgement of that SET. A
Receiver MAY report the outcomes for the actions of a single SET across
several messages. An Enforcement Outcome, once reported, is final.

If a SET fails validation and is reported in `setErrs` without an `actions`
member, the Receiver has attempted none of its actions and no further outcomes
are owed for that SET.

## The enforced Member

This specification defines the following member, used in the Receiver's
acknowledgement message: the poll request body for {{RFC8936}}, or the push
response body for {{MULTI-SET-PUSH}}.

enforced

> OPTIONAL. A JSON object whose keys are `jti` values of previously received
  SETs and whose values are arrays of action `id` values that the Receiver has
  enforced.

## Action Errors in setErrs

This specification defines the following member of the value of a `setErrs`
entry, as defined in {{RFC8935}} and {{RFC8936}}:

actions

> OPTIONAL. A JSON object whose keys are action `id` values and whose values
  are objects with the members `err` (REQUIRED) and `description` (OPTIONAL),
  with the same semantics as the corresponding members of a `setErrs` value.
  The `err` value MUST be one of the codes in {{action-error-codes}}.

When `actions` is present in a `setErrs` entry, the entry's top-level `err`
MUST be `action_failed`. This indicates that the SET was received and validated,
and that one or more of its actions was not enforced. A SET MAY appear in both
`enforced` and `setErrs` when some of its actions were enforced and others were
not.

This is an extension of the semantics of `setErrs`, which otherwise reports only
errors in parsing and validating a SET. Transmitters that implement this
specification MUST distinguish the two cases by the presence of the `actions`
member.

## Example

The following is a non-normative example of an {{RFC8936}} poll request that
reports delivery and Enforcement Outcomes:

~~~ http
POST /ssf/poll/f67e39a0 HTTP/1.1
Host: tr.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=
Content-Type: application/json

{
  "ack": [
    "f52901c499611ef94540242ac12000322"
  ],
  "enforced": {
    "4d3559ec67504aaba65d40b0363faad8": ["a1"]
  },
  "setErrs": {
    "4d3559ec67504aaba65d40b0363faad8": {
      "err": "action_failed",
      "description": "One or more actions were not enforced",
      "actions": {
        "a2": {
          "err": "action_partial",
          "description": "Sessions terminated on web; mobile pending"
        }
      }
    }
  },
  "maxEvents": 10,
  "returnImmediately": true
}
~~~
{: title="Example: Poll request with enforced and action errors"}

## Action Error Codes {#action-error-codes}

action_unsupported
: The action's `type` is not in the stream's `actions_enforcement_requested`,
  or the Receiver does not implement it. The Receiver MUST NOT enforce it.

action_declined
: The Receiver's local policy refused the action.

action_failed
: The Receiver attempted the action and could not reach its postcondition.
  Also used as the top-level `err` of a `setErrs` entry that carries `actions`.

action_partial
: Some, but not all, of the Receiver's enforcement points reached the
  postcondition. Only valid for Action Types that define partial enforcement.

action_expired
: `enforce_by` passed before the Receiver could enforce the action.

## Obligations

Transmitter
: A Transmitter MUST NOT send an action whose `type` is not in the stream's
  `actions_enforcement_requested`. After a SET carrying actions is
  acknowledged, the Transmitter MUST NOT retransmit it while awaiting
  Enforcement Outcomes. A Transmitter MUST NOT automatically re-send an action
  that received an action error code. A Transmitter MUST NOT treat an action as
  enforced unless the `enforced` member says so; an action with no outcome by
  its `enforce_by` time MUST be treated as unknown. A Transmitter MAY reflect
  such failures in the stream's status or in operational monitoring.

Receiver
: For every action whose `type` is in the stream's
  `actions_enforcement_requested`, a Receiver MUST eventually report exactly one
  Enforcement Outcome. For any action whose `type` is not in that set, a
  Receiver MUST NOT enforce it and MUST report `action_unsupported`. A Receiver
  SHOULD report outcomes as soon as they are known and SHOULD NOT delay delivery
  acknowledgement while enforcement is in progress.

When using {{MULTI-SET-PUSH}}, a Transmitter collects pending Enforcement
Outcomes by sending requests with an empty `sets` object, as defined in that
specification.

# Defining Action Types {#action-definition}

## Required Elements

Each Action Type definition MUST specify:

* **Action Type URI.** Actions defined by OpenID specifications use the form
  `https://schemas.openid.net/secevent/<profile>/action-type/<name>`. Other
  parties MUST use URIs under a domain they control.
* **Applicable event types.** The event types that may carry the action.
* **Applicable subjects.** The subject identifier formats or subject types to
  which the action applies.
* **Postcondition.** What MUST be true at the Receiver's enforcement points for
  the action to be reported as enforced.
* **Partial enforcement.** What `action_partial` means for this action, or a
  statement that it is not applicable.
* **Parameters.** The members of `params`, if any.
* **Impact tier.** One of the tiers in {{impact-tiers}}.
* **Idempotency.** The action MUST be safe to enforce more than once.
* **Inverse action**, if one exists.
* **Expected latency**, as guidance for `enforce_by`.

A change to the meaning of an Action Type requires a new URI.

## Impact Tiers {#impact-tiers}

Low
: Re-verification. The subject can continue after satisfying a check (for
  example, re-authentication or step-up).

Medium
: Revocation of active grants. Tokens, sessions or delegations are ended; the
  subject can obtain new ones through normal means.

High
: Lockout or quarantine. The subject cannot regain access without
  administrative intervention.

Receivers SHOULD NOT include High-tier Action Types in
`receiver_actions_supported` without local safeguards such as rate limits,
anomaly detection or human approval (see {{sec-impact}}).

# Initial Action Types {#initial-actions}

## Revoke Tokens {#revoke-tokens}

Action Type URI:
: `https://schemas.openid.net/secevent/ssf/action-type/revoke-tokens`

Applicable event types:
: CAEP `credential-change`, CAEP `token-claims-change`, RISC
  `credential-compromise`, and other event types whose definitions permit it.

Applicable subjects:
: Any subject that tokens can be issued to.

Postcondition:
: No access token or refresh token issued to the subject at or before the SET's
  `iat` is accepted by any of the Receiver's enforcement points.

Partial enforcement:
: Some enforcement points still accept such tokens.

Parameters:
: `token_types` (OPTIONAL): an array of strings naming the token types to
  revoke, for example `access_token` and `refresh_token`. If omitted, all token
  types.

Impact tier:
: Medium.

Inverse:
: None.

Expected latency:
: Seconds.

## Terminate Sessions {#terminate-sessions}

Action Type URI:
: `https://schemas.openid.net/secevent/ssf/action-type/terminate-sessions`

Applicable event types:
: CAEP `credential-change`, CAEP `assurance-level-change`, RISC
  `account-disabled`, and other event types whose definitions permit it. Not
  applicable to CAEP `session-revoked`, which already implies this outcome.

Applicable subjects:
: Users, devices and sessions.

Postcondition:
: No session for the subject established at or before the SET's `iat` remains
  active at any of the Receiver's enforcement points.

Partial enforcement:
: Some sessions remain active.

Parameters:
: None.

Impact tier:
: Medium.

Inverse:
: None.

Expected latency:
: Seconds.

## Require Reauthentication {#require-reauthentication}

Action Type URI:
: `https://schemas.openid.net/secevent/ssf/action-type/require-reauthentication`

Applicable event types:
: CAEP `assurance-level-change`, CAEP `risk-level-change`, CAEP
  `device-compliance-change`, and other event types whose definitions permit it.

Applicable subjects:
: Users and sessions.

Postcondition:
: The subject's next request to any of the Receiver's enforcement points
  requires a fresh authentication.

Partial enforcement:
: Not applicable.

Parameters:
: `acr_values` (OPTIONAL): a space-separated string of requested
  Authentication Context Class Reference values, in order of preference.

Impact tier:
: Low.

Inverse:
: None.

Expected latency:
: Seconds.

## Disable Account {#disable-account}

Action Type URI:
: `https://schemas.openid.net/secevent/ssf/action-type/disable-account`

Applicable event types:
: RISC `account-disabled`, RISC `identifier-recycled`, and other event types
  whose definitions permit it.

Applicable subjects:
: User accounts.

Postcondition:
: The Receiver's account linked to the subject cannot be used to authenticate or
  to access resources until re-enabled by the Receiver.

Partial enforcement:
: Not applicable.

Parameters:
: None.

Impact tier:
: High.

Inverse:
: None defined by this specification. Re-enablement is a Receiver decision.

Expected latency:
: Minutes.

# Relationship to Other Profiles

Event profiles such as {{CAEP}}, {{RISC}} and {{MLE}} define what happened.
This specification defines a shared vocabulary for what the Transmitter requests
the Receiver to do about it. Profiles SHOULD reuse the Action Types defined here
where their postconditions fit, rather than defining overlapping ones, and MAY
define additional Action Types using the template in {{action-definition}}.

Enforcement Outcomes in this specification are operational signals. Profiles
that require evidence suitable for audit, such as a signed record that a
delegation revocation was enforced, SHOULD define a receipt event sent by the
Receiver over a separate stream, and MAY reference the action `id` and the
original SET's `jti` and `txn` in that event.

# Security Considerations {#security-considerations}

The Security Considerations of {{SSF}}, {{RFC8417}}, {{RFC8935}} and
{{RFC8936}} apply.

## Actions Are Requests {#sec-requests}

A Receiver MUST apply its own authorization and policy before enforcing any
action. Receipt of a validly signed SET from a trusted Transmitter is necessary
but not sufficient. Receivers MUST NOT enforce actions on subjects for which the
stream is not authorized under {{SSF}}.

## Impact and Abuse {#sec-impact}

A compromised or malfunctioning Transmitter can request disruptive actions at
scale. Receivers SHOULD rate-limit actions per stream, SHOULD monitor for
anomalous volumes of Medium- and High-tier actions, and SHOULD require
additional safeguards for High-tier actions. Receivers MAY reduce
`receiver_actions_supported` at any time by updating the stream.

## Integrity of Actions

Actions are carried inside the event payload of a signed SET and are therefore
covered by its signature. Receivers MUST NOT honor actions conveyed in any
unsigned envelope or transport-level field.

## Integrity of Outcomes

Enforcement Outcomes are conveyed in poll requests or push responses that are
protected by TLS but not signed. They are assertions by the Receiver and are
not suitable as non-repudiable audit evidence. See the receipt pattern described
in the previous section.

## Replay

Actions are idempotent by definition ({{action-definition}}). A Receiver that
receives a SET with a `jti` it has already processed MAY skip enforcement and
report the previously determined outcome.

# Privacy Considerations {#privacy-considerations}

The Privacy Considerations of {{SSF}} apply. `description` values in action
errors SHOULD NOT reveal internal identifiers, topology or information about
subjects beyond what the Transmitter already holds. Enforcement Outcomes reveal
to the Transmitter which Receivers act on which subjects; Transmitters SHOULD
treat this information with the same care as the events themselves.

# IANA Considerations {#iana}

## Security Event Token Error Codes

This specification requests registration of the following values in the
"Security Event Token Error Codes" registry established by {{Section 7.1 of
RFC8935}}:

* Error Code: `action_unsupported`
* Description: The requested action is not supported or not agreed for the
  stream.
* Change Controller: OpenID Foundation Shared Signals Working Group
* Specification Document(s): {{action-error-codes}} of this specification

* Error Code: `action_declined`
* Description: The Receiver's policy declined the requested action.
* Change Controller: OpenID Foundation Shared Signals Working Group
* Specification Document(s): {{action-error-codes}} of this specification

* Error Code: `action_failed`
* Description: The requested action could not be enforced.
* Change Controller: OpenID Foundation Shared Signals Working Group
* Specification Document(s): {{action-error-codes}} of this specification

* Error Code: `action_partial`
* Description: The requested action was enforced at only some enforcement
  points.
* Change Controller: OpenID Foundation Shared Signals Working Group
* Specification Document(s): {{action-error-codes}} of this specification

* Error Code: `action_expired`
* Description: The requested enforcement deadline passed before the action was
  enforced.
* Change Controller: OpenID Foundation Shared Signals Working Group
* Specification Document(s): {{action-error-codes}} of this specification

--- back

# Acknowledgements

The author thanks Tom Sato and Pieter Kasselman, whose work on Mandate
Lifecycle Events and WISE motivated this specification.

# Open Issues

* Should `transmitter_actions_supported` support a per-event-type map, so a
  Receiver can agree to an action for one event type but not another?
* Should an action ever carry its own target (for example, cascades to
  sub-agents), or is "the event's subject only" sufficient?
* Should the initial Action Types live in this specification or move into
  {{CAEP}} and {{RISC}}?
* Is a delivery method identifier needed for {{MULTI-SET-PUSH}} in
  `delivery_methods_supported`?

# Notices

Copyright (c) 2026 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer,
or other interested party a non-exclusive, royalty free, worldwide copyright
license to reproduce, prepare derivative works from, distribute, perform and
display, this Implementers Draft or Final Specification solely for the purposes
of (i) developing specifications, and (ii) implementing Implementers Drafts and
Final Specifications based on such documents, provided that attribution be made
to the OIDF as the source of the material, but that such attribution does not
indicate an endorsement by the OIDF.

The technology described in this specification was made available from
contributions from various sources, including members of the OpenID Foundation
and others. Although the OpenID Foundation has taken steps to help ensure that
the technology is available for distribution, it takes no position regarding the
validity or scope of any intellectual property or other rights that might be
claimed to pertain to the implementation or use of the technology described in
this specification or the extent to which any license under such rights might or
might not be available; neither does it represent that it has made any
independent effort to identify any such rights. The OpenID Foundation and the
contributors to this specification make no (and hereby expressly disclaim any)
warranties (express, implied, or otherwise), including implied warranties of
merchantability, non-infringement, fitness for a particular purpose, or title,
related to this specification, and the entire risk as to implementing this
specification is assumed by the implementer. The OpenID Intellectual Property
Rights policy requires contributors to offer a patent promise not to assert
certain patent claims against other contributors and against implementers. The
OpenID Foundation invites any interested party to bring to the attention of the
OpenID Foundation any copyrights, patents, patent applications, or other
proprietary rights that may cover technology that may be required to practice
this specification.
