-- SentinelNet AI: planned PostgreSQL schema (design draft, v0.1).
-- NOT YET EXECUTED against PostgreSQL. Phase 3 will move this into Alembic
-- migrations with migration tests. Indexes beyond keys are deliberately omitted
-- until query patterns are measured.

CREATE TABLE organizations (
    org_id        text PRIMARY KEY CHECK (org_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    name          text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    retention_days integer NOT NULL DEFAULT 90 CHECK (retention_days > 0)
);

CREATE TABLE users (
    user_id       uuid PRIMARY KEY,
    email         text NOT NULL UNIQUE,
    password_hash text NOT NULL,                 -- argon2id; never plaintext
    failed_logins integer NOT NULL DEFAULT 0,
    locked_until  timestamptz,
    mfa_secret    text,                          -- MFA-ready; encrypted at rest
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    org_id  text NOT NULL REFERENCES organizations,
    user_id uuid NOT NULL REFERENCES users,
    role    text NOT NULL CHECK (role IN ('admin','analyst','viewer')),
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE sensors (
    org_id             text NOT NULL REFERENCES organizations,
    sensor_id          text NOT NULL CHECK (sensor_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    mode               text NOT NULL DEFAULT 'offline_pcap' CHECK (mode IN ('offline_pcap','live')),
    approved_interface text,                     -- required iff mode = 'live'
    permitted_cidrs    cidr[] NOT NULL,          -- explicit authorised scope
    authorised_by      uuid NOT NULL REFERENCES users,
    authorised_at      timestamptz NOT NULL,
    last_seen_at       timestamptz,
    PRIMARY KEY (org_id, sensor_id),
    CHECK (mode = 'offline_pcap' OR approved_interface IS NOT NULL)
);

CREATE TABLE events (
    org_id            text NOT NULL,
    event_id          char(64) NOT NULL,         -- idempotency key
    sensor_id         text NOT NULL,
    source            text NOT NULL CHECK (source IN ('zeek','suricata')),
    event_type        text NOT NULL,
    ts                timestamptz NOT NULL,      -- UTC
    src_ip            inet,
    dst_ip            inet,
    src_port          integer CHECK (src_port BETWEEN 0 AND 65535),
    dst_port          integer CHECK (dst_port BETWEEN 0 AND 65535),
    proto             text,
    flow_id           text,
    zeek_uid          text,
    community_id      text,
    signature_id      bigint,
    signature_rev     integer,
    signature_msg     text,
    category          text,
    severity          text NOT NULL,
    confidence        text,
    finding_class     text NOT NULL,
    evidence_refs     text[] NOT NULL DEFAULT '{}',
    raw_ref           text NOT NULL,
    data_origin       text NOT NULL CHECK (data_origin IN ('sample','offline_pcap','live')),
    processing_status text NOT NULL,
    attrs             jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (org_id, event_id),
    FOREIGN KEY (org_id, sensor_id) REFERENCES sensors
);

CREATE TABLE raw_evidence (                      -- access-restricted original records
    org_id   text NOT NULL,
    event_id char(64) NOT NULL,
    raw      bytea NOT NULL,
    PRIMARY KEY (org_id, event_id),
    FOREIGN KEY (org_id, event_id) REFERENCES events ON DELETE CASCADE
);

CREATE TABLE investigations (
    org_id      text NOT NULL REFERENCES organizations,
    inv_id      uuid NOT NULL,
    title       text NOT NULL,
    status      text NOT NULL DEFAULT 'new'
                CHECK (status IN ('new','triaged','investigating','resolved','false_positive','duplicate')),
    severity    text NOT NULL,
    confidence  text,
    assignee    uuid REFERENCES users,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, inv_id)
);

CREATE TABLE investigation_events (
    org_id   text NOT NULL,
    inv_id   uuid NOT NULL,
    event_id char(64) NOT NULL,
    link_reason text NOT NULL,                   -- evidence for every correlation
    PRIMARY KEY (org_id, inv_id, event_id),
    FOREIGN KEY (org_id, inv_id) REFERENCES investigations ON DELETE CASCADE,
    FOREIGN KEY (org_id, event_id) REFERENCES events
);

CREATE TABLE suppressions (
    org_id     text NOT NULL REFERENCES organizations,
    sup_id     uuid NOT NULL,
    match      jsonb NOT NULL,
    reason     text NOT NULL,
    created_by uuid NOT NULL REFERENCES users,
    expires_at timestamptz NOT NULL,             -- suppressions always expire
    PRIMARY KEY (org_id, sup_id)
);

CREATE TABLE audit_log (                         -- append-only; no UPDATE/DELETE grants
    audit_id   bigserial PRIMARY KEY,
    org_id     text NOT NULL,
    actor      uuid,
    action     text NOT NULL,
    target     text,
    detail     jsonb NOT NULL DEFAULT '{}',
    at         timestamptz NOT NULL DEFAULT now()
);
