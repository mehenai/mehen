-- Enrolment: the typed fingerprint group and one live link per key (V-5).

-- Wrong hidden-group submissions on approve. Five reject the enrolment, so
-- a 20-bit group cannot be guessed through the page.
ALTER TABLE enrolments ADD COLUMN group_attempts INTEGER NOT NULL DEFAULT 0;

-- POST /v1/enrol expires the older pending row for the same key, and an
-- expired page looks for the newer one.
CREATE INDEX enrolments_thumbprint ON enrolments (thumbprint, status);
