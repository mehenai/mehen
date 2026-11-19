-- Additive only. What a machine asked for at enrolment (EnrolRequestedScope,
-- canonical JSON), NULL when it asked for the usual scope. The registered
-- scope is the usual one narrowed by it.
ALTER TABLE enrolments ADD COLUMN requested_scope TEXT;
