-- Append-only protection for audit history. This is a separate migration because
-- previously generated projects may have already applied the base table migration.
-- Owners/superusers can still disable triggers: use separate restricted app roles.
CREATE FUNCTION primarykit_reject_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only'
        USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER audit_events_reject_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION primarykit_reject_audit_mutation();

CREATE TRIGGER audit_events_reject_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION primarykit_reject_audit_mutation();
