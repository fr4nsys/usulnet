-- 050_firewall.down.sql — drop the firewall rule management tables.

DROP TRIGGER IF EXISTS update_firewall_rules_updated_at ON firewall_rules;

DROP INDEX IF EXISTS idx_firewall_audit_created;
DROP INDEX IF EXISTS idx_firewall_audit_host;
DROP INDEX IF EXISTS idx_firewall_rules_position;
DROP INDEX IF EXISTS idx_firewall_rules_chain;
DROP INDEX IF EXISTS idx_firewall_rules_enabled;
DROP INDEX IF EXISTS idx_firewall_rules_host;

DROP TABLE IF EXISTS firewall_audit_log;
DROP TABLE IF EXISTS firewall_rules;
