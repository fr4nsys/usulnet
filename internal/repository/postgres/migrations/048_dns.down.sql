-- Rolls back 048_dns.
DROP TABLE IF EXISTS dns_audit_log;
DROP TABLE IF EXISTS dns_acme_orders;
DROP TABLE IF EXISTS dns_records;
DROP TABLE IF EXISTS dns_providers;
