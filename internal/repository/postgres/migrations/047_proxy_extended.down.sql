-- Reverse 047_proxy_extended.

DROP TABLE IF EXISTS proxy_locations;
DROP TABLE IF EXISTS proxy_access_list_clients;
DROP TABLE IF EXISTS proxy_access_list_auth;
DROP TABLE IF EXISTS proxy_access_lists;
DROP TABLE IF EXISTS proxy_dead_hosts;
DROP TABLE IF EXISTS proxy_streams;
DROP TABLE IF EXISTS proxy_redirections;

ALTER TABLE proxy_hosts DROP CONSTRAINT IF EXISTS fk_proxy_hosts_access_list;
ALTER TABLE proxy_hosts DROP COLUMN IF EXISTS access_list_id;
ALTER TABLE proxy_hosts DROP COLUMN IF EXISTS hsts_subdomains;
ALTER TABLE proxy_hosts DROP COLUMN IF EXISTS custom_nginx_config;
ALTER TABLE proxy_hosts DROP COLUMN IF EXISTS caching_enabled;
ALTER TABLE proxy_hosts DROP COLUMN IF EXISTS block_exploits;
