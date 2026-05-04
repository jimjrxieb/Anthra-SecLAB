# OSQuery Hunt Queries

SQL-based endpoint telemetry queries for threat hunting. Run via `osqueryi` or osquery fleet.

## Credential Dumping (T1003)

```sql
-- Processes with open handles to sensitive files
SELECT p.pid, p.name, p.cmdline, p.username, pof.path
FROM process_open_files pof
JOIN processes p ON pof.pid = p.pid
WHERE pof.path LIKE '/etc/shadow%' OR pof.path LIKE '/etc/passwd%';

-- Processes using ptrace (memory inspection)
SELECT pid, name, cmdline, username
FROM processes
WHERE on_disk = 0 OR cmdline LIKE '%ptrace%' OR cmdline LIKE '%gdb%';
```

## Persistence — Scheduled Tasks (T1053)

```sql
-- All cron jobs
SELECT c.command, c.path, c.minute, c.hour, u.username
FROM crontab c
LEFT JOIN users u ON c.username = u.username;

-- Recently modified startup items
SELECT name, path, source, status, last_run_time
FROM startup_items
ORDER BY last_run_time DESC
LIMIT 20;
```

## Lateral Movement Indicators (T1021)

```sql
-- Active network connections
SELECT p.name, p.cmdline, p.username, l.local_address, l.local_port, l.remote_address, l.remote_port, l.state
FROM listening_ports l
JOIN processes p ON l.pid = p.pid
WHERE l.state = 'ESTABLISHED';

-- SSH keys across all users
SELECT u.username, ak.key_type, ak.key, ak.comment, ak.key_file
FROM users u
JOIN authorized_keys ak ON u.username = ak.username;
```

## Process Injection (T1055)

```sql
-- Processes with writable+executable memory segments
SELECT p.pid, p.name, p.cmdline, pm.start, pm.end, pm.permissions, pm.path
FROM process_memory_map pm
JOIN processes p ON pm.pid = p.pid
WHERE pm.permissions LIKE '%x%' AND pm.permissions LIKE '%w%' AND pm.path = ''
LIMIT 50;
```
