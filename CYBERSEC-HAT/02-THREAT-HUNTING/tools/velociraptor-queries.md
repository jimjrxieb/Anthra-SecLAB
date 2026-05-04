# Velociraptor Hunt Queries

Reference queries for common hunt hypotheses. Run via Velociraptor server console or `velociraptor query` CLI.

## Credential Dumping (T1003)

```vql
-- Find processes accessing /proc/*/mem (LSASS equivalent on Linux)
SELECT Pid, Name, CommandLine, Username, CreateTime
FROM pslist()
WHERE Name =~ "python|perl|ruby|gdb|strace|ltrace"

-- Find ptrace activity
SELECT * FROM audit()
WHERE syscall = "ptrace"
```

## Process Injection (T1055)

```vql
-- Find processes with executable anonymous memory (shellcode indicator)
SELECT Pid, Name, CommandLine
FROM proc_maps()
WHERE protection =~ "rwx" AND filename = ""
GROUP BY Pid

-- Find unusual parent-child relationships
SELECT Pid, Ppid, Name, CommandLine, Exe
FROM pslist()
WHERE (Name = "bash" AND Ppid IN (SELECT Pid FROM pslist() WHERE Name =~ "cron|apache|nginx"))
```

## Scheduled Task Persistence (T1053)

```vql
-- Enumerate all cron entries across all users
SELECT User, Command, Minute, Hour, DayOfMonth, Month, DayOfWeek
FROM crontab()

-- Find recently modified cron files
SELECT FullPath, Mtime, Size, Mode
FROM glob(globs=["/etc/cron*/**", "/var/spool/cron/**"])
WHERE Mtime > now() - 86400
```

## Lateral Movement via SSH (T1021.002)

```vql
-- Find SSH connections in auth logs
SELECT * FROM parse_records_with_regex(
    file="/var/log/auth.log",
    regex="Accepted (?P<Method>\\S+) for (?P<User>\\S+) from (?P<SrcIP>\\S+)"
)

-- Find SSH authorized_keys files
SELECT FullPath, Mtime, Size
FROM glob(globs=["/home/*/.ssh/authorized_keys", "/root/.ssh/authorized_keys"])
```
