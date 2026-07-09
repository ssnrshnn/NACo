# Backup & restore

Use the bundled `nacoctl` CLI from inside the container:

```bash
# Backup — works for both Postgres and SQLite
docker compose exec naco nacoctl backup --output /backups/naco-$(date +%F).sql.gz

# Encrypted backup (age is bundled in the image; keep key.txt OFF the server)
age-keygen -o key.txt                      # once — prints the age1… public key
docker compose exec naco nacoctl backup \
  --output /backups/naco-$(date +%F).sql.gz.age \
  --age-recipient age1your...publickey

# Restore (DESTRUCTIVE)
docker compose exec naco nacoctl restore --input /backups/naco-2026-05-12.sql.gz
docker compose exec naco nacoctl restore \
  --input /backups/naco-2026-05-12.sql.gz.age --age-identity /run/secrets/key.txt
```

For Postgres deployments, the same tool wraps `pg_dump` / `psql`; for
SQLite it copies the file. Either way the backup is portable across NACo
v2.x. Plain dumps contain live credentials — prefer `--age-recipient`
for anything leaving the host.

---
