RESET

```bash
docker compose down --remove-orphans --volumes
docker compose build
docker compose up -d
docker compose ps
curl -s http://localhost:8000/api/setup/status
```

Then open http://localhost:3000 and walk the wizard (mint token, connect a
model or skip). Headless equivalent for step 1:

```bash
curl -s -X POST http://localhost:8000/api/setup/bootstrap
```
