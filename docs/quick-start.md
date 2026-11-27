# Quickstart

Use the local lab to follow a ModSecurity alert from the audit log to a reviewable case. You need Docker Compose and an OpenAI-compatible chat completions endpoint.

## Start the lab

From the repository root, copy the example environment file.

```bash
cp lab-data/.env.example lab-data/.env
```

Set `LLM_API_BASE_URL`, `LLM_API_KEY`, and `LLM_MODEL` in `lab-data/.env`. Set `LLM_THINKING=off` for plain chat completions. The example explicitly enables thinking for compatible providers. For a provider running on the Docker host, use an address reachable from the backend container, such as `http://host.docker.internal:8001/v1`.

```bash
docker compose up --build -d
```

Open the [local dashboard](http://localhost:3000). The lab includes DVWA and the Flask Lab Shop. Compose mounts a profile for each application.

## Send a lab request

The `Host` header selects the Flask Lab Shop. Send a product search with SQL-like words in the query.

```bash
curl -G -H 'Host: shop.lab' http://127.0.0.1:8080/search \
  --data-urlencode 'q=union select hoodie'
```

1. Open **Events** to check that ModSecurity recorded the request and reported matches.
2. Open **Cases** to see the verdict for each match as analysis completes. Repeated equivalent matches can share an existing case.
3. Open **Exceptions** to review any draft that passed the server checks. A case can have a false-positive verdict without an exclusion.

The lab runs ModSecurity in `DetectionOnly` mode. A successful HTTP response can still have CRS matches.

## If a case has no verdict

Check the audit path and readability in **Settings**, then check the model, queue, and ruleset in **Analytics**. For a provider or container startup error, inspect the backend log.

```bash
docker compose logs --tail=100 waf-tuner-backend
```

If you changed `lab-data/.env`, recreate the backend container so it receives the new environment.

```bash
docker compose up -d --force-recreate waf-tuner-backend
```

For your own WAF, follow the [integration guide](./integrations.md) and describe one noisy route in an [application profile](./profiles.md).
