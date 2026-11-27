# Application profiles

An application profile tells the analyzer what an application is (language, framework,
data stores) and what each route's parameters mean. The model reads it to judge whether
a CRS match is a false positive, and a copyable exclusion needs a specific route that
documents the exact parameter. Profiles never disable CRS rules or skip inspection.

You can create profiles in three ways:

- **Files**: one JSON file per application in `PROFILES_DIR`, loaded at startup.
- **UI or API**: the Application Profiles page, or `POST /api/application-profiles`.
- **OpenAPI import**: generate a profile from an OpenAPI 3.x JSON document (see below).

Every change creates a new immutable version of the profile. Affected cases become stale.
Use **Reanalyze** on a case to run it with the current profile.

## File format

```json
{
  "name": "catalog",
  "host_patterns": ["catalog.example.com", "*.catalog.internal"],
  "context": {
    "languages": ["python"],
    "frameworks": ["django"],
    "data_stores": ["postgresql"],
    "notes": "Internal product catalog. Search uses the ORM; no raw SQL."
  },
  "routes": [
    {
      "path": "/search",
      "methods": ["GET"],
      "parameters": {
        "q": "free-text product search; people type names, quotes and punctuation",
        "REQUEST_COOKIES:prefs": "JSON UI preferences written by front-end script"
      },
      "notes": "q is bound as a query parameter."
    },
    {
      "path": "/products/{product_id}",
      "methods": ["GET"],
      "parameters": {"product_id": "numeric product id (path segment)"}
    },
    {
      "path": "/api/cart",
      "methods": ["POST"],
      "parameters": {"json.gift_message": "free-text gift message"}
    },
    {"path": "/*", "parameters": {}, "notes": "General context for undocumented paths."}
  ]
}
```

| Field | Meaning |
|-------|---------|
| `name` | Unique profile name (1–200 characters). Files and versions are matched by name. |
| `host_patterns` | Hostnames the profile covers. Wildcards (`*`, `?`, `[...]`) are allowed; empty or `["*"]` means any host. An exact host beats a wildcard. |
| `context` | Application facts. The model sees `purpose`, `name`, `languages`, `frameworks`, `data_stores` and `notes`. |
| `routes[].path` | Absolute path. `{param}` matches one path segment; a `/*` suffix matches the prefix and everything below it. An exact path beats a template, and a template beats a prefix. |
| `routes[].methods` | HTTP methods. Omit or leave empty for any method. |
| `routes[].parameters` | What each input means, keyed the way ModSecurity names it (below). |
| `routes[].notes` | Free-text route notes for the model. |
| `source_metadata` | Optional provenance. `type`, `verified` and `seeded` are shown to the model. |

Parameter keys follow `profile_match.route_parameter_key`:

- query, form and path arguments: the plain name, such as `q`;
- JSON body fields: ModSecurity's name, `json.<field>` (for example `json.sku`);
- cookies: `REQUEST_COOKIES:<name>`;
- headers: `REQUEST_HEADERS:<name>`.

A cookie entry never covers an argument with the same name, and the other way round.
Cookie and header names ignore case. Only a specific route (not `/*`) that documents
the exact parameter can produce a copyable exclusion.

Limits, shared by files, the API and the OpenAPI import: at most 1000 routes, 200
parameters per route, 2000 characters per parameter meaning or route note, 100 host
patterns, and 2 MB per file or OpenAPI document.

## Loading files

At startup the backend reads every `*.json` file in `PROFILES_DIR` (default
`<DATA_DIR>/profiles`) in name order:

- A file with a new name creates version 1 of that profile.
- A changed file creates the next version of the profile with that name.
- An unchanged file does nothing. A version created in the UI after the file was loaded
  is kept until the file changes.
- A file whose content an existing version already has does nothing.
- Profiles whose names no file uses (for example those made in the UI) are never touched.
- A file that is not valid JSON or fails validation is logged as an error and skipped;
  startup continues. If two files use the same name, the second is skipped.

File-sourced versions carry `source_metadata.profile_file` with the file name and its
sha256. Restart the backend to pick up file changes.

The lab's profiles are in `lab/profiles/` (`dvwa.json` is `default-lab`, `shop.json` is
`shop-lab`). Docker Compose mounts that directory read-only at `/profiles` and sets
`PROFILES_DIR=/profiles`; `scripts/e2e_baremetal.sh` points `PROFILES_DIR` at it too.

## OpenAPI import

An OpenAPI 3.x **JSON** document can be turned into a profile. YAML is not supported
(the converter uses only the Python standard library); convert YAML to JSON first.

- **UI**: Application Profiles → Import OpenAPI (paste or upload the spec, then name,
  hosts and stack).
- **API**: `POST /api/application-profiles/import-openapi` with
  `{"spec": "<JSON text>", "name": "...", "host_patterns": [...], "context": {...}}`, plus
  optional `base_path` and `catch_all` (default `true`). It creates version 1, or the next
  version when the name exists.
- **CLI**: write a profile file for `PROFILES_DIR`:

  ```sh
  python3 scripts/openapi_to_profile.py lab/flask-app/openapi.json --name shop \
      --host shop.lab --language python --framework flask --data-store sqlite \
      --output data/profiles/shop.json
  ```

OpenAPI does not describe the stack, so `languages`, `frameworks`, `data_stores`, notes
and host patterns come from you. The converter maps:

| OpenAPI | Profile |
|---------|---------|
| each path (`{param}` kept), prefixed with `base_path` or the first server URL's path | one route |
| the path's operations | `methods` |
| `in: query` and `in: path` parameters | plain name |
| `in: header` / `in: cookie` parameters | `REQUEST_HEADERS:<name>` / `REQUEST_COOKIES:<name>` |
| top-level `requestBody` properties for `application/json` (and `+json`) | `json.<name>`, ModSecurity's name for JSON fields |
| top-level properties for `application/x-www-form-urlencoded` and `multipart/form-data` | plain name |
| description, type, format, enum and example | a short meaning string (at most 300 characters) |
| operation summaries | route `notes` |
| `info.title` | `context.purpose`, unless you set one |

Path-level parameters apply to every operation under the path. `allOf`, `oneOf` and
`anyOf` body schemas contribute their properties. A `/*` catch-all route is added unless
`catch_all` is false (`--no-catch-all`). Imported profiles carry
`source_metadata: {"type": "openapi", "verified": false, ...}`; review the meanings before
relying on them, since they come from the spec author. Check the meaning for each HTTP
method before drafting rules. Current imports combine operations on the same path into
one profile route. Create separate route entries when a field means different things on
two methods.

The spec is treated as untrusted. Besides the profile limits above, only local `$ref`s
(`#/...`) are followed, `$ref` chains stop at depth 16, at most 20 000 schema nodes are
visited, and control characters are removed from text. A spec that breaks a size, count
or `$ref` limit is rejected (HTTP 400, or 422 for an oversized request) rather than
partly imported. Long descriptions and enum lists are shortened, and parameters with
names over 256 characters are skipped.

`lab/flask-app/openapi.json` describes the Lab Shop. Use it as an example of what the
importer can read. The running Compose lab mounts the hand-written `shop-lab` profile.
