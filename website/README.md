# WAF Tuner documentation

The site renders the guides in [`../docs`](../docs). From this directory, use Node.js 22 or later.

```bash
npm ci
npm start
```

The local site is at `http://localhost:3000/waf-tuner/`. If the WAF Tuner UI is already using port 3000, run `npm start -- --port 3001`.

Run `npm run build` to verify links and render the static site into `build/`. Run `npm run serve` to preview the build.

Diagrams are Mermaid code blocks inside the Markdown pages, so edit them as text next to the prose they explain.
