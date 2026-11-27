# WAF Tuner documentation

The site renders the guides in [`../docs`](../docs). From this directory, use Node.js 22 or later.

```bash
npm ci
npm start
```

The local site is at `http://localhost:3000/waf-tuner/`. If the WAF Tuner UI is already using port 3000, run `npm start -- --port 3001`.

Run `npm run build` to verify links and render the static site into `build/`. Run `npm run serve` to preview the build.

Diagrams are made in Eraser (file `0qBH5xzRdtD68ZwhrvuT`: "WAF Tuner: how it works", "what the model sees", "review checks") and exported as light and dark PNGs into `static/diagrams/`. Never use Mermaid.
