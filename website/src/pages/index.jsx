import React from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import CodeBlock from '@theme/CodeBlock';

const verdict = `{
  "classification": "false_positive",
  "rule_looks_for": "SQL function names such as log() followed by an opening parenthesis, as used in SQL injection payloads.",
  "payload_is": "A free-text support message: 'Pasting console.log(window.cart) shows an empty list.'",
  "why": "The matched log( belongs to JavaScript console.log, not an SQL function call, and the /support route explicitly accepts pasted code and error text."
}`;

const rule = `SecRule REQUEST_FILENAME "@streq /support" "id:1027971,phase:1,pass,nolog,t:none,chain"
    SecRule REQUEST_METHOD "@streq POST" "t:none,chain"
    SecRule REQUEST_HEADERS:Host "@rx ^shop[.]lab[.]?(?::[0-9]+)?$" "t:none,t:lowercase,ctl:ruleRemoveTargetById=942150;ARGS:message"`;

const steps = [
  ['Your WAF logs', 'ModSecurity with OWASP CRS keeps serving traffic and writes its JSON audit log. Nothing changes on the request path.'],
  ['WAF Tuner reads the log', 'Offline, it groups repeated matches and keeps the exact rule, field and value behind each one.'],
  ['A model judges the payload', 'Any OpenAI-compatible model, self-hosted or hosted, gets the rule, the redacted value and your application profile, and explains its verdict.'],
  ['The server writes the rule', 'For a false positive that passes its checks, WAF Tuner builds one narrow exclusion: one rule, one field, one route. The model never writes rule text.'],
  ['You decide', 'You review the evidence and the rule, approve it, and deploy it through your own process.'],
];

export default function Home() {
  return (
    <Layout title="Offline false-positive triage for ModSecurity" description="WAF Tuner reads the ModSecurity audit log, asks a model of your choice whether each OWASP CRS match is a false positive, explains why, and drafts a narrow exclusion for you to review.">
      <main className="home">
        <header className="home-hero wrap">
          <p className="eyebrow">For teams that run their own ModSecurity + OWASP CRS</p>
          <h1>Find the false positives in your WAF logs, and know why they are false.</h1>
          <p className="lede">
            CRS matches patterns, not meaning: <code>select</code> in a product review or <code>console.log(</code> in a support ticket looks like an attack.
            WAF Tuner reads your audit log offline, asks a model of your choice to judge each match against what your application actually accepts,
            and drafts a narrow exclusion for you to review.
          </p>
          <div className="actions">
            <Link className="button button--primary button--lg" to="/docs/quick-start/">Run the lab in 15 minutes</Link>
            <Link className="button button--secondary button--lg" to="/docs/overview/">Why this exists</Link>
          </div>
        </header>

        <section className="wrap section">
          <h2>One real match, start to finish</h2>
          <p className="section-lede">
            From the lab: a customer pastes <code>console.log(window.cart)</code> into the support form. CRS rule 942150 sees <code>log(</code> and flags SQL injection.
          </p>
          <div className="example">
            <div>
              <h3>The model's verdict</h3>
              <CodeBlock language="json">{verdict}</CodeBlock>
            </div>
            <div>
              <h3>The exclusion the server builds</h3>
              <CodeBlock language="apacheconf">{rule}</CodeBlock>
              <p className="note">Rule 942150 stops inspecting only <code>message</code>, only on <code>POST /support</code> for this host. Every other rule still inspects that field.</p>
            </div>
          </div>
        </section>

        <section className="wrap section">
          <h2>How it works</h2>
          <ol className="steps">
            {steps.map(([title, body]) => (
              <li key={title}><strong>{title}</strong><span>{body}</span></li>
            ))}
          </ol>
          <p><Link to="/docs/architecture/">Read the architecture →</Link></p>
        </section>

        <section className="wrap section two-col">
          <div>
            <h2>What it does</h2>
            <ul className="plain">
              <li>Works offline from the audit log. Inference never sits in the request path.</li>
              <li>Uses any OpenAI-compatible endpoint, including a model you host yourself.</li>
              <li>Explains every verdict: what the rule looks for, what the value is, why they differ.</li>
              <li>Builds exclusions itself, withholds them when evidence is missing or conflicts, and waits for your approval.</li>
            </ul>
          </div>
          <div>
            <h2>What it does not do</h2>
            <ul className="plain">
              <li>It does not block traffic or edit your WAF configuration.</li>
              <li>It judges payloads only: no rate, bot, DDoS or campaign detection.</li>
              <li>It does not replace a managed WAF's other services.</li>
              <li>It does not remove the risk of an exclusion. A later attack in an excluded field passes that rule. <Link to="/docs/limits/">Limits</Link></li>
            </ul>
          </div>
        </section>

        <section className="wrap section">
          <h2>Early results</h2>
          <p className="section-lede">DeepSeek Flash on 75 lab requests (264 labelled matches). Small and lab-made, so read it as direction, not proof.</p>
          <div className="stats">
            <div><b>0 / 202</b><span>attack matches cleared</span></div>
            <div><b>200 / 202</b><span>attack matches detected</span></div>
            <div><b>51 / 62</b><span>harmless matches cleared at threshold 0.75</span></div>
            <div><b>100%</b><span>verdicts with a complete explanation</span></div>
          </div>
          <p><Link to="/docs/results/">Full results, method and caveats →</Link></p>
        </section>

        <section className="wrap section">
          <h2>Where it is going</h2>
          <p className="section-lede">
            Next is <strong>Coraza</strong>, OWASP's Go WAF, so WAF Tuner works with the engine new self-hosted deployments are choosing.
            After that: running the model on the WordPress and Nextcloud benchmark, and measuring what approved exclusions would let through.
          </p>
          <p><Link to="/docs/roadmap/">Roadmap →</Link></p>
        </section>
      </main>
    </Layout>
  );
}
