import React from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Diagram from '../components/Diagram';

const rule = `SecRule REQUEST_FILENAME "@streq /support" \\
    "id:1027971,phase:1,pass,nolog,t:none,chain"
  SecRule REQUEST_METHOD "@streq POST" "t:none,chain"
  SecRule REQUEST_HEADERS:Host "@rx ^shop[.]lab[.]?(?::[0-9]+)?$" \\
    "t:none,t:lowercase,ctl:ruleRemoveTargetById=942150;ARGS:message"`;

function CaseFile() {
  return (
    <div className="case" aria-label="Example case from the lab">
      <div className="case-head">
        <span>Case · shop.lab</span>
        <span className="case-id">POST /support</span>
      </div>
      <div className="case-log">
        <span className="dim">ARGS:message =</span> "Pasting <mark>console.log(</mark>window.cart) shows an empty list."
      </div>
      <div className="case-flag">
        <span className="tag tag--amber">CRS 942150</span>
        <span>SQL function call detected</span>
      </div>
      <div className="case-verdict">
        <span className="stamp">False positive</span>
        <dl>
          <dt>Rule looks for</dt>
          <dd>SQL function names such as <code>log()</code> followed by an opening parenthesis.</dd>
          <dt>Payload is</dt>
          <dd>A support message quoting a browser console call.</dd>
          <dt>Why</dt>
          <dd><code>log(</code> belongs to JavaScript <code>console.log</code>, and <code>/support</code> accepts pasted code.</dd>
        </dl>
      </div>
      <div className="case-rule">
        <div className="case-rule-head"><span className="tag tag--green">Draft exclusion</span><span>awaiting your approval</span></div>
        <pre>{rule}</pre>
      </div>
    </div>
  );
}

const misreads = [
  ['A product review', <>I'd call it <mark>'select'</mark> quality, <mark>or</mark> 'premium'</>, 'SQL injection'],
  ['A support ticket', <>Pasting <mark>console.log(</mark>window.cart) shows…</>, 'Node.js and SQL injection'],
  ['A preferences cookie', <>{'{'}"theme<mark>":"</mark>dark","recent<mark>":[</mark>"tote"]{'}'}</>, 'SQL authentication bypass'],
];

const roadmap = [
  ['Now', 'ModSecurity v3 + OWASP CRS 4', 'Offline triage, explanations, server-built exclusions, JSON and OpenAPI profiles.'],
  ['Next', 'Coraza', 'Read Coraza audit logs and verify exclusions end to end on the engine new self-hosted WAFs are choosing.'],
  ['Then', 'Real-app evidence', 'Run the model on the WordPress and Nextcloud benchmark and measure what exclusions let through.'],
];

export default function Home() {
  return (
    <Layout title="Offline false-positive triage for ModSecurity" description="WAF Tuner reads the ModSecurity audit log, asks a model of your choice whether each OWASP CRS match is a false positive, explains why, and drafts a narrow exclusion for you to review.">
      <main className="home">
        <section className="hero">
          <div className="wrap hero-grid">
            <div>
              <p className="kicker">Open source · ModSecurity + OWASP CRS</p>
              <h1>Your WAF flags patterns.<br /><span>WAF Tuner reads the meaning.</span></h1>
              <p className="lede">
                It reads your ModSecurity audit log offline, asks a model you choose whether each CRS match is a real attack,
                explains the answer in plain words, and drafts the narrowest exclusion that fixes a false positive. You approve it.
              </p>
              <div className="cta">
                <Link className="btn btn--primary" to="/docs/quick-start/">Run the lab</Link>
                <Link className="btn btn--ghost" to="/docs/overview/">Why it exists</Link>
              </div>
              <ul className="hero-facts">
                <li>Never in the request path</li>
                <li>Any OpenAI-compatible model</li>
                <li>Never edits your WAF</li>
              </ul>
            </div>
            <CaseFile />
          </div>
        </section>

        <section className="band">
          <div className="wrap">
            <p className="label">The problem</p>
            <h2>CRS matches patterns, not meaning.</h2>
            <p className="sub">Three ordinary values from the lab, and what the Core Rule Set thought they were.</p>
            <div className="misreads">
              {misreads.map(([what, value, thought]) => (
                <div className="misread" key={what}>
                  <span className="misread-what">{what}</span>
                  <code className="misread-value">{value}</code>
                  <span className="misread-thought"><span className="tag tag--amber">flagged</span> {thought}</span>
                </div>
              ))}
            </div>
            <p className="sub">At paranoia levels that catch real attacks, these arrive by the hundred. Teams lower the level, write broad exclusions, or stop reading. All three give protection away.</p>
          </div>
        </section>

        <section className="band band--alt">
          <div className="wrap">
            <p className="label">How it works</p>
            <h2>Beside your WAF, not in front of it.</h2>
            <Diagram name="overview" alt="HTTP traffic goes through ModSecurity with CRS, which writes an audit log. WAF Tuner ingests it; an analysis worker combines the match with the app profile and CRS rule, asks any LLM, and server checks either build an exclusion draft for you to approve or withhold it." />
            <ol className="steps">
              <li><b>Read</b><span>Tail the JSON audit log and group repeated matches, so each false positive is judged once.</span></li>
              <li><b>Judge</b><span>Give the model the rule, the redacted value and your app profile. It must say what the rule looks for, what the value is, and why they differ.</span></li>
              <li><b>Check</b><span>The server, not the model, builds one exclusion: one rule, one field, one route. Missing evidence or a conflicting verdict withholds it.</span></li>
              <li><b>Decide</b><span>You review the evidence and the rule, approve it, and deploy it your way.</span></li>
            </ol>
            <Link className="more" to="/docs/architecture/">Read the architecture</Link>
          </div>
        </section>

        <section className="band band--dark">
          <div className="wrap">
            <p className="label">Early results</p>
            <h2>No attacks cleared. Most noise explained.</h2>
            <div className="stats">
              <div><b>0<small>/202</small></b><span>attack matches cleared</span></div>
              <div><b>200<small>/202</small></b><span>attack matches detected</span></div>
              <div><b>51<small>/62</small></b><span>harmless matches cleared</span></div>
              <div><b>100%</b><span>verdicts fully explained</span></div>
            </div>
            <p className="fine">DeepSeek Flash on 75 lab requests (264 labelled matches), threshold 0.75. Small and lab-made: read it as direction, not proof. <Link to="/docs/results/">Method and caveats</Link></p>
          </div>
        </section>

        <section className="band">
          <div className="wrap two">
            <div className="card card--yes">
              <h3>What it does</h3>
              <ul>
                <li>Works offline from the audit log.</li>
                <li>Runs on any OpenAI-compatible endpoint, including a model you host.</li>
                <li>Explains every verdict in three fixed fields.</li>
                <li>Builds narrow exclusions itself and withholds them when evidence is weak.</li>
              </ul>
            </div>
            <div className="card card--no">
              <h3>What it does not do</h3>
              <ul>
                <li>Block traffic or touch your WAF configuration.</li>
                <li>Rate, bot, DDoS or campaign detection.</li>
                <li>Replace a managed WAF's other services.</li>
                <li>Remove the trade-off: an excluded field lets a later attack past that rule. <Link to="/docs/limits/">Limits</Link></li>
              </ul>
            </div>
          </div>
        </section>

        <section className="band band--alt">
          <div className="wrap">
            <p className="label">Roadmap</p>
            <h2>Next stop: Coraza.</h2>
            <div className="timeline">
              {roadmap.map(([when, what, body]) => (
                <div className={`tl tl--${when.toLowerCase()}`} key={when}>
                  <span className="tl-when">{when}</span>
                  <h3>{what}</h3>
                  <p>{body}</p>
                </div>
              ))}
            </div>
            <Link className="more" to="/docs/roadmap/">Full roadmap</Link>
          </div>
        </section>
      </main>
    </Layout>
  );
}
