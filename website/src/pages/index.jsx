import React from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Diagram from '../components/Diagram';

export default function Home() {
  return (
    <Layout title="Documentation" description="Use WAF Tuner to review ModSecurity alerts and draft scoped OWASP CRS exclusions offline.">
      <main className="docs-home">
        <section className="home-hero">
          <div className="site-wrap home-grid">
            <div className="home-intro">
              <p className="home-kicker">ModSecurity / OWASP CRS</p>
              <h1>Tune your WAF<br />with <em>context.</em></h1>
              <p className="home-deck">Review ModSecurity false positives offline. An LLM explains each match, and WAF Tuner prepares a scoped exclusion for you to review.</p>
              <div className="home-actions">
                <Link className="home-button home-button--primary" to="/docs/quick-start/">Run the quickstart <span aria-hidden="true">↗</span></Link>
                <Link className="home-button" to="/docs/architecture/">Read the architecture</Link>
              </div>
            </div>
            <div className="home-visual">
              <header><span className="panel-dot" /> From audit log to draft</header>
              <Diagram name="overview" eager alt="WAF Tuner reads the ModSecurity audit log, consults a configured model, and gives a scoped draft to an operator for review." />
            </div>
          </div>
        </section>
        <section className="site-wrap home-guides" aria-labelledby="guides-title">
          <h2 id="guides-title">Operator guide</h2>
          <div className="guide-grid">
            <Link to="/docs/integrations/" className="guide-link">
              <h3>Connect your WAF <span aria-hidden="true">↗</span></h3>
              <p>Choose a model, mount the audit log, and point WAF Tuner at the CRS rules you run.</p>
            </Link>
            <Link to="/docs/profiles/" className="guide-link">
              <h3>Describe your app <span aria-hidden="true">↗</span></h3>
              <p>Give the model the stack and the meaning of a field on a noisy route.</p>
            </Link>
            <Link to="/docs/review/" className="guide-link">
              <h3>Review an exclusion <span aria-hidden="true">↗</span></h3>
              <p>Read the verdict, check the proposed scope, and understand why a draft can be withheld.</p>
            </Link>
          </div>
        </section>
        <footer className="site-wrap home-footer">
          <Link to="/docs/limits/">Limits and data handling</Link>
          <Link to="/docs/roadmap/">Future work</Link>
          <a href="https://github.com/Vulcanite/waf-tuner/blob/master/LICENSE">Apache-2.0</a>
        </footer>
      </main>
    </Layout>
  );
}
