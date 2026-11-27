const repo = 'https://github.com/Vulcanite/waf-tuner';

module.exports = {
  title: 'WAF Tuner',
  tagline: 'Offline false-positive triage for ModSecurity and OWASP CRS',
  url: 'https://vulcanite.github.io',
  baseUrl: '/waf-tuner/',
  trailingSlash: true,
  onBrokenLinks: 'throw',
  markdown: {format: 'detect', mermaid: true, hooks: {onBrokenMarkdownLinks: 'throw'}},
  themes: ['@docusaurus/theme-mermaid'],
  presets: [
    ['classic', {
      docs: {
        path: '../docs',
        sidebarPath: require.resolve('./sidebars.js'),
      },
      blog: false,
      theme: {customCss: require.resolve('./src/css/site.css')},
    }],
  ],
  themeConfig: {
    colorMode: {defaultMode: 'light', respectPrefersColorScheme: true},
    mermaid: {theme: {light: 'neutral', dark: 'dark'}},
    navbar: {
      title: 'WAF Tuner',
      items: [
        {type: 'doc', docId: 'overview', label: 'Why', position: 'left'},
        {type: 'doc', docId: 'quick-start', label: 'Quickstart', position: 'left'},
        {type: 'doc', docId: 'architecture', label: 'How it works', position: 'left'},
        {type: 'doc', docId: 'results', label: 'Results', position: 'left'},
        {type: 'doc', docId: 'roadmap', label: 'Roadmap', position: 'left'},
        {href: repo, label: 'GitHub', position: 'right'},
      ],
    },
    footer: {
      style: 'light',
      links: [
        {label: 'Limits and data handling', to: '/docs/limits/'},
        {label: 'GitHub', href: repo},
        {label: 'Apache-2.0', href: `${repo}/blob/master/LICENSE`},
      ],
    },
    prism: {additionalLanguages: ['bash', 'json', 'apacheconf']},
  },
};
