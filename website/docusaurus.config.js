const repo = 'https://github.com/Vulcanite/waf-tuner';

module.exports = {
  title: 'WAF Tuner',
  tagline: 'Offline false-positive triage for ModSecurity and OWASP CRS',
  url: 'https://vulcanite.github.io',
  baseUrl: '/waf-tuner/',
  trailingSlash: true,
  onBrokenLinks: 'throw',
  markdown: {format: 'detect', hooks: {onBrokenMarkdownLinks: 'throw'}},
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
    navbar: {
      title: 'WAF Tuner',
      logo: {alt: '', src: 'img/mark.svg'},
      items: [
        {to: '/docs/overview/', label: 'Why', position: 'left'},
        {to: '/docs/quick-start/', label: 'Quickstart', position: 'left'},
        {to: '/docs/architecture/', label: 'How it works', position: 'left'},
        {to: '/docs/results/', label: 'Results', position: 'left'},
        {to: '/docs/roadmap/', label: 'Roadmap', position: 'left'},
        {href: repo, label: 'GitHub', position: 'right'},
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {label: 'Limits and data handling', to: '/docs/limits/'},
        {label: 'GitHub', href: repo},
        {label: 'Apache-2.0', href: `${repo}/blob/master/LICENSE`},
      ],
      copyright: 'WAF Tuner is an independent open-source project. ModSecurity, OWASP CRS and Coraza are projects of their respective owners.',
    },
    prism: {additionalLanguages: ['bash', 'json', 'apacheconf']},
  },
};
