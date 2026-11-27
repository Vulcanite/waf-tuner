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
    colorMode: {defaultMode: 'dark', respectPrefersColorScheme: false},
    navbar: {
      title: 'WAF Tuner',
      logo: {alt: '', src: 'img/mark.svg'},
      items: [
        {type: 'doc', docId: 'quick-start', label: 'Quickstart', position: 'left'},
        {type: 'doc', docId: 'architecture', label: 'Architecture', position: 'left'},
        {type: 'doc', docId: 'profiles', label: 'Profiles', position: 'left'},
        {href: repo, label: 'GitHub', position: 'right'},
      ],
    },
  },
};
