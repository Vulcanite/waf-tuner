import React from 'react';
import {useColorMode} from '@docusaurus/theme-common';
import ThemedImage from '@theme/ThemedImage';
import useBaseUrl from '@docusaurus/useBaseUrl';

export default function Diagram({name, alt, caption, eager = false}) {
  const light = useBaseUrl(`/diagrams/${name}-light.svg`);
  const dark = useBaseUrl(`/diagrams/${name}-dark.svg`);
  const {colorMode} = useColorMode();

  return (
    <figure className={`diagram diagram--${name}`}>
      <a href={colorMode === 'dark' ? dark : light} aria-label={`Open full-size diagram. ${alt}`}>
        <ThemedImage alt={alt} sources={{light, dark}} loading={eager ? 'eager' : 'lazy'} />
        <span className="diagram-expand" aria-hidden="true">Open full size ↗</span>
      </a>
      {caption && <figcaption>{caption}</figcaption>}
    </figure>
  );
}
