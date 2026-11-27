import React from 'react';
import ThemedImage from '@theme/ThemedImage';
import useBaseUrl from '@docusaurus/useBaseUrl';

// Diagrams are made in Eraser and exported as light and dark PNGs into static/diagrams.
export default function Diagram({name, alt, caption}) {
  const sources = {
    light: useBaseUrl(`/diagrams/${name}-light.png`),
    dark: useBaseUrl(`/diagrams/${name}-dark.png`),
  };
  return (
    <figure className={`diagram diagram--${name}`}>
      <ThemedImage alt={alt} sources={sources} loading="lazy" />
      {caption && <figcaption>{caption}</figcaption>}
    </figure>
  );
}
