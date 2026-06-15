import React, { useEffect, useRef } from 'react';
import mermaid from 'mermaid';

mermaid.initialize({
  startOnLoad: false,
  theme: 'dark',
  themeVariables: {
    background: '#121a2e',
    primaryColor: '#1ea5ba',
    primaryTextColor: '#e6eaf2',
    primaryBorderColor: '#263354',
    lineColor: '#8a96b8',
    secondaryColor: '#818cf8',
    tertiaryColor: '#161f38',
    actorBkg: '#161f38',
    actorBorder: '#263354',
    actorTextColor: '#e6eaf2',
    signalColor: '#8a96b8',
    signalTextColor: '#e6eaf2',
    labelBoxBkgColor: '#0dc158',
    labelBoxBorderColor: '#263354',
    labelTextColor: '#e6eaf2',
    loopTextColor: '#e6eaf2',
    noteBkgColor: '#1c2742',
    noteTextColor: '#e6eaf2',
    noteBorderColor: '#263354',
    fontFamily: "'JetBrains Mono', monospace",
  },
});

export default function AttackSimulation({ simulation }) {
  const containerRef = useRef(null);

  useEffect(() => {
    if (!simulation?.mermaid || !containerRef.current) return;

    const renderDiagram = async () => {
      try {
        const id = `mermaid-${Date.now()}`;
        const { svg } = await mermaid.render(id, simulation.mermaid);
        if (containerRef.current) {
          containerRef.current.innerHTML = svg;
        }
      } catch (err) {
        console.error('Mermaid render error:', err);
        if (containerRef.current) {
          containerRef.current.innerHTML = '<p style="color: #8a96b8; font-size: 13px;">Diagram could not be rendered.</p>';
        }
      }
    };

    renderDiagram();
  }, [simulation]);

  if (!simulation) return null;

  return (
    <div className="attack-card">
      <p className="attack-narrative">{simulation.narrative}</p>
      {simulation.mermaid && <div className="mermaid-container" ref={containerRef} />}
    </div>
  );
}
