import React from 'react';

const BAND_COLORS = {
  Critical: '#f4475a',
  High: '#fb923c',
  Medium: '#facc15',
  Low: '#4ade80',
};

/**
 * Renders a circular gauge showing the risk score (0-100) as an arc,
 * color-coded by risk band, with the score in the center.
 */
export default function RiskGauge({ score = 0, band = 'Low' }) {
  const size = 180;
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = BAND_COLORS[band] || '#16e108';
  const center = size / 2;

  return (
    <svg className="gauge-svg" viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Risk score ${score} of 100, ${band}`}>
      <defs>
        <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor={color} stopOpacity="0.4" />
          <stop offset="100%" stopColor={color} stopOpacity="1" />
        </linearGradient>
      </defs>

      {/* Background track */}
      <circle
        cx={center}
        cy={center}
        r={radius}
        fill="none"
        stroke="#20504d"
        strokeWidth={strokeWidth}
      />

      {/* Score arc */}
      <circle
        cx={center}
        cy={center}
        r={radius}
        fill="none"
        stroke="url(#gaugeGradient)"
        strokeWidth={strokeWidth}
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="round"
        transform={`rotate(-90 ${center} ${center})`}
        style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1)' }}
      />

      {/* Center score text */}
      <text
        x="50%"
        y="48%"
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize="38"
        fontWeight="800"
        fontFamily="'JetBrains Mono', monospace"
        fill="#e6eaf2"
      >
        {score}
      </text>
      <text
        x="50%"
        y="66%"
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize="11"
        fontFamily="'JetBrains Mono', monospace"
        fill="#8a96b8"
        letterSpacing="1"
      >
        / 100
      </text>
    </svg>
  );
}
