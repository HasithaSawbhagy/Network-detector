import React from 'react';

function StatusCard({ title, data, className = '' }) {
  return (
    <div className={`glass-card ${className}`}>
      <div className="card-title">{title}</div>
      <div className="card-content">
        {data.map((item, index) => (
          <div className="metric-row" key={index}>
            <span className="metric-label">{item.label}</span>
            <span className={`metric-value ${item.className || ''}`}>{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default StatusCard;
