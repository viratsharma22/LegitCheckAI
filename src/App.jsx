import React, { useState } from 'react';
import { detectPhishing } from './utils/detection';

function App() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);

  const handleCheck = () => {
    if (!url) return;
    const analysis = detectPhishing(url);
    setResult(analysis);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleCheck();
  };

  return (
    <div className="container">
      <header>
        <h1>LegitCheck Ai</h1>
        <p className="subtitle">Instant Phishing & URL Safety Analysis</p>
      </header>

      <div className="search-box">
        <input 
          type="text" 
          placeholder="Enter website URL to analyze..." 
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={handleKeyDown}
          autoFocus
        />
        <button className="check-btn" onClick={handleCheck}>Analyze Now</button>
      </div>

      {result ? (
        <>
          <div className="results-grid">
            <div className="card score-display">
              <div className={`score-circle ${result.isRisky ? 'border-danger' : 'border-success'}`}>
                <div className="score-value" style={{ color: result.score > 60 ? 'var(--danger)' : 'var(--success)' }}>
                  {result.score}
                </div>
                <div className="score-label">Risk Score</div>
              </div>
              <div className={`status-badge ${result.isRisky ? 'status-risky' : 'status-safe'}`}>
                {result.isRisky ? 'POTENTIAL THREAT' : 'LOGICALLY SAFE'}
              </div>
              <p style={{ marginTop: '1.5rem', opacity: 0.7 }}>
                Domain: <span style={{ color: 'var(--primary)' }}>{result.domain}</span>
              </p>
            </div>

            <div className="card">
              <h3>Analysis Report</h3>
              {result.reasons.length > 0 ? (
                <ul className="reasons-list" style={{ marginTop: '1rem' }}>
                  {result.reasons.map((reason, i) => (
                    <li key={i}>{reason}</li>
                  ))}
                </ul>
              ) : (
                <p style={{ marginTop: '1rem', color: 'var(--text-muted)' }}>
                  No suspicious patterns detected based on current heuristics.
                </p>
              )}
            </div>
          </div>

          <div className="card cybercell-card" style={{ marginTop: '2rem', textAlign: 'center' }}>
            <h3>Need to report a Cyber Crime?</h3>
            <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem' }}>If you have been a victim of a scam, contact the National Cyber Crime Cell immediately.</p>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '2rem', flexWrap: 'wrap' }}>
              <div className="contact-item">
                <span className="contact-label">Helpline</span>
                <a href="tel:1930" className="contact-link highlight">1930</a>
              </div>
              <div className="contact-item">
                <span className="contact-label">Official Portal</span>
                <a href="https://cybercrime.gov.in/Webform/cyber_suspect.aspx" target="_blank" rel="noopener noreferrer" className="contact-link">Report Online</a>
              </div>
            </div>
          </div>
        </>
      ) : (
        <div className="empty-state">
           <p>Enter a URL above to start the deep-scan process.</p>
        </div>
      )}
    </div>
  );
}

export default App;
