import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill';
import { AnalyzeResponse, Signal, RiskLevel, ExtractedUrl } from '@shared/types';

interface AnalyzeResult extends AnalyzeResponse {
  extractedUrls: ExtractedUrl[];
  error?: string;
}

const AnalyzePopup: React.FC = () => {
  const [text, setText] = useState('');
  const [result, setResult] = useState<AnalyzeResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tabId, setTabId] = useState<number | null>(null);

  useEffect(() => {
    // Get text and tabId from URL params
    const params = new URLSearchParams(window.location.search);
    const textParam = params.get('text');
    const tabIdParam = params.get('tabId');
    
    if (textParam) {
      setText(textParam);
    }
    if (tabIdParam) {
      setTabId(parseInt(tabIdParam, 10));
    }
  }, []);

  const handleTextChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = e.target.value;
    if (value.length <= 50000) {
      setText(value);
    }
  };

  const handleAnalyze = async () => {
    if (!text.trim()) return;
    
    setLoading(true);
    setError(null);
    setResult(null);
    
    try {
      const response = await browser.runtime.sendMessage({
        type: 'CONTEXT_MENU_ANALYZE',
        data: { text, channel: 'email' }, // Default to email for context menu
      });
      
      setResult(response as AnalyzeResult);
    } catch (err) {
      setError('Analysis failed: ' + String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    window.close();
  };

  const handleDone = () => {
    window.close();
  };

  const handleReport = async () => {
    if (!result || !tabId) return;
    
    const urls = result.extractedUrls.map(u => u.url).join(', ');
    const note = `User reported from text analysis. URLs: ${urls}`;
    
    try {
      await browser.runtime.sendMessage({
        type: 'REPORT_URL',
        data: { url: result.extractedUrls[0]?.url || '', note },
      });
      alert('Report submitted. Thank you!');
    } catch {
      alert('Failed to submit report.');
    }
  };

  const getRiskBadgeClass = (level: RiskLevel) => {
    return level.toLowerCase();
  };

  const getRiskIcon = (level: RiskLevel) => {
    switch (level) {
      case 'Low': return '✅';
      case 'Medium': return '⚠️';
      case 'High': return '🔴';
      case 'Critical': return '🛑';
    }
  };

  const getSignalPointsClass = (points: number) => {
    if (points > 20) return 'high';
    if (points > 10) return 'medium';
    return 'low';
  };

  const getUrlRiskClass = (level: RiskLevel) => {
    return level.toLowerCase();
  };

  return (
    <div>
      <div className="section" id="inputSection">
        <div className="section-title">Text to Analyze</div>
        <div className="textarea-container">
          <textarea
            id="textInput"
            value={text}
            onChange={handleTextChange}
            placeholder="Text will appear here..."
            disabled={loading}
            rows={6}
          />
          <div className="char-count">{text.length}/50000 characters</div>
        </div>
        <div className="btn-row">
          <button className="btn btn-secondary" id="closeBtn" onClick={handleClose} disabled={loading}>
            Close
          </button>
          <button 
            className="btn btn-primary" 
            id="analyzeBtn" 
            onClick={handleAnalyze}
            disabled={loading || !text.trim()}
          >
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>
      </div>
      
      <div className="section" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
        {loading && (
          <div className="loading" id="loading">
            <div className="spinner"></div>
            <span>Analyzing...</span>
          </div>
        )}
        
        {error && (
          <div className="error" id="error">{error}</div>
        )}
        
        {result && !loading && (
          <div className="results visible" id="results">
            <div className={`risk-badge ${getRiskBadgeClass(result.level)}`} id="riskBadge">
              <div className="risk-icon" id="riskIcon">{getRiskIcon(result.level)}</div>
              <div className="risk-info">
                <div className="risk-level" id="riskLevel">{result.level} Risk</div>
                <div className="risk-score" id="riskScore">Score: {result.score}/100</div>
              </div>
            </div>
            
            <div>
              <div className="section-title">Detected Signals</div>
              <div className="signals-list" id="signalsList">
                {result.signals.length === 0 ? (
                  <div style={{ padding: '12px', color: '#6b7280', fontSize: '13px', background: 'white', border: '1px solid #e5e7eb', borderRadius: '8px' }}>
                    No suspicious signals detected.
                  </div>
                ) : (
                  result.signals.map((signal: Signal, index: number) => (
                    <div key={index} className="signal-item">
                      <div className="signal-header">
                        <span className="signal-name">{signal.label}</span>
                        <span className={`signal-points ${getSignalPointsClass(signal.points)}`}>
                          {signal.points > 0 ? '+' : ''}{signal.points} pts
                        </span>
                      </div>
                      <div className="signal-reason">{signal.reason}</div>
                      {signal.evidence.length > 0 && (
                        <div className="signal-evidence">
                          {signal.evidence.map((evidence, i) => (
                            <div key={i} className="evidence-item">
                              {evidence.description}: <code>{evidence.value}</code>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
            
            <div>
              <div className="section-title">Extracted URLs</div>
              <div className="urls-list" id="urlsList">
                {result.extractedUrls.length === 0 ? (
                  <div style={{ padding: '12px', color: '#6b7280', fontSize: '13px', background: 'white', border: '1px solid #e5e7eb', borderRadius: '8px' }}>
                    No URLs found in the analyzed text.
                  </div>
                ) : (
                  result.extractedUrls.map((url: ExtractedUrl, index: number) => (
                    <div key={index} className="url-item">
                      <div className="url-header">
                        <span className="url-text">{url.url}</span>
                        <span className={`url-risk ${getUrlRiskClass(url.riskLevel)}`}>{url.riskLevel}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
            
            <div className="action-buttons">
              <button className="btn btn-secondary" id="reportBtn" onClick={handleReport}>
                Report
              </button>
              <button className="btn btn-primary" id="doneBtn" onClick={handleDone}>
                Done
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const container = document.getElementById('root') || document.body;
const root = createRoot(container);
root.render(<AnalyzePopup />);