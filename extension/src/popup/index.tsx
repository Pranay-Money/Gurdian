import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill';
import { DEFAULT_SETTINGS, DeviceSettings, StatsResponse } from '@shared/types';

interface Stats {
  totalCases: number;
  highCritical: number;
  averageScore: number;
}

const EMPTY_STATS: Stats = { totalCases: 0, highCritical: 0, averageScore: 0 };

const Popup: React.FC = () => {
  const [settings, setSettings] = useState<DeviceSettings>(DEFAULT_SETTINGS);
  const [stats, setStats] = useState<Stats>(EMPTY_STATS);
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [apiOnline, setApiOnline] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reportMessage, setReportMessage] = useState<string | null>(null);

  useEffect(() => {
    async function initialize() {
      try {
        const stored = await browser.storage.local.get('settings');
        const storedSettings = stored.settings as Partial<DeviceSettings> | undefined;
        const loadedSettings = { ...DEFAULT_SETTINGS, ...storedSettings };
        setSettings(loadedSettings);
        setSettingsLoaded(true);
        await Promise.all([loadStats(loadedSettings), checkApiStatus(loadedSettings)]);
      } catch (cause) {
        console.error('Failed to initialize popup settings', cause);
        setSettingsLoaded(true);
        setError('Unable to load Guardian settings.');
      }
    }

    void initialize();
  }, []);

  async function loadStats(currentSettings: DeviceSettings) {
    try {
      const response = await fetch(`${currentSettings.apiBaseUrl.replace(/\/+$/, '')}/stats?range=7d`, {
        headers: { 'X-Device-Token': currentSettings.deviceToken },
      });
      if (!response.ok) {
        throw new Error(`Stats request failed with HTTP ${response.status}`);
      }
      const data = await response.json() as StatsResponse;
      setStats({
        totalCases: data.total_cases ?? 0,
        highCritical: (data.by_level?.High ?? 0) + (data.by_level?.Critical ?? 0),
        averageScore: data.avg_score ?? 0,
      });
    } catch (cause) {
      console.error('Failed to load popup statistics', cause);
      setError('Statistics are currently unavailable.');
    }
  }

  async function checkApiStatus(currentSettings: DeviceSettings) {
    const apiRoot = currentSettings.apiBaseUrl.replace(/\/v1\/?$/, '').replace(/\/+$/, '');
    try {
      const response = await fetch(`${apiRoot}/health`);
      setApiOnline(response.ok);
    } catch (cause) {
      console.error('Failed to check API status', cause);
      setApiOnline(false);
    }
  }

  async function updateSetting(
    key: 'protectionEnabled' | 'enforcementPolicy' | 'showInlineBadges',
    value: boolean | 'warn' | 'block',
  ) {
    const updatedSettings = { ...settings, [key]: value };
    setSettings(updatedSettings);
    try {
      await browser.storage.local.set({ settings: updatedSettings });
      setError(null);
    } catch (cause) {
      console.error(`Failed to save popup setting ${key}`, cause);
      setSettings(settings);
      setError('Unable to save this setting.');
    }
  }

  function handleProtectionChange(event: React.ChangeEvent<HTMLInputElement>) {
    void updateSetting('protectionEnabled', event.currentTarget.checked);
  }

  function openPage(page: string) {
    void browser.tabs.create({ url: browser.runtime.getURL(page) }).catch((cause: unknown) => {
      console.error(`Failed to open extension page ${page}`, cause);
      setError('Unable to open that Guardian page.');
    });
    window.close();
  }

  async function reportSite() {
    setReportMessage(null);
    try {
      const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url || !/^https?:\/\//i.test(tab.url)) {
        setReportMessage('Open a website to report it.');
        return;
      }
      const response = await fetch(`${settings.apiBaseUrl.replace(/\/+$/, '')}/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-Token': settings.deviceToken,
        },
        body: JSON.stringify({ url: tab.url }),
      });
      if (!response.ok) {
        throw new Error(`Report request failed with HTTP ${response.status}`);
      }
      setReportMessage('Site reported. Thank you!');
    } catch (cause) {
      console.error('Failed to report current site', cause);
      setReportMessage('Unable to report this site right now.');
    }
  }

  return (
    <main className="container">
      <header className="header">
        <div className="logo">G</div>
        <div className="title">Guardian</div>
        <div className={`status ${settings.protectionEnabled ? 'active' : 'inactive'}`} id="statusIndicator">
          <span className="status-dot" />
          <span>{settings.protectionEnabled ? 'Active' : 'Disabled'}</span>
        </div>
      </header>

      <div className="api-status" role="status" aria-live="polite">
        <div className="api-item">
          <span className={`api-dot ${apiOnline ? 'online' : 'offline'}`} />
          <span>API: {settingsLoaded ? (apiOnline ? 'Online' : 'Offline') : 'Connecting...'}</span>
        </div>
      </div>

      <section className="section" aria-labelledby="protection-title">
        <h2 className="section-title" id="protection-title">Protection</h2>
        <div className="toggle-row">
          <div className="toggle-label">
            <span className="toggle-title">Web Protection</span>
            <span className="toggle-desc">Block malicious and phishing websites</span>
          </div>
          <label className="toggle">
            <input
              type="checkbox"
              id="protectionEnabled"
              checked={settings.protectionEnabled}
              onChange={handleProtectionChange}
              disabled={!settingsLoaded}
            />
            <span className="toggle-slider" />
          </label>
        </div>
        <div className="toggle-row">
          <div className="toggle-label">
            <span className="toggle-title">Enforcement Policy</span>
            <span className="toggle-desc">How to handle detected threats</span>
          </div>
          <div className="radio-group" style={{display: 'flex', gap: '16px', alignItems: 'center'}}>
            <label style={{display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer'}}>
              <input
                type="radio"
                name="enforcementPolicy"
                value="warn"
                checked={settings.enforcementPolicy === 'warn'}
                onChange={() => void updateSetting('enforcementPolicy', 'warn')}
                disabled={!settingsLoaded}
                style={{width: '16px', height: '16px'}}
              />
              <span>Warn (default)</span>
            </label>
            <label style={{display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer'}}>
              <input
                type="radio"
                name="enforcementPolicy"
                value="block"
                checked={settings.enforcementPolicy === 'block'}
                onChange={() => void updateSetting('enforcementPolicy', 'block')}
                disabled={!settingsLoaded}
                style={{width: '16px', height: '16px'}}
              />
              <span>Block</span>
            </label>
          </div>
        </div>
        <div className="toggle-row">
          <div className="toggle-label">
            <span className="toggle-title">Inline Badges</span>
            <span className="toggle-desc">Show risk badges on suspicious pages</span>
          </div>
          <label className="toggle">
            <input
              type="checkbox"
              id="showBadges"
              checked={settings.showInlineBadges}
              onChange={(event) => void updateSetting('showInlineBadges', event.currentTarget.checked)}
              disabled={!settingsLoaded}
            />
            <span className="toggle-slider" />
          </label>
        </div>
      </section>

      <section className="section" aria-labelledby="statistics-title">
        <h2 className="section-title" id="statistics-title">Statistics (7 days)</h2>
        <div className="stat-row">
          <span className="stat-label">Analyzed Cases</span>
          <span className="stat-value">{stats.totalCases}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">High/Critical</span>
          <span className="stat-value">{stats.highCritical}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Average Risk Score</span>
          <span className="stat-value">{Math.round(stats.averageScore)}</span>
        </div>
      </section>

      <section className="section" aria-label="Guardian actions">
        <div className="btn-row">
          <button className="btn btn-secondary" id="viewHistory" onClick={() => openPage('history.html')}>History</button>
          <button className="btn btn-secondary" id="viewWhitelist" onClick={() => openPage('whitelist.html')}>Whitelist</button>
        </div>
        <div className="btn-row" style={{ marginTop: 8 }}>
          <button className="btn btn-primary" id="openOptions" onClick={() => openPage('options.html')}>Settings</button>
          <button className="btn btn-danger" id="reportSite" onClick={() => void reportSite()}>Report Site</button>
        </div>
        {reportMessage && <p role="status" aria-live="polite">{reportMessage}</p>}
      </section>

      {error && <p role="alert">{error}</p>}

      <footer className="footer">
        <a href="https://github.com/guardian/help" id="helpLink" target="_blank" rel="noreferrer">Help &amp; Support</a>
      </footer>
    </main>
  );
};

const container = document.getElementById('root');
if (!container) {
  throw new Error('Popup root element is missing');
}

createRoot(container).render(<Popup />);
