import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill';
import { BlockData, Signal } from '@shared/types';

interface BlockPageData extends BlockData {
  tabId: number;
  blockSource?: 'blocklist' | 'ml' | 'heuristic';
}

const BlockedPage: React.FC = () => {
  const [blockData, setBlockData] = useState<BlockPageData | null>(null);
  const [loading, setLoading] = useState(true);

  // Safe DOM element accessor
  const $ = <T extends HTMLElement = HTMLElement>(id: string): T | null => 
    document.getElementById(id) as T | null;

  useEffect(() => {
    loadBlockData();
  }, []);

  async function loadBlockData() {
    const params = new URLSearchParams(window.location.search);
    const tabId = params.get('tabId');

    if (!tabId) {
      const el = $('blockMessage');
      if (el) el.textContent = 'Invalid block request.';
      setLoading(false);
      return;
    }

    try {
      const response = await browser.runtime.sendMessage({
        type: 'GET_BLOCK_DATA',
        data: { tabId: parseInt(tabId, 10) },
      });

      if (response) {
        const data = { ...response, tabId: parseInt(tabId, 10) } as BlockPageData;
        setBlockData(data);
        renderBlockData(data);
      } else {
        const el = $('blockMessage');
        if (el) el.textContent = 'Block information not found.';
      }
    } catch (e) {
      console.error('Error loading block data:', e);
      const el = $('blockMessage');
      if (el) el.textContent = 'Error loading block information.';
    } finally {
      setLoading(false);
    }
  }

  function renderBlockData(data: BlockPageData) {
    // Update basic info
    const blockedUrlEl = $('blockedUrl');
    if (blockedUrlEl) blockedUrlEl.textContent = data.url;

    const blockTimeEl = $('blockTime');
    if (blockTimeEl) blockTimeEl.textContent = new Date(data.timestamp).toLocaleString();

    const caseIdEl = $('caseId');
    if (caseIdEl) caseIdEl.textContent = data.caseId || '--';

    const riskScoreEl = $('riskScore');
    if (riskScoreEl) riskScoreEl.textContent = `${data.score ?? '--'}/100`;

    const riskLevelDisplayEl = $('riskLevelDisplay');
    if (riskLevelDisplayEl) riskLevelDisplayEl.textContent = data.level || 'Medium';

    // Update risk badge
    const badge = $('riskBadge');
    const level = data.level || 'Medium';
    if (badge) {
      badge.textContent = level;
      badge.className = `risk-badge risk-${level.toLowerCase()}`;
    }

    // Update title and message based on block source and risk level
    const blockTitleEl = $('blockTitle');
    const blockMessageEl = $('blockMessage');
    const proceedSectionEl = $('proceedSection');
    const criticalNoticeEl = $('criticalNotice');
    const reportSiteEl = $('reportSite');
    const blockSourceEl = $('blockSource');

    // Clear any previous source indicator
    if (blockSourceEl) {
      blockSourceEl.remove();
    }

    // Add block source indicator
    const sourceLabel = data.blockSource === 'blocklist' 
      ? 'Confirmed Blocklist Match' 
      : data.blockSource === 'ml' 
        ? 'ML Model Prediction' 
        : data.blockSource === 'heuristic'
          ? 'Heuristic Analysis'
          : 'Unknown';

    // Insert source indicator after risk badge
    const headerEl = $('header') || document.querySelector('.header');
    if (headerEl && data.blockSource) {
      const sourceDiv = document.createElement('div');
      sourceDiv.id = 'blockSource';
      sourceDiv.style.cssText = 'margin-top: 8px; font-size: 12px; opacity: 0.9;';
      sourceDiv.textContent = `Source: ${sourceLabel}`;
      headerEl.appendChild(sourceDiv);
    }

    if (data.reason === 'malicious') {
      // For ML/heuristic blocks, show appropriate UI based on risk level
      if (data.blockSource === 'blocklist') {
        // Confirmed blocklist - always block, no proceed
        if (blockTitleEl) blockTitleEl.textContent = 'Confirmed Malicious Website Blocked';
        if (blockMessageEl) blockMessageEl.textContent = 'This site is on a confirmed threat blocklist.';
        proceedSectionEl?.classList.remove('show');
        criticalNoticeEl?.classList.add('show');
        if (criticalNoticeEl) {
          criticalNoticeEl.querySelector('.critical-title')!.textContent = '🔒 Confirmed Threat';
          criticalNoticeEl.querySelector('.critical-text')!.textContent = 'This site has been confirmed as malicious by threat intelligence sources. Access is not recommended.';
        }
      } else if (data.blockSource === 'ml') {
        // ML prediction - show based on risk level and enforcement policy
        if (level === 'Critical') {
          if (blockTitleEl) blockTitleEl.textContent = 'Critical Risk Website Blocked';
          if (blockMessageEl) blockMessageEl.textContent = 'Our ML model predicts this site poses a critical security risk.';
          proceedSectionEl?.classList.remove('show');
          criticalNoticeEl?.classList.add('show');
        } else if (level === 'High') {
          if (blockTitleEl) blockTitleEl.textContent = 'High Risk Website Blocked';
          if (blockMessageEl) blockMessageEl.textContent = 'Our ML model predicts this site poses a high security risk.';
          proceedSectionEl?.classList.add('show');
          criticalNoticeEl?.classList.remove('show');
        } else if (level === 'Medium') {
          if (blockTitleEl) blockTitleEl.textContent = 'Medium Risk Website — Warning';
          if (blockMessageEl) blockMessageEl.textContent = 'Our ML model detects suspicious patterns. Proceed with caution.';
          proceedSectionEl?.classList.add('show');
          criticalNoticeEl?.classList.remove('show');
        } else {
          if (blockTitleEl) blockTitleEl.textContent = 'Low Risk — Warning';
          if (blockMessageEl) blockMessageEl.textContent = 'This site was flagged but risk appears low.';
          proceedSectionEl?.classList.add('show');
          criticalNoticeEl?.classList.remove('show');
        }
      } else if (data.blockSource === 'heuristic') {
        // Heuristic-only block
        if (blockTitleEl) blockTitleEl.textContent = 'Suspicious Patterns Detected';
        if (blockMessageEl) blockMessageEl.textContent = 'Local heuristic analysis found suspicious URL patterns.';
        proceedSectionEl?.classList.add('show');
        criticalNoticeEl?.classList.remove('show');
      } else {
        // Unknown source - treat as ML
        if (blockTitleEl) blockTitleEl.textContent = 'Website Blocked';
        if (blockMessageEl) blockMessageEl.textContent = 'This website has been blocked for your safety.';
        proceedSectionEl?.classList.add('show');
        criticalNoticeEl?.classList.remove('show');
      }
    } else {
      // Inappropriate content
      if (blockTitleEl) blockTitleEl.textContent = 'Inappropriate Content Blocked';
      if (blockMessageEl) blockMessageEl.textContent = 'Child safety mode - inappropriate content';
      proceedSectionEl?.classList.remove('show');
      criticalNoticeEl?.classList.remove('show');
      // Hide report button for inappropriate content
      reportSiteEl?.classList.add('hidden');
    }

    renderSignals(data.signals || []);
    setupEventListeners(data);
  }

  function renderSignals(signals: Signal[]) {
    const container = $('signalsContainer');
    if (!container) return;

    if (!signals.length) {
      container.innerHTML = '<p style="color:#6b7280;font-size:13px;">No detailed signals available.</p>';
      return;
    }

    container.innerHTML = signals.map(signal => `
      <div class="reason-item ${signal.points > 20 ? 'high' : signal.points > 10 ? 'medium' : 'low'}">
        <div class="reason-name">${signal.label} <span style="float:right;color:#6b7280;font-weight:400;">${signal.points > 0 ? '+' : ''}${signal.points} pts</span></div>
        <div class="reason-desc">${signal.reason}</div>
        ${signal.evidence.length ? `
          <div class="reason-evidence">
            ${signal.evidence.map(e => `<div class="reason-evidence-item">${e.description}: <code>${e.value}</code></div>`).join('')}
          </div>
        ` : ''}
      </div>
    `).join('');
  }

  function setupEventListeners(data: BlockPageData) {
    // Go back button - use the referrer from the blocked URL or go back in history
    const goBackEl = $('goBack');
    if (goBackEl) {
      goBackEl.addEventListener('click', () => {
        // Try to extract the original referrer from the URL params
        const params = new URLSearchParams(window.location.search);
        const referrer = params.get('referrer');
        if (referrer) {
          window.location.href = referrer;
        } else if (document.referrer) {
          window.location.href = document.referrer;
        } else {
          window.history.back();
        }
      });
    }

    // New tab button
    const newTabEl = $('newTab');
    if (newTabEl) newTabEl.addEventListener('click', () => {
      browser.tabs.create({ url: 'chrome://newtab/' });
      window.close();
    });

    // Proceed anyway button (for malicious, non-critical)
    const proceedBtn = $('proceedBtn') as HTMLButtonElement | null;
    const proceedCheckbox = $('proceedCheckbox') as HTMLInputElement | null;
    const countdownText = $('countdownText');

    if (proceedBtn && proceedCheckbox) {
      let countdown = 5;
      let countdownInterval: ReturnType<typeof setInterval> | null = null;

      const updateCountdown = () => {
        if (countdownText) {
          countdownText.textContent = `Proceed button enables in ${countdown}s...`;
        }
        if (countdown <= 0) {
          if (countdownInterval) clearInterval(countdownInterval);
          proceedBtn.disabled = false;
          if (countdownText) countdownText.textContent = '';
        }
        countdown--;
      };

      proceedCheckbox.addEventListener('change', () => {
        if (proceedCheckbox.checked) {
          countdown = 5;
          proceedBtn.disabled = true;
          updateCountdown();
          countdownInterval = setInterval(updateCountdown, 1000);
        } else {
          if (countdownInterval) clearInterval(countdownInterval);
          proceedBtn.disabled = true;
          if (countdownText) countdownText.textContent = '';
        }
      });

      proceedBtn.addEventListener('click', async () => {
        const confirmed = confirm(
          `⚠️ SECURITY WARNING ⚠️\n\n` +
          `Are you absolutely sure you want to continue to ${new URL(data.url).hostname}?\n\n` +
          `This site was flagged as ${data.reason} with a ${data.level} risk score of ${data.score}/100.\n\n` +
          `Continuing may expose you to:\n` +
          `• Identity theft\n` +
          `• Malware infection\n` +
          `• Financial fraud\n\n` +
          `This will add the site to your allowlist and allow future access.\n` +
          `Only continue if you absolutely trust this website.`
        );

        if (confirmed) {
          try {
            await browser.runtime.sendMessage({
              type: 'CONTINUE_ANYWAY',
              data: { tabId: data.tabId },
            });
            window.location.href = data.url;
          } catch (e) {
            console.error('Error:', e);
            alert('Error proceeding. Please try again.');
          }
        }
      });
    }

    // Report site button
    const reportSiteEl = $('reportSite');
    if (reportSiteEl) {
      reportSiteEl.addEventListener('click', async () => {
        const reason = prompt('Why are you reporting this site?\n(phishing/malware/scam/fake/other)');
        if (reason) {
          try {
            await browser.runtime.sendMessage({
              type: 'REPORT_URL',
              data: { url: data.url, note: `User report: ${reason}` },
            });
            alert('Thank you for reporting this site!');
          } catch (e) {
            alert('Error reporting site.');
          }
        }
      });
    }

    // False positive link
    const falsePositiveLinkEl = $('falsePositiveLink');
    if (falsePositiveLinkEl) {
      falsePositiveLinkEl.addEventListener('click', (e) => {
        e.preventDefault();
        const subject = encodeURIComponent('Guardian False Positive Report');
        const body = encodeURIComponent(
          `I believe the following URL was incorrectly blocked:\n\n` +
          `URL: ${data.url}\n` +
          `Reason: ${data.reason}\n` +
          `Risk Level: ${data.level}\n` +
          `Score: ${data.score}/100\n` +
          `Time: ${new Date(data.timestamp).toLocaleString()}\n\n` +
          `Additional details:\n`
        );
        window.open(`mailto:security@guardian.example.com?subject=${subject}&body=${body}`);
      });
    }

    // Settings link in critical notice
    const settingsLinkEl = $('settingsLink');
    if (settingsLinkEl) {
      settingsLinkEl.addEventListener('click', (e) => {
        e.preventDefault();
        browser.tabs.create({ url: browser.runtime.getURL('options.html') });
        window.close();
      });
    }

    // Settings link in footer
    const settingsLinkFooterEl = $('settingsLinkFooter');
    if (settingsLinkFooterEl) {
      settingsLinkFooterEl.addEventListener('click', (e) => {
        e.preventDefault();
        browser.tabs.create({ url: browser.runtime.getURL('options.html') });
        window.close();
      });
    }
  }

  if (loading) {
    return <div style={{textAlign: 'center', padding: '40px'}}>Loading...</div>;
  }

  return null;
};

const container = document.getElementById('root');
if (!container) {
  console.error('Root container not found');
} else {
  const root = createRoot(container);
  root.render(<BlockedPage />);
}