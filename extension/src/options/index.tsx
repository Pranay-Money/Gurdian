import browser from 'webextension-polyfill';
import {
  DEFAULT_EXTENDED_SETTINGS,
  ExtendedDeviceSettings,
  SupportedSite,
  SUPPORTED_SITES,
} from '@shared/types';
import { getApiRoot, parseMlHealthStatus } from '@shared/api-status';

type Settings = ExtendedDeviceSettings & {
  blocklistUrl?: string;
  customRules?: string;
};

let settings: Settings = { ...DEFAULT_EXTENDED_SETTINGS };

function getElement<T extends HTMLElement>(id: string): T | null {
  return document.getElementById(id) as T | null;
}

function updateSiteCard(siteKey: SupportedSite, enabled: boolean) {
  getElement(`site-card-${siteKey}`)?.classList.toggle('enabled', enabled);
  const status = getElement(`site-status-${siteKey}`);
  if (status) {
    status.textContent = enabled ? 'Enabled' : 'Disabled';
    status.className = `site-status ${enabled ? 'enabled' : 'disabled'}`;
  }
}

function updatePermissionNotice() {
  const notice = getElement('permissionNotice');
  if (notice) {
    const anyEnabled = Object.values(settings.enabledSites).some(Boolean);
    notice.classList.toggle('visible', settings.linkScanningEnabled && anyEnabled);
  }
}

function applySettingsToDOM() {
  const controls: Array<[string, boolean]> = [
    ['protectionEnabled', settings.protectionEnabled],
    ['showBadges', settings.showInlineBadges],
    ['sendTelemetry', settings.sendTelemetry],
    ['linkScanningEnabled', settings.linkScanningEnabled],
  ];

  for (const [id, checked] of controls) {
    const input = getElement<HTMLInputElement>(id);
    if (input) input.checked = checked;
  }

  // Enforcement policy radio buttons
  const warnRadio = getElement<HTMLInputElement>('enforcementWarn');
  const blockRadio = getElement<HTMLInputElement>('enforcementBlock');
  if (warnRadio) warnRadio.checked = settings.enforcementPolicy === 'warn';
  if (blockRadio) blockRadio.checked = settings.enforcementPolicy === 'block';

  const apiBaseUrl = getElement<HTMLInputElement>('apiBaseUrl');
  if (apiBaseUrl) apiBaseUrl.value = settings.apiBaseUrl;

  const blocklistUrl = getElement<HTMLInputElement>('blocklistUrl');
  if (blocklistUrl) blocklistUrl.value = settings.blocklistUrl ?? '';

  const customRules = getElement<HTMLTextAreaElement>('customRules');
  if (customRules) customRules.value = settings.customRules ?? '';

  for (const siteKey of Object.keys(SUPPORTED_SITES) as SupportedSite[]) {
    const enabled = settings.enabledSites[siteKey] ?? false;
    const checkbox = getElement<HTMLInputElement>(`site-${siteKey}`);
    if (checkbox) {
      checkbox.checked = enabled;
      checkbox.disabled = !settings.linkScanningEnabled;
    }
    updateSiteCard(siteKey, enabled);
  }

  updatePermissionNotice();
}

function updateStatus(
  id: 'api' | 'ml',
  state: 'online' | 'offline' | 'unknown',
  description: string,
) {
  const dot = getElement(`${id}Dot`);
  const text = getElement(`${id}Desc`);
  if (dot) dot.className = `api-status-dot ${state}`;
  if (text) text.textContent = description;
}

async function checkApiHealth() {
  const apiRoot = getApiRoot(settings.apiBaseUrl);
  try {
    const response = await fetch(`${apiRoot}/health`);
    updateStatus('api', response.ok ? 'online' : 'offline', response.ok ? 'API reachable' : `HTTP ${response.status}`);
    if (!response.ok) {
      updateStatus('ml', 'unknown', 'Status unavailable');
      return;
    }
    try {
      const mlStatus = parseMlHealthStatus(await response.json() as unknown);
      const state = mlStatus.state === 'loaded'
        ? 'online'
        : mlStatus.state === 'not-loaded'
          ? 'offline'
          : 'unknown';
      updateStatus('ml', state, mlStatus.description);
    } catch (cause) {
      console.error('Failed to read Guardian ML health status', cause);
      updateStatus('ml', 'unknown', 'Status unavailable');
    }
  } catch (cause) {
    console.error('Failed to check Guardian API health', cause);
    updateStatus('api', 'offline', 'Connection failed');
    updateStatus('ml', 'unknown', 'Status unavailable');
  }
}

async function updateSetting<K extends keyof Settings>(key: K, value: Settings[K]) {
  const previousSettings = settings;
  settings = { ...settings, [key]: value };
  try {
    await browser.storage.local.set({ settings });
  } catch (cause) {
    settings = previousSettings;
    applySettingsToDOM();
    console.error(`Failed to save Guardian setting ${key}`, cause);
    window.alert('Unable to save this setting. Please try again.');
    return;
  }

  if (key === 'apiBaseUrl') {
    void checkApiHealth();
  }
  if (key === 'linkScanningEnabled') {
    for (const siteKey of Object.keys(SUPPORTED_SITES) as SupportedSite[]) {
      const checkbox = getElement<HTMLInputElement>(`site-${siteKey}`);
      if (checkbox) checkbox.disabled = !settings.linkScanningEnabled;
    }
    updatePermissionNotice();
  }
}

async function updateSiteSetting(siteKey: SupportedSite, enabled: boolean) {
  const site = SUPPORTED_SITES[siteKey];
  try {
    if (enabled && !(await browser.permissions.contains({ origins: site.hostPatterns }))) {
      const granted = await browser.permissions.request({ origins: site.hostPatterns });
      if (!granted) {
        const checkbox = getElement<HTMLInputElement>(`site-${siteKey}`);
        if (checkbox) checkbox.checked = false;
        window.alert(`Permission denied for ${site.name}. Link scanning cannot be enabled for this site.`);
        return;
      }
    }
  } catch (cause) {
    console.error(`Failed to request permission for ${site.name}`, cause);
    const checkbox = getElement<HTMLInputElement>(`site-${siteKey}`);
    if (checkbox) checkbox.checked = settings.enabledSites[siteKey] ?? false;
    window.alert(`Unable to update permissions for ${site.name}.`);
    return;
  }

  const previousSettings = settings;
  settings = {
    ...settings,
    enabledSites: { ...settings.enabledSites, [siteKey]: enabled },
  };
  try {
    await browser.storage.local.set({ settings });
    updateSiteCard(siteKey, enabled);
    updatePermissionNotice();
  } catch (cause) {
    settings = previousSettings;
    applySettingsToDOM();
    console.error(`Failed to save ${site.name} scanning setting`, cause);
    window.alert('Unable to save this setting. Please try again.');
  }
}

async function resetAllData() {
  if (!window.confirm('This will delete ALL your data (history, whitelist, reports, settings). Are you sure?')) return;
  if (!window.confirm('This action CANNOT be undone. Type "RESET" to confirm.')) return;

  try {
    await browser.storage.local.clear();
    settings = { ...DEFAULT_EXTENDED_SETTINGS };
    applySettingsToDOM();
    window.alert('All data has been reset. The page will reload.');
    window.location.reload();
  } catch (cause) {
    console.error('Failed to reset Guardian data', cause);
    window.alert('Unable to reset Guardian data. Please try again.');
  }
}

function buildSiteCards() {
  const grid = getElement('sitesGrid');
  if (!grid) return;

  grid.replaceChildren();
  for (const [siteKey, config] of Object.entries(SUPPORTED_SITES) as Array<[SupportedSite, typeof SUPPORTED_SITES[SupportedSite]]>) {
    const card = document.createElement('div');
    card.id = `site-card-${siteKey}`;
    card.className = 'site-card';

    const header = document.createElement('div');
    header.className = 'site-header';
    const siteName = document.createElement('span');
    siteName.className = 'site-name';
    siteName.textContent = config.name;
    const label = document.createElement('label');
    label.className = 'toggle';
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.id = `site-${siteKey}`;
    checkbox.disabled = !settings.linkScanningEnabled;
    checkbox.addEventListener('change', () => {
      void updateSiteSetting(siteKey, checkbox.checked);
    });
    const slider = document.createElement('span');
    slider.className = 'toggle-slider';
    label.append(checkbox, slider);
    header.append(siteName, label);

    const description = document.createElement('div');
    description.className = 'site-desc';
    description.textContent = `Scan links in ${config.name} conversations`;
    const status = document.createElement('span');
    status.id = `site-status-${siteKey}`;
    status.className = 'site-status disabled';
    status.textContent = 'Disabled';

    card.append(header, description, status);
    grid.append(card);
  }
}

function bindControls() {
  getElement<HTMLInputElement>('protectionEnabled')?.addEventListener('change', (event) => {
    void updateSetting('protectionEnabled', (event.currentTarget as HTMLInputElement).checked);
  });
  // Enforcement policy radio buttons
  getElement<HTMLInputElement>('enforcementWarn')?.addEventListener('change', (event) => {
    if ((event.currentTarget as HTMLInputElement).checked) {
      void updateSetting('enforcementPolicy', 'warn');
    }
  });
  getElement<HTMLInputElement>('enforcementBlock')?.addEventListener('change', (event) => {
    if ((event.currentTarget as HTMLInputElement).checked) {
      void updateSetting('enforcementPolicy', 'block');
    }
  });
  getElement<HTMLInputElement>('showBadges')?.addEventListener('change', (event) => {
    void updateSetting('showInlineBadges', (event.currentTarget as HTMLInputElement).checked);
  });
  getElement<HTMLInputElement>('sendTelemetry')?.addEventListener('change', (event) => {
    void updateSetting('sendTelemetry', (event.currentTarget as HTMLInputElement).checked);
  });
  getElement<HTMLInputElement>('apiBaseUrl')?.addEventListener('blur', (event) => {
    void updateSetting('apiBaseUrl', (event.currentTarget as HTMLInputElement).value);
  });
  getElement<HTMLInputElement>('blocklistUrl')?.addEventListener('blur', (event) => {
    void updateSetting('blocklistUrl', (event.currentTarget as HTMLInputElement).value);
  });
  getElement<HTMLTextAreaElement>('customRules')?.addEventListener('blur', (event) => {
    void updateSetting('customRules', (event.currentTarget as HTMLTextAreaElement).value);
  });
  getElement<HTMLInputElement>('linkScanningEnabled')?.addEventListener('change', (event) => {
    void updateSetting('linkScanningEnabled', (event.currentTarget as HTMLInputElement).checked);
  });
  getElement<HTMLButtonElement>('resetData')?.addEventListener('click', () => void resetAllData());
}

async function initialize() {
  buildSiteCards();
  bindControls();
  try {
    const result = await browser.storage.local.get('settings');
    const saved = result.settings;
    const storedSettings = saved && typeof saved === 'object' ? saved as Partial<Settings> : {};
    settings = {
      ...DEFAULT_EXTENDED_SETTINGS,
      ...storedSettings,
      enabledSites: {
        ...DEFAULT_EXTENDED_SETTINGS.enabledSites,
        ...storedSettings.enabledSites,
      },
    };
    applySettingsToDOM();
    void checkApiHealth();
  } catch (cause) {
    console.error('Failed to load Guardian settings', cause);
    window.alert('Unable to load Guardian settings. The displayed controls may not reflect saved preferences.');
  }
}

void initialize();
