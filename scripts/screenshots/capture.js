#!/usr/bin/env node
// Auto-capture screenshots for usulnet. Requires:
//   - usulnet running at BASE_URL (default https://localhost:7443)
//   - admin user with PASSWORD env (default 'usulnet')
//   - playwright + chromium installed (browser path can be set via
//     PLAYWRIGHT_BROWSERS_PATH and explicit executablePath)

const fs = require('fs');
const path = require('path');
const {chromium} = require('playwright');

const BASE_URL = process.env.USULNET_URL || 'https://localhost:7443';
const USERNAME = process.env.USULNET_USER || 'admin';
const PASSWORD = process.env.USULNET_PASSWORD || 'usulnet';
const OUT_DIR  = process.env.OUT_DIR || path.resolve(__dirname, '../../docs/screenshots');
const CHROME_BIN = process.env.PLAYWRIGHT_CHROMIUM_PATH ||
  '/opt/pw-browsers/chromium-1194/chrome-linux/chrome';
const VIEWPORT = {width: 1600, height: 1000};

// Screenshot specs. {file: 'name.png', url: '/path', ...}
// Acks the recon legal notice before capturing recon pages.
const SHOTS = [
  // Login (logged out)
  {file: 'login.png',                url: '/login',                    skipLogin: true},

  // README hero
  {file: 'dashboard-hero.png',       url: '/'},

  // README sidebar (clip the full sidebar with sections expanded)
  {file: 'sidebar-v26.5.1.png',      url: '/',  sidebarOnly: true},

  // README modules
  {file: 'license-agpl.png',         url: '/license'},
  {file: 'firewall-rules.png',       url: '/firewall'},
  {file: 'marketplace-browse.png',   url: '/marketplace'},
  {file: 'wireguard-peers.png',      url: '/wireguard'},
  {file: 'calendar-monthly.png',     url: '/calendar'},
  {file: 'dns-providers.png',        url: '/dns'},
  {file: 'ssl-observatory.png',      url: '/ssl'},
  {file: 'image-builder-list.png',   url: '/image-builder'},
  {file: 'crontab-jobs.png',         url: '/crontab'},
  {file: 'backup-verify.png',        url: '/backup-verify'},
  {file: 'rollback-policies.png',    url: '/rollback'},
  {file: 'docker-engine-diff.png',   url: '/config/docker'},
  {file: 'proxy-access-list.png',    url: '/proxy'},
  {file: 'multi-node.png',           url: '/nodes'},

  // Recon (needs ack)
  {file: 'recon-dashboard.png',      url: '/recon/dashboard',  reconAck: true},
  {file: 'recon-results.png',        url: '/recon/scans',      reconAck: true},
  {file: 'metadata-strip.png',       url: '/recon/metadata',   reconAck: true},
];

async function login(page) {
  await page.goto(`${BASE_URL}/login`, {waitUntil: 'domcontentloaded'});
  await page.fill('input[name="username"]', USERNAME);
  await page.fill('input[name="password"]', PASSWORD);
  await Promise.all([
    page.waitForURL(/.*\/(?!login).*/),
    page.click('button[type="submit"]'),
  ]);
}

async function ackRecon(page) {
  // Try posting via the dashboard form. If already ack'd, this no-ops.
  await page.goto(`${BASE_URL}/recon/dashboard`, {waitUntil: 'domcontentloaded'});
  const ackForm = await page.$('form[action="/recon/ack"]');
  if (!ackForm) return;
  await page.evaluate(() => {
    const f = document.querySelector('form[action="/recon/ack"]');
    if (f) f.submit();
  });
  await page.waitForLoadState('domcontentloaded').catch(() => {});
}

async function capture(page, spec) {
  const out = path.join(OUT_DIR, spec.file);
  process.stdout.write(`-> ${spec.file.padEnd(28)} ${spec.url} ... `);
  await page.goto(BASE_URL + spec.url, {waitUntil: 'domcontentloaded'});

  // Let HTMX poll components and Alpine reactivity settle.
  await page.waitForTimeout(1100);

  // Hide any persistent floating overlays that may obscure the shot.
  await page.evaluate(() => {
    document.querySelectorAll('#toast-container').forEach(el => el.style.display = 'none');
  });

  if (spec.sidebarOnly) {
    // Expand all collapsible sidebar sections via localStorage and reload.
    await page.evaluate(() => {
      const open = {operations: false, connections: false, tools: false, integrations: false};
      localStorage.setItem('usulnet-sidebar-collapsed', JSON.stringify(open));
    });
    // Resize the viewport tall enough to fit the entire expanded sidebar.
    await page.setViewportSize({width: 280, height: 1900});
    await page.reload({waitUntil: 'domcontentloaded'});
    await page.waitForTimeout(900);
    // Make nav static and let it size to its full content so the
    // screenshot includes every section, not just the viewport slice.
    await page.evaluate(() => {
      const nav = document.querySelector('nav');
      if (nav) {
        nav.style.position = 'static';
        nav.style.height = 'auto';
        nav.style.minHeight = 'auto';
      }
      document.body.style.background = '#0a0a0f';
    });
    await page.waitForTimeout(400);
    const sidebar = await page.$('nav');
    if (sidebar) {
      await sidebar.screenshot({path: out, type: 'png'});
      const stat = fs.statSync(out);
      console.log(`${(stat.size/1024).toFixed(1)} KB (sidebar element)`);
      // restore viewport for subsequent shots
      await page.setViewportSize(VIEWPORT);
      return;
    }
    await page.setViewportSize(VIEWPORT);
  }

  const screenshotOpts = {
    path: out,
    type: 'png',
    fullPage: false,
  };
  if (spec.clip) screenshotOpts.clip = spec.clip;
  await page.screenshot(screenshotOpts);
  const stat = fs.statSync(out);
  console.log(`${(stat.size/1024).toFixed(1)} KB`);
}

async function main() {
  fs.mkdirSync(OUT_DIR, {recursive: true});
  const browser = await chromium.launch({
    headless: true,
    executablePath: CHROME_BIN,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  const context = await browser.newContext({
    viewport: VIEWPORT,
    ignoreHTTPSErrors: true,
    colorScheme: 'dark',
    deviceScaleFactor: 1,
  });
  const page = await context.newPage();
  page.on('console', msg => {
    if (msg.type() === 'error') {
      const txt = msg.text();
      if (txt.includes('Failed to load resource')) return;
      // console.log('[console]', msg.type(), txt);
    }
  });

  console.log(`Logging in as ${USERNAME} @ ${BASE_URL}`);
  await login(page);

  let recoAcked = false;
  for (const spec of SHOTS) {
    try {
      if (spec.reconAck && !recoAcked) {
        await ackRecon(page);
        recoAcked = true;
      }
      if (spec.skipLogin) {
        // Logout first
        await page.context().clearCookies();
      }
      await capture(page, spec);
      if (spec.skipLogin) {
        // Re-login after the captured shot
        await login(page);
      }
    } catch (e) {
      console.error(`FAIL ${spec.file}: ${e.message}`);
    }
  }

  await browser.close();
  console.log('\nDone.');
}

main().catch(e => {
  console.error('FATAL', e);
  process.exit(1);
});
