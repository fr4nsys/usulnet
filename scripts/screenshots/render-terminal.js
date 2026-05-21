#!/usr/bin/env node
// Render terminal-style screenshots as PNG. The "terminal" is a dark
// rounded card with monospace text, an OS-style traffic-light header,
// and ANSI-coloured output. Used for install-terminal.png and
// cli-version.png referenced from README.md.

const fs = require('fs');
const path = require('path');
const {chromium} = require('playwright');

const CHROME_BIN = process.env.PLAYWRIGHT_CHROMIUM_PATH ||
  '/opt/pw-browsers/chromium-1194/chrome-linux/chrome';
const OUT_DIR = path.resolve(__dirname, '../../docs/screenshots');

// Each terminal spec produces one PNG.
const TERMS = [
  {
    file: 'install-terminal.png',
    title: 'fran@host: ~',
    width: 1600,
    height: 1100,
    lines: [
      {prompt: '$', cmd: 'curl -fsSL https://raw.githubusercontent.com/fr4nsys/usulnet/main/deploy/install.sh | sudo bash'},
      '',
      {color: 'gray',    text: '============================================'},
      {color: 'orange',  text: ' usulnet Docker Management Platform'},
      {color: 'gray',    text: ' Installation Script'},
      {color: 'gray',    text: '============================================'},
      '',
      {color: 'green', text: '✓ docker (29.3.1) detected'},
      {color: 'green', text: '✓ docker compose v2 detected'},
      {color: 'green', text: '✓ openssl detected'},
      '',
      'Install directory: /opt/usulnet',
      'Downloading docker-compose.yml ........... OK (12 KB)',
      'Downloading .env.example ................. OK (1.9 KB)',
      '',
      'Generating secrets:',
      {color: 'cyan',  text: '  DB_PASSWORD     = 7c2f4e1a3b5d8c6a9e0f1b2c3d4e5f6a'},
      {color: 'cyan',  text: '  JWT_SECRET      = 9b8a7c6d5e4f3a2b…3c2d1e0f9a8b'},
      {color: 'cyan',  text: '  ENCRYPTION_KEY  = e1d2c3b4a596877…2a2b1c0d9e8f7a6'},
      '',
      'Pulling images:',
      {color: 'gray',  text: '  → usulnet/usulnet:latest       (173 MB)'},
      {color: 'gray',  text: '  → postgres:16-alpine           (111 MB)'},
      {color: 'gray',  text: '  → redis:8-alpine               (35 MB)'},
      {color: 'gray',  text: '  → nats:2.12-alpine             (11 MB)'},
      '',
      'Starting usulnet ...',
      {color: 'green', text: '✔ usulnet-postgres   healthy'},
      {color: 'green', text: '✔ usulnet-redis      healthy'},
      {color: 'green', text: '✔ usulnet-nats       healthy'},
      {color: 'green', text: '✔ usulnet            running (auto-TLS self-signed cert generated)'},
      '',
      {color: 'gray',  text: '============================================'},
      {color: 'orange',text: ' usulnet installed successfully!'},
      {color: 'gray',  text: '============================================'},
      '',
      ' Access usulnet:',
      {color: 'cyan',  text: '   HTTPS: https://10.0.0.42:7443'},
      '',
      ' Default credentials: admin / usulnet  (change immediately after first login)',
      '',
      {prompt: '$', cmd: ''},
    ],
  },
  {
    file: 'cli-version.png',
    title: 'fran@host: ~',
    width: 1100,
    height: 480,
    lines: [
      {prompt: '$', cmd: 'docker exec usulnet usulnet version'},
      '',
      {color: 'white', text: 'usulnet v26.5.2 Beta'},
      {color: 'gray',  text: '  Commit:     a6d0769 (main)'},
      {color: 'gray',  text: '  Built:      2026-05-19T18:42:11Z'},
      {color: 'gray',  text: '  Go version: go1.25.10'},
      {color: 'gray',  text: '  OS/Arch:    linux/amd64'},
      {color: 'gray',  text: '  License:    AGPL-3.0-or-later (Community Edition)'},
      '',
      {prompt: '$', cmd: 'docker exec usulnet usulnet migrate status | tail -6'},
      '',
      {color: 'gray',  text: '051_ssl_observatory     Applied at 2026-05-20T08:49:42Z'},
      {color: 'gray',  text: '052_backup_verification Applied at 2026-05-20T08:49:42Z'},
      {color: 'gray',  text: '053_image_builder       Applied at 2026-05-20T08:49:42Z'},
      {color: 'gray',  text: '054_automated_rollback  Applied at 2026-05-20T08:49:42Z'},
      {color: 'gray',  text: '055_wireguard_vpn       Applied at 2026-05-20T08:49:42Z'},
      {color: 'gray',  text: '056_marketplace         Applied at 2026-05-20T08:49:42Z'},
      '',
      {prompt: '$', cmd: ''},
    ],
  },
];

function renderHTML(term) {
  const colorMap = {
    gray:   '#8b8b95',
    white:  '#e6e6ee',
    cyan:   '#75b6ff',
    green:  '#7ee787',
    orange: '#ff6b35',
    yellow: '#ffcc66',
    red:    '#ff7b72',
  };
  const escapeHtml = s => String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const linesHtml = term.lines.map(line => {
    if (line === '') return '<div class="line">&nbsp;</div>';
    if (typeof line === 'string') {
      return `<div class="line"><span class="text-gray">${escapeHtml(line)}</span></div>`;
    }
    if (line.prompt !== undefined) {
      const caret = line.cmd === '' ? '<span class="caret">▍</span>' : '';
      return `<div class="line"><span class="prompt">$</span> <span class="cmd">${escapeHtml(line.cmd)}</span>${caret}</div>`;
    }
    const color = colorMap[line.color] || colorMap.white;
    return `<div class="line"><span style="color:${color}">${escapeHtml(line.text)}</span></div>`;
  }).join('\n');

  return `<!doctype html>
<html><head><meta charset="utf-8">
<style>
  html, body { margin: 0; padding: 0; background: #0a0a0f; }
  body {
    width: ${term.width}px; height: ${term.height}px;
    display: flex; align-items: flex-start; justify-content: center;
    padding-top: 40px; box-sizing: border-box;
    font-family: 'IBM Plex Mono', 'Fira Code', 'Menlo', 'Consolas', monospace;
  }
  .term {
    width: ${term.width - 80}px;
    background: #14141a;
    border-radius: 12px;
    border: 1px solid #2a2a36;
    box-shadow: 0 24px 48px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,107,53,0.06);
    overflow: hidden;
    display: flex; flex-direction: column;
  }
  .titlebar {
    height: 36px;
    background: linear-gradient(180deg, #1c1c24 0%, #16161e 100%);
    border-bottom: 1px solid #2a2a36;
    display: flex; align-items: center;
    padding: 0 14px;
    color: #a0a0aa;
    font-size: 12px;
    font-weight: 500;
    letter-spacing: 0.02em;
  }
  .dots { display: inline-flex; gap: 8px; margin-right: 16px; }
  .dot { width: 12px; height: 12px; border-radius: 50%; }
  .dot.r { background: #ff5f56; }
  .dot.y { background: #ffbd2e; }
  .dot.g { background: #27c93f; }
  .title { flex: 1; text-align: center; font-family: 'IBM Plex Sans', system-ui, sans-serif; }
  .body {
    padding: 18px 22px;
    color: #e0e0e8;
    font-size: 14px;
    line-height: 1.55;
    flex: 1;
  }
  .line { white-space: pre; }
  .line + .line { margin-top: 0; }
  .prompt { color: #ff6b35; font-weight: 600; }
  .cmd    { color: #e6e6ee; }
  .text-gray { color: #8b8b95; }
  .caret { color: #ff6b35; animation: blink 1.1s infinite steps(1); }
  @keyframes blink { 50% { opacity: 0; } }
</style></head>
<body>
  <div class="term">
    <div class="titlebar">
      <span class="dots"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span></span>
      <span class="title">${escapeHtml(term.title)}</span>
    </div>
    <div class="body">${linesHtml}</div>
  </div>
</body></html>`;
}

async function main() {
  const browser = await chromium.launch({
    headless: true,
    executablePath: CHROME_BIN,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  for (const term of TERMS) {
    const ctx = await browser.newContext({
      viewport: {width: term.width, height: term.height},
      colorScheme: 'dark',
      deviceScaleFactor: 1,
    });
    const page = await ctx.newPage();
    await page.setContent(renderHTML(term), {waitUntil: 'domcontentloaded'});
    await page.waitForTimeout(200);
    const out = path.join(OUT_DIR, term.file);
    await page.screenshot({path: out, type: 'png'});
    const stat = fs.statSync(out);
    console.log(`-> ${term.file.padEnd(28)} ${term.width}x${term.height}  ${(stat.size/1024).toFixed(1)} KB`);
    await ctx.close();
  }
  await browser.close();
}

main().catch(e => { console.error(e); process.exit(1); });
