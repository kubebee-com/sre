'use strict';

const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

function redact(value, token = process.env.SRE_UI_TOKEN) {
  const message = value instanceof Error ? value.stack || value.message : String(value);
  return token ? message.split(token).join('[REDACTED]') : message;
}

function readConfig() {
  if (process.argv.length !== 3) {
    throw new Error('usage: node scripts/ci/legacy-dashboard-browser.cjs <config.json>');
  }
  const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  for (const key of ['url', 'module']) {
    if (!config[key]) throw new Error(`browser config is missing ${key}`);
  }
  return config;
}

async function assertModalClosed(page, reason) {
  const modal = page.locator('#modal-backdrop');
  await page.waitForFunction(() => {
    const element = document.querySelector('#modal-backdrop');
    return element && element.getAttribute('aria-hidden') === 'true' && getComputedStyle(element).display === 'none';
  });
  assert.equal(await modal.getAttribute('aria-hidden'), 'true', `${reason}: modal must be aria-hidden`);
  assert.equal(await modal.evaluate(element => getComputedStyle(element).display), 'none', `${reason}: modal must be display:none`);
}

async function openResourceLogs(page, issueRow, issueName) {
  const modal = page.locator('#modal-backdrop');
  await issueRow.getByRole('button', {name: /resource logs/i}).click();
  await modal.waitFor({state: 'visible'});
  assert.equal(await modal.getAttribute('aria-hidden'), 'false', 'opened modal must not be aria-hidden');
  assert.equal((await page.locator('#modal-title').textContent()).trim(), issueName, 'modal must identify the selected issue');
  const logText = (await page.locator('#modal-content').textContent()).trim();
  assert.ok(logText, 'selected issue must have non-empty resource log text');
  return {modal, logText};
}

async function findIssueWithResourceLogs(page) {
  await page.waitForFunction(() => document.querySelectorAll('#triage-queue [data-issue-row]').length > 0);
  const issueRows = page.locator('#triage-queue [data-issue-row]');
  const issueCount = await issueRows.count();
  assert.ok(issueCount, 'triage queue must contain issue rows');

  for (let index = 0; index < issueCount; index += 1) {
    const issueRow = issueRows.nth(index);
    const logsButton = issueRow.getByRole('button', {name: /resource logs/i});
    if (await logsButton.count() === 0) continue;

    const issueName = ((await issueRow.locator('[data-issue-name]').textContent()) || '').trim();
    if (!issueName) continue;

    const modal = page.locator('#modal-backdrop');
    await logsButton.click();
    await modal.waitFor({state: 'visible'});
    assert.equal(await modal.getAttribute('aria-hidden'), 'false', 'opened modal must not be aria-hidden');
    assert.equal((await page.locator('#modal-title').textContent()).trim(), issueName, 'modal must identify the selected issue');
    const logText = ((await page.locator('#modal-content').textContent()) || '').trim();
    if (logText) return {issueRow, issueName, modal};

    await modal.getByRole('button', {name: /close/i}).click();
    await assertModalClosed(page, `empty logs for ${issueName}`);
  }

  throw new Error('triage queue has no issue row with a Resource Logs button and non-empty logs');
}

async function main() {
  const config = readConfig();
  const token = process.env.SRE_UI_TOKEN;
  if (!token) throw new Error('SRE_UI_TOKEN is required for the legacy dashboard browser test');

  const {chromium} = require(config.module);
  const launchOptions = {headless: true};
  if (config.chromium && fs.existsSync(config.chromium)) launchOptions.executablePath = config.chromium;
  const browser = await chromium.launch(launchOptions);
  try {
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      viewport: {width: 1440, height: 1000}
    });
    const dashboardOrigin = new URL(config.url).origin;
    await context.route('**/*', async route => {
      const request = route.request();
      let requestOrigin = '';
      try {
        requestOrigin = new URL(request.url()).origin;
      } catch (_) {
        await route.continue();
        return;
      }
      if (requestOrigin !== dashboardOrigin) {
        await route.continue();
        return;
      }
      const headers = {...request.headers()};
      for (const name of Object.keys(headers)) {
        if (name.toLowerCase() === 'authorization') delete headers[name];
      }
      headers.authorization = `Bearer ${token}`;
      await route.continue({headers});
    });
    const page = await context.newPage();
    page.setDefaultTimeout(45000);
    const pageErrors = [];
    page.on('pageerror', error => pageErrors.push(redact(error, token)));

    await page.goto(config.url, {waitUntil: 'domcontentloaded'});
    const globalLinks = page.locator('#global-nav a, #global-nav button');
    assert.equal(await globalLinks.count(), 3, 'global navigation must contain three links');
    for (let index = 0; index < await globalLinks.count(); index += 1) {
      const link = globalLinks.nth(index);
      assert.ok(await link.isVisible(), `global link ${index + 1} must be visible`);
      assert.ok((await link.getAttribute('href'))?.trim() || (await link.getAttribute('data-tab'))?.trim(), `global link ${index + 1} must have an href or data-tab`);
    }

    const sidebar = page.locator('#left-nav');
    assert.ok(await sidebar.isVisible(), 'grouped left navigation must be visible');
    assert.ok(await sidebar.locator('[data-nav-group]').count(), 'left navigation must contain grouped sections');
    assert.ok(await sidebar.locator('a, button').count(), 'left navigation must contain controls');

    const selectedIssue = await findIssueWithResourceLogs(page);
    const issueRow = selectedIssue.issueRow;
    const issueName = selectedIssue.issueName;
    const issueCount = await page.locator('#triage-queue [data-issue-row]').count();
    await page.waitForFunction(expected => {
      const values = ['stat-issues', 'nav-issue-count', 'overview-review']
        .map(id => Number(document.getElementById(id)?.textContent));
      return values.every(value => value === expected);
    }, issueCount);

    let modal = selectedIssue.modal;
    await modal.getByRole('button', {name: /close/i}).click();
    await assertModalClosed(page, 'close button');

    modal = (await openResourceLogs(page, issueRow, issueName)).modal;
    await page.keyboard.press('Escape');
    await assertModalClosed(page, 'Escape');

    modal = (await openResourceLogs(page, issueRow, issueName)).modal;
    await modal.click({position: {x: 1, y: 1}});
    await assertModalClosed(page, 'backdrop');

    if (pageErrors.length) {
      throw new Error(`page errors: ${pageErrors.join('; ')}`);
    }

    if (config.artifacts) {
      fs.mkdirSync(config.artifacts, {recursive: true});
      await page.screenshot({path: path.join(config.artifacts, 'legacy-dashboard-desktop.png'), fullPage: true});
      await page.setViewportSize({width: 390, height: 844});
      await page.screenshot({path: path.join(config.artifacts, 'legacy-dashboard-mobile.png'), fullPage: true});
    }

    console.log('Legacy dashboard browser passed: global navigation, grouped sidebar, issue log modal close paths, and desktop/mobile rendering.');
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(redact(error));
  process.exitCode = 1;
});
