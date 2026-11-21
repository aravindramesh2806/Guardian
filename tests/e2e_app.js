// Browser test of the whole app with a virtual passkey (Chromium WebAuthn emulation).
// Start the app with an empty users folder, then: node tests/e2e_app.js <folder for screenshots> <users folder>
// e.g. GUARDIAN_USERS_DIR=/tmp/g-e2e .venv/bin/python app/server.py &  then  node tests/e2e_app.js /tmp /tmp/g-e2e
// (the users folder can also come from GUARDIAN_USERS_DIR; the sign-up code is read from its dev_mail.log)
// Persona's widget doesn't run headless, so the trusted person stays "not invited" here (tests/test_app.py
// covers the invite itself).
const { chromium } = require('playwright');
const dir = process.argv[2], usersDir = process.argv[3] || process.env.GUARDIAN_USERS_DIR;
if (!dir || !usersDir) { console.error('usage: node tests/e2e_app.js <screenshots folder> <users folder>'); process.exit(2); }
const fs = require('fs');
let page = null, pageErrors = [];  // kept outside so a failure can save what was on screen
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 390, height: 844 } });
  await ctx.grantPermissions(['notifications'], { origin: 'http://localhost:8800' });
  const p = page = await ctx.newPage();
  const errors = pageErrors; let noSidecar = false;  // on the verify page with no sidecar, one 400 from /api/persona/begin is expected
  p.on('pageerror', e => errors.push(e.message));
  p.on('console', m => {
    if (m.type() !== 'error') return;
    const url = (m.location() && m.location().url) || '';
    if (noSidecar && /status of 400/.test(m.text()) && url.endsWith('/api/persona/begin')) return;
    errors.push(m.text() + (url ? ' (' + url + ')' : ''));
  });
  const cdp = await ctx.newCDPSession(p);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  const shot = async (name) => { await p.screenshot({ path: `${dir}/e2e-${name}.png`, fullPage: true }); };
  const text = async () => (await p.textContent('main')).replace(/\s+/g, ' ');
  const tap = (label) => p.getByRole('button', { name: label, exact: true }).click();

  await p.goto('http://localhost:8800/');
  await shot('welcome');
  await tap('Get started');
  await p.getByText('Who is Guardian for?').waitFor();
  await p.getByRole('button', { name: /^Me / }).click();
  await p.fill('#name', 'Rose');
  await p.fill('#email', 'rose.e2e@example.com');
  await tap('Continue with Face ID');
  await p.getByText('Check your email').waitFor();
  await shot('verify-email');
  const mail = fs.readFileSync(usersDir + '/dev_mail.log', 'utf8');
  const code = mail.match(/Your Guardian code is (\d{6})/g).pop().slice(-6);
  await p.fill('#code', '000000' === code ? '111111' : '000000');
  await tap('Confirm');
  await p.getByText(/isn't right/).waitFor();
  await p.fill('#code', code);
  await tap('Confirm');
  await p.getByText('A quick check that you\'re really here').waitFor();
  console.log('1 registered with a passkey, wrong code refused, emailed code accepted -> Persona step (step 2 of 6)');
  await tap('Do this later');
  await p.getByText('Guardian will never').waitFor();
  await tap('Continue');
  await p.fill('#fname', 'Sam (daughter)'); await p.fill('#fphone', '+1 555 0142');
  await tap('Continue');
  await p.getByRole('radio', { name: /Act for me, then tell me/ }).click();
  await p.getByRole('switch').click();
  await shot('setup-mode');
  await tap('Continue');
  await p.getByText('Step 6 of 6').waitFor();
  await tap('Send me a practice alert');
  await tap('Yes, I got it');
  console.log('2 setup done, practice alert sent and confirmed');

  await p.getByText('Hi, Rose').waitFor();
  await shot('home');
  let t = await text();
  console.log('3 home hero:', /Almost ready/.test(t) ? 'Almost ready (sample data)' : 'MISSING', '| items:', (await p.$$('.card.item')).length,
    '| asks:', await p.getByText('Yes, do it').count());
  console.log('   family not invited, needs Persona first:', /Sam \(daughter\) not invited yet/.test(t) && /First, do the Persona check/.test(t));
  noSidecar = true;
  await p.getByText('Verify with Persona').click();
  await p.getByText(/isn.t set up on this computer|reach the Persona check/).waitFor();
  noSidecar = false;
  console.log('   verify page (no sidecar):', (await p.textContent('#status')).trim());
  await shot('verify');
  await p.getByText('Back to Guardian').click();
  await p.getByText('Hi, Rose').waitFor();
  await p.goto('http://localhost:8800/?read=' + encodeURIComponent('charge:tx-4'));
  await p.locator('.card.item.focus').waitFor();
  console.log('   alert "See details" -> focused item open:', await p.locator('.card.item.focus details[open]').count() === 1);
  await p.goto('http://localhost:8800/?undo=' + encodeURIComponent('scam:c-201'));
  await p.getByText('Was this real?').waitFor();
  await shot('alert-undo');
  await tap('No, it was a scam');
  await p.getByText("Let's deal with it").waitFor();
  console.log('   alert "It was real" -> asked, and "No, it was a scam" opened the fix screen');
  await tap('Back to my Guardian');
  await p.getByText('Hi, Rose').waitFor();
  const ask = p.locator('.card', { hasText: 'Dispute $389.00' }).filter({ has: p.getByText('Yes, do it') });
  await ask.getByText('Yes, do it').click();
  await p.waitForTimeout(1500);
  t = await text();
  console.log('4 dispute approved -> still asked:', /Dispute \$389\.00/.test(t));
  const phish = p.locator('.card.item', { hasText: 'paylinc' });
  console.log('   phishing card says:', (await phish.locator('.did').textContent()).trim());
  await phish.getByText('This was real, not a scam').click();
  await p.getByText(/You marked 1 as real/).waitFor();
  console.log('5 "This was real" -> moved under "You marked 1 as real"');
  await tap("Pause Guardian's actions");
  await p.getByText("Guardian's actions are paused").waitFor();
  await shot('paused');
  await tap("Resume Guardian's actions");
  await p.getByText('Almost ready').waitFor();
  console.log('6 paused and resumed | alerts button:', await p.getByText('Turn on alerts on this device').count() === 1);
  await tap('Sign out');
  await tap('I already have an account');
  await p.getByText('Hi, Rose').waitFor();
  console.log('7 signed out, signed back in with the same passkey');
  await tap('Delete my data');
  await p.getByText(/Tap again to delete everything/).click();
  await p.getByText('Get started').waitFor();
  console.log('8 deleted -> back at welcome');
  console.log('page errors:', JSON.stringify(errors));
  await b.close();
  if (errors.length) { console.error('E2E FAILED: the page logged errors'); process.exit(1); }
})().catch(async e => {
  console.error('E2E FAILED:', e.message);
  if (pageErrors.length) console.error('page errors:', JSON.stringify(pageErrors));
  if (page) {
    try {
      console.error('on screen:', ((await page.textContent('main', { timeout: 2000 })) || '').replace(/\s+/g, ' ').slice(0, 600));
      await page.screenshot({ path: `${dir}/e2e-failure.png`, fullPage: true, timeout: 5000 });
    } catch (_) { /* best effort */ }
  }
  process.exit(1);
});
