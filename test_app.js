'use strict';
// Release integrity checks. Functional component coverage: tests/angular-smoke.mjs.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const manifest = JSON.parse(fs.readFileSync('frontend-build.json','utf8'));
const digest = p => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
for (const [path, expected] of Object.entries({...manifest.sources,...manifest.files})) assert.equal(digest(path),expected,'stale Angular build: '+path);
const html = fs.readFileSync('index.html','utf8');
assert.ok(html.includes('<ndr-root>'));
assert.ok(html.includes('type="module"'));
for (const file of ['app.js','ui.js','app.css']) assert.ok(html.includes('/'+file+'?v='+manifest.files[file].slice(0,16)));
assert.equal(fs.existsSync('frontend/src/app/runtime/console-runtime.js'),false);
console.log('ok - Angular sources, production assets and content-versioned entry point agree');
