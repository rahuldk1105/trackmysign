// npm test: every catalog has exactly the English keys, the same message
// shapes (plain or one/other), and the same {placeholders} in each message.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import ts from "typescript";

// The catalogs are TypeScript with only type imports; compile each on its own.
async function load(name) {
  const src = readFileSync(new URL(`../src/i18n/${name}.ts`, import.meta.url), "utf8");
  const js = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 } }).outputText;
  return (await import(`data:text/javascript;base64,${Buffer.from(js).toString("base64")}`))[name];
}

const en = await load("en");
const others = { hi: await load("hi"), ta: await load("ta") };

const forms = (m) => (typeof m === "string" ? { text: m } : m);
const placeholders = (s) => [...new Set([...s.matchAll(/\{(\w*)\}/g)].map((x) => x[1]))].sort();

test("English messages are well-formed", () => {
  for (const [key, m] of Object.entries(en)) {
    assert.ok(typeof m === "string" || (Object.keys(m).sort().join() === "one,other"), key);
    for (const [form, s] of Object.entries(forms(m))) {
      assert.ok(s.trim(), `${key}.${form} is empty`);
      assert.ok(!placeholders(s).includes(""), `${key}.${form} has an empty {}`);
    }
    if (typeof m !== "string") assert.deepEqual(placeholders(m.one), placeholders(m.other), key);
  }
});

for (const [lang, catalog] of Object.entries(others)) {
  test(`${lang} has the same keys as en`, () => {
    assert.deepEqual(Object.keys(catalog).sort(), Object.keys(en).sort());
  });

  test(`${lang} has the same shapes and placeholders as en`, () => {
    for (const [key, m] of Object.entries(en)) {
      const theirs = catalog[key];
      assert.equal(typeof theirs, typeof m, `${lang} ${key}: plain vs. count message`);
      const want = placeholders(typeof m === "string" ? m : m.other);
      for (const [form, s] of Object.entries(forms(theirs))) {
        assert.ok(s.trim(), `${lang} ${key}.${form} is empty`);
        assert.deepEqual(placeholders(s), want, `${lang} ${key}.${form}`);
      }
    }
  });

  test(`${lang} has plural rules`, () => {
    assert.equal(new Intl.PluralRules(lang).resolvedOptions().locale, lang);
  });
}
