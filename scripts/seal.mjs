#!/usr/bin/env node
// Seals the prototype behind a password that changes every day.
//
// One secret (SHARE_SECRET) does two jobs:
//   - it encrypts the committed snapshot (snapshot.enc), so the repo can be
//     public without exposing the prototype;
//   - it derives each day's password (America/Edmonton date), so the daily
//     workflow and your machine agree on it without it ever being stored.
//
// Commands:
//   node scripts/seal.mjs snapshot <prototype.html>   re-seal a new build
//   node scripts/seal.mjs build <outDir>              gate + today's payload
//   node scripts/seal.mjs password [--day YYYY-MM-DD] the live password
//
// The secret comes from $SHARE_SECRET, else the macOS keychain item
// "usability-prototype-share".

import { execFileSync } from "node:child_process";
import { createCipheriv, createDecipheriv, createHmac, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SNAPSHOT = join(ROOT, "snapshot.enc");
const SITE_URL = "https://davidalves9.github.io/usability-prototype/";
const KEYCHAIN_SERVICE = "usability-prototype-share";
const TIME_ZONE = "America/Edmonton";
// The gate closes itself this long after a deploy, so a missed rotation
// shuts the page instead of leaving yesterday's password working.
const OPEN_FOR_MS = 26 * 60 * 60 * 1000;
const ITERATIONS = 600_000;
// 32 symbols, no 0/O or 1/I: a byte mod 32 is unbiased.
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const MAGIC = Buffer.from("UPS1");

function secret() {
  if (process.env.SHARE_SECRET) return process.env.SHARE_SECRET;
  try {
    return execFileSync("security", ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"], { encoding: "utf8" }).trim();
  } catch {
    throw new Error(`No secret: set SHARE_SECRET or add the "${KEYCHAIN_SERVICE}" keychain item.`);
  }
}

const snapshotKey = () => Buffer.from(hkdfSync("sha256", secret(), Buffer.alloc(0), "snapshot", 32));

function today() {
  return new Intl.DateTimeFormat("en-CA", { timeZone: TIME_ZONE }).format(new Date());
}

function passwordFor(day) {
  const bytes = createHmac("sha256", secret()).update(`password:${day}`).digest();
  const chars = [...bytes.subarray(0, 8)].map((b) => ALPHABET[b % 32]).join("");
  return `${chars.slice(0, 4)}-${chars.slice(4)}`;
}

// What the gate does to whatever is typed: case and dashes don't matter.
const normalize = (password) => password.toUpperCase().replace(/[^A-Z0-9]/g, "");

function aesEncrypt(key, plain) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([iv, cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
}

function aesDecrypt(key, sealed) {
  const iv = sealed.subarray(0, 12);
  const tag = sealed.subarray(sealed.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(sealed.subarray(12, sealed.length - 16)), decipher.final()]);
}

function sealSnapshot(htmlPath) {
  const html = readFileSync(htmlPath);
  writeFileSync(SNAPSHOT, Buffer.concat([MAGIC, aesEncrypt(snapshotKey(), html)]));
  console.log(`Sealed ${htmlPath} (${(html.length / 1e6).toFixed(1)} MB) into snapshot.enc`);
}

function build(outDir) {
  const sealed = readFileSync(SNAPSHOT);
  if (!sealed.subarray(0, 4).equals(MAGIC)) throw new Error("snapshot.enc isn't a sealed snapshot");
  const html = aesDecrypt(snapshotKey(), sealed.subarray(4));

  const day = today();
  const salt = randomBytes(16);
  const key = pbkdf2Sync(normalize(passwordFor(day)), salt, ITERATIONS, 32, "sha256");
  // payload.bin: salt (16) | iv (12) | ciphertext | tag (16)
  const payload = Buffer.concat([salt, aesEncrypt(key, html)]);

  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "payload.bin"), payload);
  const index = readFileSync(join(ROOT, "site/index.html"), "utf8")
    .replaceAll("{{DAY}}", day)
    .replaceAll("{{EXPIRES}}", new Date(Date.now() + OPEN_FOR_MS).toISOString())
    .replaceAll("{{ITERATIONS}}", String(ITERATIONS));
  writeFileSync(join(outDir, "index.html"), index);
  for (const file of ["gate.js", "gate.css"]) copyFileSync(join(ROOT, "site", file), join(outDir, file));
  writeFileSync(join(outDir, ".nojekyll"), "");
  // Never print the password: workflow logs on a public repo are public.
  console.log(`Built the gate for ${day} in ${outDir}`);
}

async function password(args) {
  const at = args.indexOf("--day");
  if (at >= 0) {
    console.log(passwordFor(args[at + 1]));
    return;
  }
  // The live page says which day it was sealed for, so this matches it even
  // in the minutes around midnight before the new deploy lands.
  let day = today();
  let live = false;
  try {
    const page = await (await fetch(SITE_URL, { cache: "no-store" })).text();
    const match = page.match(/data-day="(\d{4}-\d{2}-\d{2})"/);
    if (match) [day, live] = [match[1], true];
  } catch {
    // Offline: fall back to today's date.
  }
  console.log(`URL:      ${SITE_URL}`);
  console.log(`Password: ${passwordFor(day)}`);
  console.log(`Day:      ${day}${live ? " (read from the live page)" : " (today; the live page couldn't be read)"}`);
}

const [command, ...args] = process.argv.slice(2);
if (command === "snapshot" && args[0]) sealSnapshot(args[0]);
else if (command === "build" && args[0]) build(args[0]);
else if (command === "password") await password(args);
else {
  console.error("Usage: seal.mjs snapshot <prototype.html> | build <outDir> | password [--day YYYY-MM-DD]");
  process.exit(1);
}
