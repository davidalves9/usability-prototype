# Usability prototype

A password-gated GitHub Pages share of the Jobber project prototype
(Desktop → Vision → V2.3 Deliverables, Work progress tab, V1 off) for
usability sessions with SPs.

The password changes every day at 07:00 UTC (midnight in Edmonton). A
scheduled workflow re-encrypts the snapshot under the new day's password and
redeploys, so a password only works on the day it was given. If a rotation is
missed, the page closes itself 26 hours after its last deploy.

The prototype is never in this repo in the clear: `snapshot.enc` is
AES-256-GCM encrypted with a key derived from the `SHARE_SECRET` Actions
secret, and the deployed `payload.bin` is encrypted with a PBKDF2 key from the
day's password.

## Today's password

```bash
node scripts/seal.mjs password
```

Reads the secret from the macOS keychain item `usability-prototype-share`
and the day from the live page, so it always matches what's deployed.

## Update the prototype

In `jobber-project-prototype`:

```bash
npm run build:usability-v23
```

Then here:

```bash
node scripts/seal.mjs snapshot ../jobber-project-prototype/dist-usability-v23/index.html
git commit -am "Update snapshot" && git push
```

The push redeploys with today's password.

## Rotate now, or turn it off

- Rotate now: run the **Rotate password and deploy** workflow from the
  Actions tab.
- Take it down: Settings → Pages → unpublish, or delete the repo.
- GitHub disables scheduled workflows after 60 days with no commits; after
  that the page closes on its own within 26 hours.
