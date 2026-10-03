# Selective privacy profile

## Scope and tradeoffs

The initial profile matches **OLED65G56LS / webOS TV 10.2.1 / aarch64**, the reviewed WoV PDM capture node, and the expected firmware paths. Rooting compatibility and privacy compatibility are different. `check` reads state without applying controls and refuses an unknown layout. Existing `/var/lib/webosbrew/init.d/05-lg-privacy` installations must be reviewed/migrated separately; they are never silently overwritten.

The embedded `POLICY` in `privacy.py` is the complete executable/unit/setting/host list. The installer:

- Bind-mounts inert replacements over 27 ACR, advertising, voice, diagnostic and updater executables; masks 11 corresponding systemd units; stops matching running processes. Adds 29 reviewed activation-definition overlays, preserves three shared definitions and watches one absent executable. Original firmware hashes must match before new activation overlays are mounted.
- Bind-mounts `/dev/null` over the verified **WoV PDM microphone capture node** `/dev/snd/pcmC1D0c`. It does not record audio, probe other capture devices, or change speaker/mixer nodes.
- Disables viewing-history collection, remote diagnostic uploads, long-distance voice, voice wake-up, personalized ads, home/screensaver promotion, AI nudges and content recommendations. HbbTV and third-party cookies use persistent `offByUser` settings; HbbTV device identification is off and DNT on.
- Declines only the reviewed optional voice, ACR, advertising, data-partner and marketing consents. Existing basic service agreements and all unrelated consent metadata are retained. It never accepts an agreement or changes the LG Services Country.
- Rewrites only six named SDX logging routes in each TV's own map, leaving other routes unchanged. SDX is restarted to discard its earlier cached routes; it is not disabled.
- Adds exact advertising/diagnostic host entries without blocking shared LG parent domains. Adds one owned IPv4 firewall rule for the known firmware-update fallback `156.147.69.32:8080`. It does not block general WAN, DNS, IPv6 or LAN access.
- Moves the contents of four known diagnostic queues into a private quarantine after stopping collectors, including files hidden beneath Homebrew queue mounts. The inspection happens in a private mount namespace; existing queue mounts remain intact globally. No diagnostic archive is uploaded or deleted.
- Sets ACR's persisted opt-out marker and the Homebrew firmware-update block preference. Official firmware updating is intentionally affected; this is not a promise of security updates while rooted.

## Preserved features

The script does not disable SDX itself, pushclient, IoT support, AirPlay, Google Cast, app networking, Bluetooth, LAN discovery, audio/video output, picture processing, panel control or ARC. It verifies that seven core AV services remain active. It does not change picture or audio calibration settings. A particular app can still require its own terms or tracking-heavy functionality; preserving networking is not a guarantee that every LG app will work with optional agreements declined.

No app is automatically removed. There is no generalized wildcard DNS block list. Network addresses and SSH credentials belonging to the original test device are not included.

## Persistence, limitations and microphone evidence

A Homebrew startup hook reapplies runtime overlays/settings after each normal full boot. Keep Quick Start+ disabled and verify after reboot, a country change or a firmware change. This is not immutable hardware enforcement: root software can remove the overlays, Homebrew failsafe may skip custom hooks, and system services can start before the hook runs. For an offline-from-first-boot setup, keep WAN blocked until post-install verification. The installer does not prove that every possible telemetry path or cached record has been found.

The five-minute maintenance timer verifies configured controls and repairs known
drift only after profile, mount ownership and captured startup/runtime integrity
checks pass. Changed startup files are reported, never silently replaced. Bind
verification requires source identity and a read-only target. Maintenance stops
before restore. This does not close the interval before Homebrew hooks execute.

Passive `audit`/`connections` reporting and the optional Pi experiment
tool are documented in README.md and probe/README.md. Additional
capture paths and candidate endpoints are evidence inputs, not enabled blocks.

The physical microphone switch should remain Off. Earlier matched direct-ALSA measurements showed a changing signal with the switch On and zeros after an initial transient with it Off. That supports the switch muting the tested path; it does **not** establish whether it physically disconnects microphone power, whether firmware could override it, or whether a separate remote-control microphone could capture audio. No recording or blanket “no app can ever record” claim is made by this installer.

## Backups and restore

Installation creates a root-private `/var/lib/webosbrew/dangbro-privacy/` directory with:

- The self-contained runtime script and inert overlay files.
- Original and filtered SDX maps.
- A journal of owned mounts, previous privacy settings and original Telnet/update preference presence.
- The previous ACR allowed marker if present, and diagnostic queue quarantine if nonempty.

The first backup is retained across repeat installation. Mount operations are recorded before mutation. A conflicting overlay or firewall-chain name causes installation to stop; restore removes only layers that still match this install's source files. Failures are explicit, and an interrupted apply leaves completed blocks in place for review.

```sh
python3 /var/lib/webosbrew/dangbro-privacy/privacy.py restore
```

Restore removes the startup hook, removes owned mounts/firewall rules, restores the prior privacy settings and Telnet/update preferences, and leaves backups available. Reboot to resume formerly stopped services. **It intentionally does not accept optional agreements, restore ACR's allowed marker, or requeue old uploads.** Those actions could resume data collection/transmission and require an intentional decision afterward. This is operational recovery, not a byte-for-byte reset of every privacy choice.

Telnet remains untouched unless `--disable-telnet` is chosen. That flag requires an SSH-enabled preference, an installed authorized key and invocation from an SSH session; it affects the next normal boot only. The Homebrew failsafe can independently expose Telnet for recovery. No remote access is exposed to the public Internet by this project.

## Validation status

The component policy was exercised on the original G5, including repeated full boots and selective Internet restoration. The packaged installer is new. The privacy host-side tests cover consent preservation, route filtering, supported-profile checks, mount ownership/journaling and restoration semantics. Rooting, offline URL selection, asset checks and local-server tests remain in the separate dangbro repository. A complete clean-TV install/reboot/restore cycle remains required before calling this package field-validated. `verify` reports observed local state, not an absolute guarantee about all firmware behavior.
