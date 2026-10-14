# Oreon Defense

Oreon Defense is the security app for Oreon. It scans files with ClamAV and blocks threats before they open or run. It stops harmful programs and keeps an eye on the network. It sits in the tray and tells you in plain words when something needs your attention.

## Install

Oreon Defense comes from the Oreon repos.

```
sudo dnf install oreon-defense
```

Though it is pre-installed on all Oreon 11 installations.

## Build from source

Install the build dependencies, then build with CMake.

```
sudo dnf install cmake gcc-c++ qt6-qtbase-devel openssl-devel yaml-cpp-devel json-devel clamav-devel libcurl-devel
cmake -S . -B build
cmake --build build
```

To build the RPM, use the spec in `packaging` with the matching source tarball.

## How it protects you

New and changed files are scanned the moment they are saved, including downloads in your home folder. A file that matches a known threat is blocked and moved to quarantine. You can delete it without a password, but restoring it needs an admin.

Programs are checked when they start. Known malware, miners and reverse shells are stopped. Unknown programs in `/dev/shm` are blocked from running. In `/tmp` and Downloads you get a warning instead, so normal work isn't broken.

Hidden decoy files in your Documents, Pictures, Desktop and Downloads folders catch ransomware early. A program that rewrites lots of your files very quickly gets stopped too. Oreon Defense also watches the places malware uses to stay on a system, like startup files, cron jobs, SSH keys and sudoers.

Changes made by dnf, rpm, dracut and the installer are trusted, so system updates don't set off alerts.

## Rule updates (TEAM)

Detection rules update from od-rules.oreonhq.com every six hours. Every update is signed, and Oreon Defense refuses anything that isn't signed with the Oreon key.

To publish new rules, edit `rules-feed/rules.yaml` and raise its version number. Then sign it with the private key and upload `rules.yaml`, `rules.yaml.sig` and `manifest.json` to the bucket, with `manifest.json` last.

```
scripts/sign-rules.sh sign ~/od-rules-key/od-rules-ed25519.key rules-feed/rules.yaml rules-feed
```

Keep the private key off the source tree. Only the public key in `data/keys` ships with the app.

## Settings

Most people never need to change anything. Everything is in the Settings page. The system config file is `/etc/oreon-defense/config.json`, and there's an example in `config`.

## Testing

`scripts/verify_detection.sh` checks a build or an installed system. Run it with sudo to also test blocking. On a machine with Oreon Defense installed and running, use `sudo /usr/libexec/oreon-defense/test_installed_detection.sh`.

## License

See `LICENSE`. Copyright (C) 2026 Oreon HQ.
