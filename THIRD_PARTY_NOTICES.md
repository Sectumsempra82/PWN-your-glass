# Reviewed sources

No upstream installer is executed or downloaded by the TV runtime.

| Project / pinned revision | Use | Notice |
|---|---|---|
| JulioFerrero/own-your-glass `be9c69540f9e1677990bfb31d8fa3165749a2d98` | Capture enumeration and voice/screen investigation concepts, independently implemented as passive metadata inspection. No blanket capture controls, fallback device list, consent module or watcher imported. | `licenses/own-your-glass.txt` (MIT code; bundled data exception retained) |
| josippapez/webos_lockout `f7ff5350819fb0ea54153634edc2cf0546229e2b` | Adapted proc socket/inode attribution approach; extended to UDP/IPv6, explicit unknown ownership and timestamped JSON. Replaced address-prefix classification with Python ipaddress. | `licenses/webos-lockout.txt` (MIT) |
| furkan-bayrak/lg-tv-blocklist `687ceb5b58562e56a9af2f23a9066a2d7e9c7e78` | Nonduplicate `src/safe.txt` annotations retained in `policies/endpoints.json` as disabled candidates. Added local confidence, region and dependency fields. SAFE is an upstream claim, not G5 approval. | `licenses/lg-tv-blocklist.txt` ([CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)); attribution: furkan-bayrak/lg-tv-blocklist contributors |

Source URLs are recorded with endpoint records. Original G5 controls retain their
existing behavior and provenance; attribution does not establish compatibility.
Other compared projects informed evaluation only; no code/data was incorporated.
The root MIT license applies to original project code. Retained third-party
material remains under the terms listed above; the MIT grant does not relicense it.
