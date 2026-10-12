# Microsoft Intune and Kryptkeeper SCEP

**Status (2026-10-08): not supported in v1.** Tracked as W20-23.

## Why

An earlier version of this guide described Intune fetching a SCEP challenge
from `/scep/mscep_admin`. That was not a working integration:

- **Intune doesn't work that way.** Intune's third-party SCEP support
  validates each device's challenge through Microsoft's SCEP challenge
  validation API. A connector built against the Intune SCEP library,
  registered as an application in Microsoft Entra ID, checks every
  enrollment with Intune. Intune never reads an NDES admin page.
- **It was unsafe.** `/scep/mscep_admin` handed one static, shared challenge
  to anyone who asked, with no authentication. W20-16 removed it (D-121).

## What SCEP offers today

SCEP enrollment now uses one-time challenges. Each is minted for one
device's names through the authenticated API, and the hub issues exactly
those names. See [`docs/ops/SCEP.md`](../ops/SCEP.md). That suits devices an
operator provisions one at a time, such as printers, network gear and
appliances. It does not suit Intune, which needs per-device challenges it
validates itself.

## What Intune support needs (W20-23)

- **Validation:** check Intune-issued challenges through the Intune SCEP
  validation API, using an Entra ID app registration and its credentials.
- **Names:** issue the names Intune approved for the device.
- **Reporting:** report success and failure back to Intune.

Until then, use Windows autoenrollment (XCEP/WSTEP,
[`docs/ops/WSTEP_AUTOENROLLMENT.md`](../ops/WSTEP_AUTOENROLLMENT.md)) for
domain-joined Windows machines and users.
