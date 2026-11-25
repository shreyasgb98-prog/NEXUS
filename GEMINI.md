# Project Rules: NEXUS AI (Major Project)

Target Hardware: ESP32-S3 (N16R8) | Framework: Hybrid Arduino-as-ESP-IDF-Component
Local Storage: SQLite3 (WAL Mode) | Web Stack: Vanilla HTML5/Canvas/Web Serial API

## 1. Web Dashboard UI (Classic Cyber-Workstation / Win32 Utility)
- Aesthetic: Classic High-Density Engineering Workstation (Win98 / Win2K / Industrial Telemetry Instrument inspired).
  - Surface: Utilitarian workstation gray/charcoal (`#1e1e1e` workspace, `#2d2d2d` window panels, crisp `#3c3c3c` / `#111111` 3D beveled borders).
  - Typography: Monospace and clean system typography (`Consolas`, `Segoe UI`, `Tahoma`, system-ui) with strict tabular numbers (`font-variant-numeric: tabular-nums`).
  - Density: Zero decorative empty padding. Every pixel conveys status, telemetry, or control.
  - Windows & Tabs: Classical Win32 property sheets with tabbed panels, menu bar (`File`, `Capture`, `Detectors`, `Help`), and sunken status bar.
  - Signal Display: High-contrast phosphor telemetry screen (black CRT backdrop with crisp green `#22c55e`, cyan `#38bdf8`, and amber `#f59e0b` trace lines).
  - Anti-Slop Enforcement: Strictly NO floating rounded card soup, NO neon gradient backgrounds, NO arbitrary divider banners, and NO empty decorative progress bars.

## 2. Firmware Code (ESP32-S3 Hybrid)
- Architecture: ESP-IDF FreeRTOS core tasks running Arduino-compatible API wrappers.
- Ban blocking execution: zero `delay()` in `loop()` or sniffing paths; enforce non-blocking `millis()` state engines or FreeRTOS `vTaskDelayUntil()`.
- Ban runtime heap allocation: zero `String` class mutations, `malloc()`, or `new` within promiscuous callbacks and window loops; use fixed-size static buffers (`char buf[128]`, `std::array`).
- Ban magic numbers: declare all GPIO assignments, SPI buses, and radio channels as explicit `constexpr uint8_t` or `#define` constants.
- Ban hardcoded credentials: load configuration strictly from NVS or compile-time build flags.
- Sniffer execution safety: keep packet sniffer callbacks strictly in `IRAM_ATTR`; perform only lightweight bitmask inspection and ring-buffer writes inside ISR context.
- Telemetry format: emit telemetry strictly as single-line JSON (`{"deauth":%u,"mgmt":%u,"ble":%u,"rogue":%u,"nfc":%u}\n`) at 115200 baud.

## 3. Local SQL Database (SQLite3)
- Connection pragmas: enforce `PRAGMA journal_mode = WAL;`, `PRAGMA synchronous = NORMAL;`, and `PRAGMA foreign_keys = ON;` on every initialization.
- Ban wildcard selections: zero `SELECT *` queries in runtime application code; specify explicit column projections.
- Ban dynamic SQL concatenation: use strictly parameterized prepared statements (`?` / `:named`) for all telemetry ingest and queries.
- Schema indexing: index all timestamp (`epoch_ms`), `event_type`, and foreign key columns for rolling window queries.
- Schema migrations: manage database versions via sequential migration scripts; forbid unversioned runtime alterations.

## 4. Documentation & Code Hygiene
- Comment strictness: document only register bitmasks, physical pin constraints, timing errata, and mathematical formulas; omit self-evident prose comments.
- Ban placeholder code: zero `// TODO`, `// implement later`, or mock data presented as completed functionality.
- Architecture integrity: maintain strict separation between passive defensive telemetry (NEXUS AI) and experimental penetration firmware (HIZMOS).
- Lexicon ban: zero occurrences of *delve, robust, seamless, pivotal, crucial, tapestry, leverage, holistic, beacon, game-changer*.

## 5. Frontend Anti-Slop Safeguards (.agents/skills/avoid-ai-design)
- Skill link: `.agents/skills/avoid-ai-design/SKILL.md` (scanner: `scripts/detect.mjs`).
- Mandated Section 1 design choices (`Inter` typography, `14px`–`16px` radii, and protocol state badges) must be annotated with `avoid-ai-design-ignore` or `avoid-ai-design-ignore-file` comments.
- Prohibited defaults: purple/violet accents (`#c084fc`), glowing box-shadows, low-contrast text below WCAG AA (4.5:1), and missing `:focus-visible` keyboard focus styles.
