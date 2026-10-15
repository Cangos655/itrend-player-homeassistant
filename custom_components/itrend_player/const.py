"""Konstanten der iTrend-Player-Integration."""

from __future__ import annotations

from datetime import timedelta
from typing import Final

DOMAIN: Final = "itrend_player"
MANUFACTURER: Final = "iTrend24"

# Konfigurationseintrag (Daten)
CONF_DEVICE_ID: Final = "device_id"
CONF_WEBHOOK_ID: Final = "webhook_id"
CONF_K_A2H: Final = "k_a2h"
CONF_K_H2A: Final = "k_h2a"
CONF_NAME: Final = "name"
CONF_PLATFORM: Final = "platform"
CONF_APP_VERSION: Final = "app_version"
CONF_UNPAIRED: Final = "unpaired"
CONF_REMOTE_PAIRED: Final = "paired_from_remote"
OPT_ALLOW_REMOTE: Final = "allow_remote"

EVENT_ITREND: Final = "itrend_player_event"

# Pairing-Pfade
PAIR_START_URL: Final = "/api/itrend_player/pair/start"
PAIR_FINISH_URL: Final = "/api/itrend_player/pair/finish"

# Kopplung (PROTOCOL.md 3.4 / 3.6)
CODE_LIFETIME: Final = 300.0  # Sekunden, monotone Uhr
ATTEMPT_LIFETIME: Final = 60.0
MAX_FAILURES: Final = 3
MAX_ATTEMPTS_TOTAL: Final = 4
MAX_ATTEMPTS_PER_SOURCE: Final = 2
MAX_CONCURRENT_FINISH: Final = 2
PAIR_RATE_LIMIT: Final = 10  # je Quelladresse
PAIR_RATE_WINDOW: Final = 60.0
LOCKOUT_COUNT: Final = 3  # gesperrte Codes ...
LOCKOUT_WINDOW: Final = 600.0  # ... innerhalb dieser Zeit ...
LOCKOUT_DURATION: Final = 600.0  # ... sperren die Kopplung so lange

# Webhook (PROTOCOL.md 4.3, 4.6, 5.3)
SEQ_RESERVE_AHEAD: Final = 99
DEVICE_RATE_LIMIT: Final = 10
DEVICE_RATE_WINDOW: Final = 10.0
BAD_SIG_RATE_LIMIT: Final = 30  # je Quelladresse
BAD_SIG_RATE_WINDOW: Final = 60.0
CLONE_MIN_EVENTS: Final = 5
CLONE_WINDOW: Final = 600.0
CLONE_JUMP: Final = 1000

# Verfuegbarkeit: drei verpasste Herzschlaege a 30 s
HEARTBEAT_INTERVAL: Final = 30
MISSED_HEARTBEATS: Final = 3
AVAILABILITY_TIMEOUT: Final = timedelta(seconds=HEARTBEAT_INTERVAL * MISSED_HEARTBEATS)

STORAGE_VERSION: Final = 1

ISSUE_UNPAIRED: Final = "unpaired_by_app_{entry_id}"
ISSUE_REMOTE_HINT: Final = "remote_source_{entry_id}"
ISSUE_KEY_COPIED: Final = "key_possibly_copied_{entry_id}"

PLATFORM_MODELS: Final = {
    "android": "Android TV / Fire TV",
    "tizen": "Samsung (Tizen)",
}
