#!/usr/bin/env python3
"""
MISP Collector for Splunk Enterprise 9.3+
- No Splunk Add-on
- No splunklib or third-party Python packages
- MISP 2.5 REST API
- JSON Lines to stdout
- Timestamp checkpoints with overlap
"""

import hashlib
import json
import os
import ssl
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


APP_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = APP_DIR / "local" / "misp_collector.json"
STATE_FILE = APP_DIR / "var" / "state" / "checkpoint.json"


def log(message):
    """Write operational messages to stderr, never stdout."""
    print(
        f"[misp_collector] {message}",
        file=sys.stderr,
        flush=True,
    )


def load_json(path, default):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default


def save_state(state):
    """Atomically replace the checkpoint file."""
    state_dir = STATE_FILE.parent
    state_dir.mkdir(parents=True, exist_ok=True)

    fd, temp_path = tempfile.mkstemp(
        prefix=".checkpoint-",
        dir=str(state_dir),
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())

        os.chmod(temp_path, 0o600)
        os.replace(temp_path, STATE_FILE)

    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def request_misp(config, endpoint, payload):
    base_url = config["misp_url"].rstrip("/")
    url = f"{base_url}/{endpoint.lstrip('/')}"

    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": config["api_key"],
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )

    if config.get("verify_tls", True):
        tls_context = ssl.create_default_context()
    else:
        # Temporary workaround for the current self-signed certificate.
        tls_context = ssl._create_unverified_context()

    try:
        with urlopen(
            request,
            timeout=int(config.get("timeout_seconds", 60)),
            context=tls_context,
        ) as response:
            raw = response.read()

        data = json.loads(raw.decode("utf-8"))

    except HTTPError as exc:
        raise RuntimeError(
            f"MISP HTTP {exc.code} on {endpoint}"
        ) from None

    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(
            f"MISP connection error on {endpoint}: "
            f"{type(exc).__name__}"
        ) from None

    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError(
            f"MISP returned invalid JSON on {endpoint}"
        ) from None

    if not isinstance(data, (dict, list)):
        raise RuntimeError(
            f"Unexpected MISP response type on {endpoint}"
        )

    if isinstance(data, dict):
        if data.get("errors") or data.get("error"):
            raise RuntimeError(
                f"MISP API returned an error on {endpoint}"
            )

        # MISP can return errors such as {"name", "message", "url"}
        # without a normal "response" field.
        if "response" not in data and "message" in data:
            raise RuntimeError(
                f"MISP returned an error response on {endpoint}"
            )

    return data


def unwrap_records(data, object_key):
    if isinstance(data, dict):
        data = data.get("response", data)

    if isinstance(data, dict) and object_key in data:
        data = data[object_key]

    if isinstance(data, dict):
        data = [data]

    if not isinstance(data, list):
        raise RuntimeError("Unexpected MISP response structure")

    records = []

    for item in data:
        if not isinstance(item, dict):
            continue

        record = item.get(object_key)

        if isinstance(record, dict):
            records.append(record)
        elif isinstance(record, list):
            records.extend(
                entry for entry in record
                if isinstance(entry, dict)
            )
        elif object_key not in item and (
            "uuid" in item or "id" in item
        ):
            records.append(item)

    return records


def record_timestamp(record):
    try:
        return int(record.get("timestamp") or 0)
    except (ValueError, TypeError):
        return 0


def make_event(record, record_type):
    identity = record.get("uuid") or record.get("id")

    if identity is None:
        canonical = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        identity = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

    uid_input = f"{record_type}:{identity}"
    record_uid = hashlib.sha256(
        uid_input.encode("utf-8")
    ).hexdigest()

    return {
        "misp_record_type": record_type,
        "misp_record_uid": record_uid,
        "misp_uuid": record.get("uuid"),
        "misp_event_id": (
            record.get("id")
            if record_type == "misp_event"
            else record.get("event_id")
        ),
        "misp_timestamp": record_timestamp(record),
        "collector_time": int(time.time()),
        "record": record,
    }


def collect_endpoint(
    config,
    state,
    endpoint,
    object_key,
    state_key,
    record_type,
    timestamp_filter,
):
    """
    Emit records one by one to avoid retaining the entire dataset in RAM.

    The watermark is updated only after all pages for this endpoint
    have been read and stdout has been flushed. Scripted Input does
    not expose a per-event indexing acknowledgment, so this is
    best-effort checkpointing, not exactly-once delivery.
    """
    page_size = int(config.get("page_size", 200))
    max_pages = int(config.get("max_pages_per_endpoint", 2000))
    overlap = int(config.get("overlap_seconds", 300))

    if page_size < 1 or max_pages < 1:
        raise RuntimeError("Invalid page_size or max_pages_per_endpoint")

    previous = state.get(state_key)
    filters = {
        "returnFormat": "json",
        "limit": page_size,
    }

    if previous is not None:
        filters[timestamp_filter] = max(
            0, int(previous) - overlap
        )
    else:
        lookback_days = int(
            config.get("initial_lookback_days", 0)
        )
        if lookback_days > 0:
            filters[timestamp_filter] = max(
                0, int(time.time()) - lookback_days * 86400
            )

    max_seen = int(previous or 0)
    count = 0
    complete = False

    for page in range(1, max_pages + 1):
        payload = dict(filters)
        payload["page"] = page

        response = request_misp(config, endpoint, payload)
        records = unwrap_records(response, object_key)

        for record in records:
            max_seen = max(
                max_seen,
                record_timestamp(record),
            )

            output = make_event(record, record_type)
            print(
                json.dumps(
                    output,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
                flush=False,
            )
            count += 1

        log(
            f"{state_key}: page={page}, "
            f"records={len(records)}"
        )

        if len(records) < page_size:
            complete = True
            break

    if not complete:
        raise RuntimeError(
            f"{state_key}: page limit reached; "
            "watermark not advanced. Increase max_pages_per_endpoint."
        )

    sys.stdout.flush()

    state[state_key] = max_seen
    state["last_run_utc"] = datetime.now(
        timezone.utc
    ).isoformat()

    save_state(state)

    log(f"{state_key}: completed, emitted={count}")


def main():
    config = load_json(CONFIG_FILE, None)

    if not isinstance(config, dict):
        raise RuntimeError("Missing or invalid configuration file")

    if not config.get("misp_url") or not config.get("api_key"):
        raise RuntimeError("misp_url and api_key are required")

    if not config["misp_url"].startswith("https://"):
        raise RuntimeError("MISP URL must use HTTPS")

    state = load_json(STATE_FILE, {})
    if not isinstance(state, dict):
        raise RuntimeError("Checkpoint file must contain a JSON object")

    # Event metadata, tags and nested attributes where permitted.
    collect_endpoint(
        config=config,
        state=state,
        endpoint="events/restSearch",
        object_key="Event",
        state_key="misp_events",
        record_type="misp_event",
        timestamp_filter="timestamp",
    )

    # IOC attributes, including their available event context.
    collect_endpoint(
        config=config,
        state=state,
        endpoint="attributes/restSearch",
        object_key="Attribute",
        state_key="misp_ioc",
        record_type="misp_ioc",
        timestamp_filter="attribute_timestamp",
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log(f"FAILED: {type(exc).__name__}: {exc}")
        sys.exit(1)
