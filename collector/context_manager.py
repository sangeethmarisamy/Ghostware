import threading
import time
import socket
import subprocess
from datetime import datetime, timezone


class ContextManager:
    FLUSH_INTERVAL_SECONDS = 5

    def __init__(self):
        self.contexts = {}
        self.unmatched_events = []

        # Authentication failures / security events that do not
        # belong to an authenticated SSH context.
        self.pending_security_events = []

        # Standalone events that do not belong to an SSH context.
        # Used by cron, file, process, and other local collectors.
        self.pending_standalone_events = []

        self.flush_callback = None
        self.security_flush_callback = None

        self._flush_running = False
        self._flush_thread = None
        self._lock = threading.RLock()

    # ---------------------------------------------------------
    # BASIC HELPERS
    # ---------------------------------------------------------

    def parse_event_timestamp(self, value):
        if not value:
            return datetime.now(timezone.utc)

        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except Exception:
            return datetime.now(timezone.utc)

    def get_host_ip(self):
        try:
            result = subprocess.run(
                ["ip", "route", "get", "1.1.1.1"],
                capture_output=True,
                text=True,
                timeout=2,
            )

            parts = result.stdout.split()

            if "src" in parts:
                return parts[parts.index("src") + 1]

        except Exception:
            pass

        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None

    def normalize_tty(self, tty):
        if not tty:
            return None

        tty = tty.strip()

        if tty.startswith("/dev/"):
            tty = tty[5:]

        if tty.startswith("pts/"):
            tty = tty.replace("/", "")

        return tty

    # ---------------------------------------------------------
    # CONTEXT KEY
    # ---------------------------------------------------------

    def make_context_key(self, remote_ip, username, session_id):
        return (
            remote_ip,
            username,
            session_id,
        )

    # ---------------------------------------------------------
    # CONTEXT CREATION
    # ---------------------------------------------------------

    def create_context(self, event):
        metadata = event.get("metadata", {})

        username = metadata.get("username")
        session_id = metadata.get("session_id")
        remote_ip = event.get("source_ip")
        tty = self.normalize_tty(metadata.get("tty"))

        if not remote_ip:
            return None

        key = self.make_context_key(
            remote_ip,
            username,
            session_id,
        )

        with self._lock:

            if key in self.contexts:
                return self.contexts[key]

            context = {
                "host_ip": self.get_host_ip(),
                "remote_ip": remote_ip,
                "username": username,
                "session_id": session_id,
                "tty": tty,
                "start_time": event.get("timestamp"),
                "end_time": None,
                "status": "active",
                "events": [],
                "pending_events": [],
                "last_flush_time": time.monotonic(),
            }

            self.contexts[key] = context

            return context

    # ---------------------------------------------------------
    # EVENT ENRICHMENT
    # ---------------------------------------------------------

    def enrich_event(self, event, context):
        enriched = dict(event)

        enriched["context"] = {
            "host_ip": context["host_ip"],
            "remote_ip": context["remote_ip"],
            "username": context["username"],
            "session_id": context["session_id"],
            "tty": context["tty"],
        }

        return enriched

    # ---------------------------------------------------------
    # APPEND EVENT
    # ---------------------------------------------------------

    def append_to_context(self, context, event):
        context["events"].append(event)
        context["pending_events"].append(event)

    # ---------------------------------------------------------
    # AUTHENTICATION
    # ---------------------------------------------------------

    def handle_authentication_event(self, event):

        event_type = event.get("event_type")

        # -----------------------------------------------------
        # LOGIN SUCCESS = CREATE SSH CONTEXT
        # -----------------------------------------------------

        if event_type == "login_success":

            context = self.create_context(event)

            if context is None:
                self.unmatched_events.append({
                    "reason": "login_without_remote_ip",
                    "event": event,
                })
                return None

            enriched_event = self.enrich_event(
                event,
                context,
            )

            self.append_to_context(
                context,
                enriched_event,
            )

            return enriched_event

        # -----------------------------------------------------
        # LOGIN FAILURE
        #
        # Do NOT create an SSH context.
        # But DO preserve and forward the event as a
        # security event.
        # -----------------------------------------------------

        if event_type == "login_failure":

            security_event = {
                "type": "security_event",
                "event": event,
                "context": None,
            }

            with self._lock:
                self.pending_security_events.append(
                    security_event
                )

                self.unmatched_events.append({
                    "reason": "authentication_login_failure",
                    "event": event,
                })

            return security_event

        # -----------------------------------------------------
        # ALL OTHER AUTH EVENTS
        # -----------------------------------------------------

        return self.find_context_for_event(event)

    # ---------------------------------------------------------
    # NETWORK MATCHING
    # ---------------------------------------------------------

    def network_matches_context(self, event, context):

        remote_ip = context.get("remote_ip")

        if not remote_ip:
            return False

        metadata = event.get("metadata", {})

        addresses = {
            metadata.get("ipv4_src"),
            metadata.get("ipv4_dst"),
            metadata.get("ipv6_src"),
            metadata.get("ipv6_dst"),
        }

        addresses.discard(None)
        addresses.discard("")

        return remote_ip in addresses

    # ---------------------------------------------------------
    # COMMAND MATCHING
    # ---------------------------------------------------------

    def command_matches_context(self, event, context):

        metadata = event.get("metadata", {})

        event_username = metadata.get("username")
        event_tty = self.normalize_tty(
            metadata.get("tty")
        )

        context_username = context.get("username")
        context_tty = context.get("tty")

        if event_username and context_username:
            if event_username != context_username:
                return False

        if event_tty and context_tty:
            if event_tty != context_tty:
                return False

        if not event_username and not event_tty:
            return False

        return True

    # ---------------------------------------------------------
    # FIND CONTEXT
    # ---------------------------------------------------------

    def find_context_for_event(self, event):

        source = event.get("source")
        candidates = []

        with self._lock:

            for context in self.contexts.values():

                if context.get("status") != "active":
                    continue

                # -------------------------------------------------
                # NETWORK
                # -------------------------------------------------

                if source == "network":

                    if self.network_matches_context(
                        event,
                        context,
                    ):
                        candidates.append(context)

                    continue

                # -------------------------------------------------
                # COMMAND
                # -------------------------------------------------

                if source == "command":

                    if self.command_matches_context(
                        event,
                        context,
                    ):
                        candidates.append(context)

                    continue

                # -------------------------------------------------
                # OTHER EVENTS
                # -------------------------------------------------

                event_source_ip = event.get("source_ip")

                if (
                    event_source_ip
                    and event_source_ip == context.get("remote_ip")
                ):
                    candidates.append(context)

            # -----------------------------------------------------
            # EXACTLY ONE CONTEXT
            # -----------------------------------------------------

            if len(candidates) == 1:

                context = candidates[0]

                enriched_event = self.enrich_event(
                    event,
                    context,
                )

                self.append_to_context(
                    context,
                    enriched_event,
                )

                if event.get("event_type") == "session_close":

                    context["status"] = "closed"
                    context["end_time"] = event.get("timestamp")

                return enriched_event

            # -----------------------------------------------------
            # MULTIPLE CONTEXTS
            # -----------------------------------------------------

            if len(candidates) > 1:

                self.unmatched_events.append({
                    "reason": "ambiguous_context",
                    "event": event,
                    "candidate_contexts": [
                        {
                            "remote_ip": c.get("remote_ip"),
                            "username": c.get("username"),
                            "session_id": c.get("session_id"),
                            "tty": c.get("tty"),
                        }
                        for c in candidates
                    ],
                })

                return {
                    "event": event,
                    "context": None,
                    "context_status": "ambiguous_context",
                }

            # -----------------------------------------------------
            # NO MATCH
            # -----------------------------------------------------

            self.unmatched_events.append({
                "reason": "no_matching_context",
                "event": event,
            })

            return {
                "event": event,
                "context": None,
            }

    # ---------------------------------------------------------
    # FLUSH LOOP
    # ---------------------------------------------------------

    def start_flush_loop(
        self,
        callback,
        security_callback=None,
    ):

        self.flush_callback = callback
        self.security_flush_callback = security_callback

        if self._flush_running:
            return

        self._flush_running = True

        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            daemon=True,
        )

        self._flush_thread.start()

    def _flush_loop(self):

        while self._flush_running:

            time.sleep(
                self.FLUSH_INTERVAL_SECONDS
            )

            try:
                self.flush_pending()
            except Exception as exc:
                print(
                    f"[ContextManager] flush error: {exc}"
                )

    # ---------------------------------------------------------
    # FLUSH
    # ---------------------------------------------------------

    def flush_pending(self):

        batches = []
        security_events = []
        standalone_events = []

        with self._lock:

            # -------------------------------------------------
            # NORMAL SSH CONTEXT BATCHES
            # -------------------------------------------------

            for context in self.contexts.values():

                pending = context.get(
                    "pending_events",
                    [],
                )

                if not pending:
                    continue

                batch = {
                    "type": "context_batch",
                    "host_ip": context.get("host_ip"),
                    "remote_ip": context.get("remote_ip"),
                    "username": context.get("username"),
                    "session_id": context.get("session_id"),
                    "tty": context.get("tty"),
                    "start_time": context.get("start_time"),
                    "end_time": context.get("end_time"),
                    "status": context.get("status"),
                    "events": list(pending),
                }

                context["pending_events"] = []
                context["last_flush_time"] = time.monotonic()

                batches.append(batch)

            # -------------------------------------------------
            # AUTHENTICATION SECURITY EVENTS
            # -------------------------------------------------

            if self.pending_security_events:

                security_events = list(
                    self.pending_security_events
                )

                self.pending_security_events = []

            # -------------------------------------------------
            # STANDALONE EVENTS
            # -------------------------------------------------

            if self.pending_standalone_events:

                standalone_events = list(
                    self.pending_standalone_events
                )

                self.pending_standalone_events = []

        # -----------------------------------------------------
        # SEND NORMAL CONTEXT BATCHES
        # -----------------------------------------------------

        if self.flush_callback:

            for batch in batches:

                try:
                    self.flush_callback(batch)

                except Exception as exc:
                    print(
                        f"[ContextManager] batch callback error: {exc}"
                    )

        # -----------------------------------------------------
        # SEND STANDALONE EVENT BATCH
        # -----------------------------------------------------

        if standalone_events and self.flush_callback:

            standalone_batch = {
                "type": "event_batch",
                "event_count": len(standalone_events),
                "events": standalone_events,
            }

            try:
                self.flush_callback(standalone_batch)

            except Exception as exc:
                print(
                    "[ContextManager] "
                    f"standalone callback error: {exc}"
                )

        # -----------------------------------------------------
        # SEND SECURITY BATCH
        # -----------------------------------------------------

        if (
            security_events
            and self.security_flush_callback
        ):

            security_batch = {
                "type": "security_events",
                "event_count": len(security_events),
                "events": security_events,
            }

            try:
                self.security_flush_callback(
                    security_batch
                )

            except Exception as exc:
                print(
                    "[ContextManager] "
                    f"security callback error: {exc}"
                )

    # ---------------------------------------------------------
    # STOP
    # ---------------------------------------------------------

    def stop_flush_loop(self):

        self._flush_running = False

        if (
            self._flush_thread
            and self._flush_thread.is_alive()
        ):
            self._flush_thread.join(
                timeout=2
            )

    # ---------------------------------------------------------
    # DEBUG
    # ---------------------------------------------------------

    def get_active_contexts(self):

        with self._lock:

            return [
                {
                    "host_ip": c.get("host_ip"),
                    "remote_ip": c.get("remote_ip"),
                    "username": c.get("username"),
                    "session_id": c.get("session_id"),
                    "tty": c.get("tty"),
                    "status": c.get("status"),
                    "event_count": len(
                        c.get("events", [])
                    ),
                }
                for c in self.contexts.values()
                if c.get("status") == "active"
            ]

    def get_unmatched_events(self):

        with self._lock:
            return list(self.unmatched_events)

