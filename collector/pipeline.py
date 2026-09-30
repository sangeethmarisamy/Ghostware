from context_manager import ContextManager

from processor.authentication import (
    parse_authentication_event,
    validate_authentication_event,
    deduplicate_authentication_event,
    normalize_authentication_event,
)

from processor.command import (
    parse_command_event,
    validate_command_event,
    deduplicate_command_event,
    normalize_command_event,
)

from processor.file import (
    parse_file_event,
    validate_file_event,
    deduplicate_file_event,
    normalize_file_event,
)

from processor.process import (
    parse_process_event,
    validate_process_event,
    deduplicate_process_event,
    normalize_process_event,
)

from processor.network import (
    parse_network_event,
    validate_network_event,
    deduplicate_network_event,
    normalize_network_event,
)

from processor.cron import (
    parse_cron_event,
    validate_cron_event,
    deduplicate_cron_event,
    normalize_cron_event,
)


class EventPipeline:

    PROCESSORS = {
        "authentication": (
            parse_authentication_event,
            validate_authentication_event,
            deduplicate_authentication_event,
            normalize_authentication_event,
        ),
        "command": (
            parse_command_event,
            validate_command_event,
            deduplicate_command_event,
            normalize_command_event,
        ),
        "file": (
            parse_file_event,
            validate_file_event,
            deduplicate_file_event,
            normalize_file_event,
        ),
        "process": (
            parse_process_event,
            validate_process_event,
            deduplicate_process_event,
            normalize_process_event,
        ),
        "network": (
            parse_network_event,
            validate_network_event,
            deduplicate_network_event,
            normalize_network_event,
        ),
        "cron": (
            parse_cron_event,
            validate_cron_event,
            deduplicate_cron_event,
            normalize_cron_event,
        ),
    }

    def __init__(self):
        self.context_manager = ContextManager()

        self.batch_callback = None
        self.security_batch_callback = None

    # ---------------------------------------------------------
    # RAW -> NORMALIZED -> CONTEXT
    # ---------------------------------------------------------

    def process_raw_line(self, source, raw_line):

        if source not in self.PROCESSORS:
            return None

        (
            parse_event,
            validate_event,
            deduplicate_event,
            normalize_event,
        ) = self.PROCESSORS[source]

        event = parse_event(raw_line)

        if not validate_event(event):
            return None

        if not deduplicate_event(event):
            return None

        normalized = normalize_event(event)

        if not normalized:
            return None

        return self.process_event(normalized)

    # ---------------------------------------------------------
    # EVENT PROCESSING
    # ---------------------------------------------------------

    def process_event(self, event):

        if not event:
            return None

        source = event.get("source")

        # Authentication has special context handling.
        #
        # login_success -> normal SSH context
        # login_failure -> separate security event
        #
        if source == "authentication":
            return self.context_manager.handle_authentication_event(
                event
            )

        enriched_event = self.context_manager.find_context_for_event(
            event
        )

        if enriched_event:
            return enriched_event

        # No SSH context: queue as a standalone event so it
        # is still transferred to the downstream receiver.
        standalone_event = {
            "event": event,
            "context": None,
        }

        with self.context_manager._lock:
            self.context_manager.pending_standalone_events.append(
                standalone_event
            )

            print(
                "[Pipeline] STANDALONE EVENT QUEUED "
                f"(source={event.get('source')}, "
                f"type={event.get('event_type')}, "
                f"queue_size="
                f"{len(self.context_manager.pending_standalone_events)})"
            )

        return standalone_event

    # ---------------------------------------------------------
    # NORMAL CONTEXT BATCH
    # ---------------------------------------------------------

    def _handle_batch(self, batch):

        if self.batch_callback:
            self.batch_callback(batch)

    # ---------------------------------------------------------
    # SECURITY EVENT BATCH
    # ---------------------------------------------------------

    def _handle_security_batch(self, batch):

        if self.security_batch_callback:
            self.security_batch_callback(batch)

    # ---------------------------------------------------------
    # START
    # ---------------------------------------------------------

    def start(
        self,
        batch_callback,
        security_batch_callback=None,
    ):

        self.batch_callback = batch_callback
        self.security_batch_callback = security_batch_callback

        self.context_manager.start_flush_loop(
            self._handle_batch,
            self._handle_security_batch,
        )

    # ---------------------------------------------------------
    # STOP
    # ---------------------------------------------------------

    def stop(self):

        self.context_manager.stop_flush_loop()
