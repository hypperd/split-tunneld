import argparse
import asyncio
import logging
from signal import SIGINT, SIGTERM
import sys

from dbus_fast.aio import MessageBus
from dbus_fast.constants import BusType
from setproctitle import setproctitle

from .interface import SplitTunnelInterface

DBUS_PATH = "/org/hypperd/SplitTunnel"
DBUS_INTERFACE = "org.hypperd.SplitTunnel"

logger = logging.getLogger(__name__)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("-v", "--verbose", action="count", default=0)
    return parser.parse_args()


async def start(finalize_event: asyncio.Event) -> None:
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    _ = await bus.request_name(DBUS_INTERFACE)
    bus.export(DBUS_PATH, SplitTunnelInterface(DBUS_INTERFACE))

    _ = await finalize_event.wait()
    bus.disconnect()
    await bus.wait_for_disconnect()


def main():
    setproctitle("split-tunneld")
    arguments = parse_arguments()

    error = False
    logging.basicConfig(
        level=max((3 - arguments.verbose) * 10, 0),  # pyright: ignore[reportAny]
        format="%(levelname)s: %(message)s",
    )

    loop = asyncio.new_event_loop()
    finalize_event = asyncio.Event()
    loop.add_signal_handler(SIGINT, lambda: finalize_event.set())
    loop.add_signal_handler(SIGTERM, lambda: finalize_event.set())

    try:
        loop.run_until_complete(start(finalize_event))
    except Exception as ex:
        logger.exception(ex)
        error = True
    finally:
        loop.close()

    if error:
        sys.exit(1)
