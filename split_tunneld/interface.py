# pyright: reportUnknownMemberType=false
import ctypes
import logging
import os
from typing import final

import bcc
from dbus_fast import DBusError, ErrorType
from dbus_fast.service import ServiceInterface, dbus_method
from dbus_fast.annotations import DBusStr, DBusUInt32


FWMARK_MAP_KEY = ctypes.c_int32(1)
BPF_PROGRAM = """
BPF_TABLE_PINNED("hash", u32, u32, fwmark_map, 1, "/sys/fs/bpf/split-tunneld/fwmark_map");

int split_tunnel(struct bpf_sock *sk) {
    u32 fwmark_key = 1;
    u32 *fwmark = fwmark_map.lookup(&fwmark_key);

    if (fwmark) {
        sk->mark = *fwmark;
    }

    return 1;
}
"""


logger = logging.getLogger(__name__)


@final
class SplitTunnelInterface(ServiceInterface):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self._bpf = bcc.BPF(text=BPF_PROGRAM)
        self._bpf_fwmark_map: bcc.table.HashTable = self._bpf.get_table("fwmark_map")
        self._bpf_split_tunneling_func = self._bpf.load_func(
            "split_tunnel", self._bpf.CGROUP_SOCK
        )

    @dbus_method()
    def SetFwmark(self, fwmark: DBusUInt32):
        value = self._bpf_fwmark_map.get(FWMARK_MAP_KEY)  # pyright: ignore[reportUnknownVariableType]

        if value is not None and value == fwmark:
            logger.warning(f"the fwmark is already set to '{fwmark}'")
            return

        self._bpf_fwmark_map[FWMARK_MAP_KEY] = ctypes.c_int32(fwmark)

    @dbus_method()
    def RemoveFwmark(self):
        if self._bpf_fwmark_map.get(FWMARK_MAP_KEY) is None:
            logger.warning(f"the fwmark is not set")
            return

        del self._bpf_fwmark_map[FWMARK_MAP_KEY]

    @dbus_method()
    def AddCgroupToSplitTunnel(self, path: DBusStr):
        if not os.path.exists(path):
            raise DBusError(ErrorType.FILE_NOT_FOUND, "cgroup not found")

        cgroup = os.open(path, os.O_RDONLY)

        self._bpf.attach_func(
            self._bpf_split_tunneling_func,
            cgroup,
            bcc.BPFAttachType.CGROUP_INET_SOCK_CREATE,
        )

        os.close(cgroup)
