import ctypes
import os
import struct

WATCH_ROOTS = [
    "/home/sangeeth/Desktop",
    "/home/sangeeth/Documents",
    "/home/sangeeth/Downloads",
    "/home/sangeeth/Pictures",
    "/home/sangeeth/Videos",
    "/home/sangeeth/Music",
    "/home/sangeeth/Projects",
    "/home/sangeeth/Public",
    "/home/sangeeth/Templates",
    "/home/sangeeth/.local/share/Trash",
    "/mnt",
    "/media",
]

IN_CREATE = 0x00000100
IN_MODIFY = 0x00000002
IN_DELETE = 0x00000200
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080

IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_IGNORED = 0x00008000

MASK = (
    IN_CREATE
    | IN_MODIFY
    | IN_DELETE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)

libc = ctypes.CDLL(None)

fd = libc.inotify_init1(0)

if fd < 0:
    raise OSError("inotify_init1 failed")

EVENT_STRUCT = struct.Struct("iIII")

watch_paths = {}
watch_descriptors = {}


def remove_watch(wd):
    path = watch_paths.pop(wd, None)

    if path is not None:
        watch_descriptors.pop(path, None)


def add_watch(path):
    if not os.path.isdir(path):
        return

    if path in watch_descriptors:
        return

    wd = libc.inotify_add_watch(
        fd,
        path.encode(),
        MASK
    )

    if wd < 0:
        return

    watch_paths[wd] = path
    watch_descriptors[path] = wd


def add_recursive(root):
    if not os.path.isdir(root):
        return

    add_watch(root)

    for current_root, directories, _ in os.walk(root):
        for directory in directories:
            add_watch(os.path.join(current_root, directory))


for root in WATCH_ROOTS:
    add_recursive(root)

print("GHOSTWIRE File Collector started...")
print("Waiting for filesystem events...\n")

try:
    while True:
        data = os.read(fd, 65536)

        offset = 0

        while offset < len(data):
            wd, mask, cookie, name_len = EVENT_STRUCT.unpack_from(
                data,
                offset
            )

            offset += EVENT_STRUCT.size

            name = data[offset:offset + name_len].split(b"\0", 1)[0]
            offset += name_len

            name = name.decode(errors="replace")

            parent = watch_paths.get(wd)

            if parent is None:
                continue

            full_path = os.path.join(parent, name)

            print(mask, cookie, full_path)

            if mask & IN_CREATE:
                if os.path.isdir(full_path):
                    add_recursive(full_path)

            if mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED):
                remove_watch(wd)

finally:
    os.close(fd)
