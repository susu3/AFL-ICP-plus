"""Bounded AF_UNIX wire receiver. It writes complete frames before index entries."""
import argparse
import hashlib
import json
import os
import socket
import struct
import time
from pathlib import Path
from ..common import ICPError, atomic_write, canonical, save_json

MAGIC = b"AICPEV01"
HEADER = struct.Struct("<8sHHQ")
FIXED = struct.Struct("<QQIBBHQQIIII")
REQ = struct.Struct("<IIHHQ")
WINDOW = struct.Struct("<iiIIQ")


def read_exact(stream, size, heartbeat=None):
    parts = bytearray()
    while len(parts) < size:
        try:
            data = stream.recv(size - len(parts))
        except socket.timeout:
            if heartbeat:
                atomic_write(heartbeat, str(time.time()))
            continue
        if not data:
            raise EOFError("truncated evidence frame")
        parts.extend(data)
    return bytes(parts)


def validate_payload(payload, maximum):
    if len(payload) < FIXED.size or len(payload) + HEADER.size > maximum:
        raise ICPError("Evidence payload outside configured bounds", "evidence")
    exec_id, case_id, triggers, novelty, outcome, reserved, start, end, nr, nw, ns, nb = FIXED.unpack_from(payload)
    if reserved or triggers & ~3 or novelty not in (0, 1, 2) or outcome != 0:
        raise ICPError("Unknown evidence flags or outcome", "evidence")
    if nr > maximum // REQ.size or nw > maximum // WINDOW.size or ns > maximum // 4 or nb > maximum:
        raise ICPError("Evidence count exceeds configured bound", "evidence")
    offset, requests, windows = FIXED.size, [], []
    def take(size):
        nonlocal offset
        if size < 0 or offset > len(payload) or size > len(payload) - offset:
            raise ICPError("Evidence field extends beyond frame", "evidence")
        part = payload[offset:offset + size]
        offset += size
        return part
    for _ in range(nr):
        planned, sent, status, flags, timestamp = REQ.unpack(take(REQ.size))
        data = take(planned)
        if flags & ~3 or (flags & 2 and sent != 0xffffffff) or status not in (0, 1, 2, 3):
            raise ICPError("Invalid evidence request metadata", "evidence")
        requests.append({"planned_length": planned, "sent_length": None if sent == 0xffffffff else sent,
                         "send_status": status, "timestamp_ns": timestamp if not flags & 1 else None,
                         "planned_hex": data.hex()})
    for _ in range(nw):
        after, status, length, flags, timestamp = WINDOW.unpack(take(WINDOW.size))
        data = take(length)
        if flags & ~7 or after < -1 or after >= nr or status not in (0, 1):
            raise ICPError("Invalid receive window metadata", "evidence")
        windows.append({"after_request_index": after, "receive_status": status, "timestamp_ns": timestamp if not flags & 1 else None,
                        "tail": bool(flags & 4), "data_hex": data.hex()})
    states_raw = take(ns * 4)
    states = list(struct.unpack("<%dI" % ns, states_raw)) if ns else []
    bitmap = take(nb)
    if offset != len(payload):
        raise ICPError("Trailing bytes in evidence payload", "evidence")
    return {"execution_id": exec_id, "fuzz_case_index": case_id, "trigger_bits": triggers,
            "trigger_reasons": [name for bit, name in ((1, "new_coverage"), (2, "periodic")) if triggers & bit],
            "novelty": novelty, "execution_outcome": "normal", "start_time_ns": start or None, "end_time_ns": end or None,
            "requests": requests, "receive_windows": windows, "state_sequence": states,
            "coverage_bitmap_hex": bitmap.hex(), "completeness": "complete"}


class EvidenceWriter:
    def __init__(self, root, campaign_id, max_record_bytes, queue_capacity_bytes, pack_segment_bytes, identity_path=None):
        self.root = Path(root)
        self.campaign_id = campaign_id
        self.maximum = max_record_bytes
        self.queue_capacity = queue_capacity_bytes
        self.pack_segment_bytes = pack_segment_bytes
        self.identity = json.loads(Path(identity_path).read_text()) if identity_path else {}
        self.socket_path = Path("/tmp") / ("aflicp-" + campaign_id[:24] + ".sock")
        self.status_path = self.root / "interactions" / "writer-status.json"
        self.heartbeat_path = self.root / "interactions" / "writer-heartbeat"

    def serve(self):
        self.root.joinpath("interactions").mkdir(parents=True, exist_ok=True)
        for stale in (self.status_path, self.heartbeat_path):
            try:
                stale.unlink()
            except FileNotFoundError:
                pass
        if self.socket_path.exists() or self.socket_path.is_symlink():
            if not self.socket_path.is_socket():
                raise ICPError("Evidence socket path exists and is not a socket")
            self.socket_path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.queue_capacity)
        server.bind(str(self.socket_path)); os.chmod(self.socket_path, 0o600); server.listen(1)
        self.heartbeat_path.write_text(str(time.time()))
        atomic_write(self.root / "interactions" / "writer-ready", self.campaign_id)
        frames = sum(len(path.read_text().splitlines()) for path in (self.root / "interactions").glob("records-*.jsonl"))
        existing_packs = sorted((self.root / "interactions").glob("records-*.pack"))
        segment = max([int(path.stem.split("-")[-1]) for path in existing_packs] or [0])
        indexed = {int(path.stem.split("-")[-1]) for path in (self.root / "interactions").glob("records-*.jsonl")}
        packed = {int(path.stem.split("-")[-1]) for path in existing_packs}
        if packed != indexed:
            raise ICPError("Evidence pack/index segment mismatch; preserve artifacts and mark this campaign incomplete", "evidence")
        pack = None
        try:
            connection, _ = server.accept()
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.queue_capacity)
            connection.settimeout(1.0)
            while True:
                header = read_exact(connection, HEADER.size, self.heartbeat_path)
                magic, version, flags, length = HEADER.unpack(header)
                if magic != MAGIC or version != 1 or flags != 0 or length > self.maximum:
                    raise ICPError("Invalid evidence wire header", "evidence")
                if length == 0:
                    if pack:
                        pack.flush(); os.fsync(pack.fileno()); pack.close(); pack = None
                    save_json(self.status_path, {"status": "complete", "frames": frames, "campaign_id": self.campaign_id})
                    connection.sendall(b"K")
                    return
                payload = read_exact(connection, length, self.heartbeat_path)
                metadata = validate_payload(payload, self.maximum)
                record_bytes = header + payload
                if pack and pack.tell() + len(record_bytes) > self.pack_segment_bytes:
                    pack.flush(); os.fsync(pack.fileno()); pack.close(); pack = None
                if not pack:
                    segment += 1
                    pack = (self.root / "interactions" / ("records-%04d.pack" % segment)).open("xb")
                offset = pack.tell()
                pack.write(header); pack.write(payload); pack.flush(); os.fsync(pack.fileno())
                bitmap_hex = metadata.pop("coverage_bitmap_hex")
                metadata["coverage_bitmap"] = {"bytes": len(bitmap_hex) // 2,
                                                "sha256": hashlib.sha256(bytes.fromhex(bitmap_hex)).hexdigest()}
                entry = {"campaign_id": self.campaign_id, "segment": segment, "offset": offset, "length": len(record_bytes),
                         "sha256": hashlib.sha256(record_bytes).hexdigest(), "codec": "none", **metadata}
                entry.update(self.identity)
                index_path = self.root / "interactions" / ("records-%04d.jsonl" % segment)
                with index_path.open("ab") as index_stream:
                    index_stream.write(canonical(entry) + b"\n")
                    index_stream.flush(); os.fsync(index_stream.fileno())
                frames += 1
        except BaseException as exc:
            save_json(self.status_path, {"status": "incomplete", "frames": frames, "campaign_id": self.campaign_id,
                      "error": str(exc), "time": time.time()})
            raise
        finally:
            if pack:
                pack.close()
            server.close()
            if self.socket_path.exists():
                self.socket_path.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--max-record-bytes", type=int, required=True)
    parser.add_argument("--queue-capacity-bytes", type=int, required=True)
    parser.add_argument("--pack-segment-bytes", type=int, required=True)
    parser.add_argument("--identity-file")
    args = parser.parse_args(argv)
    EvidenceWriter(args.root, args.campaign_id, args.max_record_bytes, args.queue_capacity_bytes,
                   args.pack_segment_bytes, args.identity_file).serve()


if __name__ == "__main__":
    main()
