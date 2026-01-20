#! /usr/bin/env python3

import os
import struct
import fcntl
import sys
import argparse
import asyncio
import socket
import ipaddress
import logging
from contextlib import closing
from abc import ABC, abstractmethod
import zlib


CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000

MAX_PACKET_SIZE = 1 * 1024 * 1024


def setns(fd, flags):
    import ctypes

    ctypes.cdll.LoadLibrary("libc.so.6")
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    ret = libc.setns(ctypes.c_int(fd.fileno()), ctypes.c_int(flags))
    if ret != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def create_tap(name, device):
    fd = os.fdopen(os.open(device, os.O_RDWR))
    TUNSETIFF = 0x400454CA
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    ifr = struct.pack("16sH22s", name.encode("utf-8"), IFF_TAP | IFF_NO_PI, b"\x00" * 22)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd


def nsenter(path, flags):
    with os.fdopen(os.open(path, os.O_RDONLY)) as fd:
        setns(fd, flags)


class ReadyFD(object):
    def __init__(self, fd):
        self.fd = fd

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def signal(self):
        if self.fd >= 0:
            os.write(self.fd, b"1")
            self.close()


class Stream(ABC):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    async def stream_to(self, dest):
        async for data in self:
            await dest.send(data)

    async def stream(self, dest):
        await asyncio.gather(self.stream_to(dest), dest.stream_to(self))

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            data = await self.recv()
            if not data:
                raise StopAsyncIteration
        except EOFError:
            raise StopAsyncIteration
        return data

    @abstractmethod
    async def send(self, data):
        raise NotImplementedError("Must be implemented in derived classes")

    @abstractmethod
    async def recv(self):
        raise NotImplementedError("Must be implemented in derived classes")


class TapStream(Stream):
    def __init__(self, fd):
        super().__init__()
        self.fd = fd
        os.set_blocking(self.fd, False)

        self.read_buf = None
        self.read_lock = asyncio.Lock()
        self.read_event = asyncio.Event()

        self.write_buf = None
        self.write_lock = asyncio.Lock()
        self.write_event = asyncio.Event()

        self.loop = asyncio.get_running_loop()

    def __do_read(self):
        if not self.read_buf:
            try:
                self.read_buf = os.read(self.fd, MAX_PACKET_SIZE)
            except BlockingIOError:
                self.logger.debug("Would block on read")
                return

        self.read_event.set()

    def __do_write(self):
        if self.write_buf:
            try:
                os.write(self.fd, self.write_buf)
            except BlockingIOError:
                self.logger.debug("Would block on write")
                return

            self.logger.debug("Wrote %d bytes", len(self.write_buf))
            self.write_buf = None

        self.write_event.set()

    async def send(self, data):
        async with self.write_lock:
            hdr = struct.unpack_from("@hh", data)
            self.logger.debug("Writing %d bytes: %s", len(data), hdr)

            self.write_buf = data

            self.loop.add_writer(self.fd, self.__do_write)
            try:
                while self.write_buf:
                    await self.write_event.wait()
                    self.write_event.clear()
            finally:
                self.loop.remove_writer(self.fd)

    async def recv(self):
        async with self.read_lock:
            self.loop.add_reader(self.fd, self.__do_read)
            try:
                while not self.read_buf:
                    await self.read_event.wait()
                    self.read_event.clear()
            finally:
                self.loop.remove_reader(self.fd)

            data = self.read_buf
            self.read_buf = None
            # data = struct.pack(">hh", *hdr) + self.read_buf[4:]

        hdr = struct.unpack_from("@hh", data)
        self.logger.debug("Got %d bytes: %s", len(data), hdr)
        return data


class ProtocolError(Exception):
    pass


class ProtocolStream(Stream):
    MAGIC = b"TAPT\x01"

    HEADER_FORMAT = "<LL"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    @classmethod
    async def connect(cls, *args, **kwargs):
        s = cls(*args, **kwargs)
        s.write(cls.MAGIC)
        _, remote_magic = await asyncio.gather(s.drain(), s.read(len(cls.MAGIC)))
        if remote_magic != cls.MAGIC:
            raise ProtocolError(f"Bad magic from remote. Got {remote_magic}, expected {cls.MAGIC}")
        logging.debug("Verified remote magic: %s", remote_magic)
        return s

    @abstractmethod
    async def read(self, size):
        raise NotImplementedError("Must be implemented in derived classes")

    @abstractmethod
    def write(self, data):
        raise NotImplementedError("Must be implemented in derived classes")

    @abstractmethod
    async def drain(self):
        raise NotImplementedError("Must be implemented in derived classes")

    async def send(self, data):
        self.write(struct.pack(self.HEADER_FORMAT, len(data), zlib.crc32(data)))
        self.write(data)
        await self.drain()
        self.logger.debug("Sent %d bytes", len(data))

    async def recv(self):
        hdr = struct.unpack(self.HEADER_FORMAT, await self.read(self.HEADER_SIZE))
        data = await self.read(hdr[0])
        exp_crc = zlib.crc32(data)
        if exp_crc != hdr[1]:
            raise ProtocolError("Invalid CRC. Expected %d, got %d", exp_crc, hdr[1])
        self.logger.debug("Received %d bytes", len(data))
        return data


class SocketStream(ProtocolStream):
    def __init__(self, reader, writer):
        super().__init__()
        self.reader = reader
        self.writer = writer

    async def read(self, size):
        return await self.reader.readexactly(size)

    @abstractmethod
    def write(self, data):
        self.writer.write(data)

    @abstractmethod
    async def drain(self):
        await self.writer.drain()


class FDStream(ProtocolStream):
    def __init__(self, in_fd, out_fd):
        super().__init__()
        self.in_fd = in_fd
        self.out_fd = out_fd

        os.set_blocking(self.in_fd, False)
        os.set_blocking(self.out_fd, False)

        self._eof = False

        self._read_buf = b""
        self._read_lock = asyncio.Lock()
        self._read_event = asyncio.Event()

        self._write_buf = b""
        self._write_lock = asyncio.Lock()
        self._write_event = asyncio.Event()

        self.loop = asyncio.get_running_loop()

    def _set_eof(self):
        if not self._eof:
            logging.info("Got EOF")
            self._eof = True

    def __do_read(self):
        try:
            data = os.read(self.in_fd, 1024)
        except BlockingIOError:
            self.logger.debug("Would block on read")
            return
        except BrokenPipeError:
            self._set_eof()
            self._read_event.set()
            return

        if not data:
            self._set_eof()
        else:
            self._read_buf += data
        self._read_event.set()

    def __do_write(self):
        if self._write_buf:
            try:
                w = os.write(self.out_fd, self._write_buf)
            except BlockingIOError:
                self.logger.debug("Would block on write")
                return
            except BrokenPipeError:
                self._set_eof()
                self._write_event.set()
                return

            if w == 0:
                self._set_eof()
            else:
                self._write_buf = self._write_buf[w:]

        self._write_event.set()

    async def read(self, size):
        async with self._read_lock:
            self.loop.add_reader(self.in_fd, self.__do_read)
            try:
                while len(self._read_buf) < size:
                    if self._eof:
                        raise EOFError()
                    await self._read_event.wait()
                    self._read_event.clear()
            finally:
                self.loop.remove_reader(self.in_fd)

            data = self._read_buf[:size]
            self._read_buf = self._read_buf[size:]

        return data

    def write(self, data):
        self._write_buf += data

    async def drain(self):
        async with self._write_lock:
            self.loop.add_writer(self.out_fd, self.__do_write)
            try:
                while self._write_buf:
                    if self._eof:
                        raise EOFError()
                    await self._write_event.wait()
                    self._write_event.clear()
            finally:
                self.loop.remove_writer(self.out_fd)


class TCPClient(object):
    def __init__(self, reader, writer, tap):
        self.reader = reader
        self.writer = writer
        self.tap = tap
        self.logger = logging.getLogger(self.__class__.__name__)

    @classmethod
    async def create(cls, host, port, tap):
        logging.info("Connecting to %s:%d", host, port)
        reader, writer = await asyncio.open_connection(host, port)
        logging.info("Connected to %s", writer.get_extra_info("peername"))
        return cls(reader, writer, tap)

    async def stream_forever(self):
        sock = await SocketStream.connect(self.reader, self.writer)
        await sock.stream(self.tap)


class TCPServer(object):
    def __init__(self, tap):
        self.server = None
        self.tap = tap
        self.clients = []
        self.logger = logging.getLogger(self.__class__.__name__)

    @classmethod
    async def create(cls, address, port, tap):
        server = cls(tap)
        server.server = await asyncio.start_server(server._client_connected_callback, str(address), port)

        for s in server.server.sockets:
            server.logger.info("Listening on %s", s.getsockname())

        return server

    async def serve_forever(self):
        async with self.server:
            await asyncio.gather(self.server.serve_forever(), self._stream_to_clients())

    async def _client_connected_callback(self, reader, writer):
        self.logger.info("Client %s Connected", writer.get_extra_info("peername"))
        sock = await SocketStream.connect(reader, writer)
        try:
            self.clients.append(sock)
            await sock.stream_to(self.tap)
        except asyncio.IncompleteReadError:
            pass
        finally:
            self.logger.info("Client %s disconnected", writer.get_extra_info("peername"))

    async def _stream_to_clients(self):
        async for data in self.tap:
            await asyncio.gather(*(c.send(data) for c in self.clients))


async def client_main(args, tap, ready):
    client = await TCPClient.create(args.host, args.port, tap)
    ready.signal()
    await client.stream_forever()
    return 0


async def server_main(args, tap, ready):
    server = await TCPServer.create(args.address, args.port, tap)
    ready.signal()
    await server.serve_forever()
    return 0


async def fd_main(args, tap, ready):
    ready.signal()

    in_fd = args.fd
    out_fd = args.fd if args.out_fd is None else args.out_fd

    s = await FDStream.connect(in_fd, out_fd)
    await s.stream(tap)
    return 0


async def stdio_main(args, tap, ready):
    # Duplicate stdin and stdout to new file descriptors for dedicated by the
    # stream. Replace the normal stdin and stdout descriptors with /dev/null to
    # prevent errant output from corrupting the stream
    with os.fdopen(os.dup(sys.stdin.fileno())) as in_fd, os.fdopen(os.dup(sys.stdout.fileno())) as out_fd:
        with open(os.devnull, "r+") as devnull:
            os.dup2(devnull.fileno(), sys.stdin.fileno())
        os.dup2(sys.stderr.fileno(), sys.stdout.fileno())

        ready.signal()

        logging.debug("In FD is %d", in_fd.fileno())
        logging.debug("Out FD is %d", out_fd.fileno())

        s = await FDStream.connect(in_fd.fileno(), out_fd.fileno())

        await asyncio.gather(s.stream(tap))
    return 0


async def amain():
    parser = argparse.ArgumentParser(description="Tunnel TAP data")

    parser.add_argument("--device", "-d", help="TUN device", default="/dev/net/tun")
    parser.add_argument("--tap-name", "-t", help="TAP name", default="tap0")

    ns_group = parser.add_mutually_exclusive_group()
    ns_group.add_argument(
        "--netns-pid",
        "-p",
        type=int,
        help="Network namespace PID",
    )
    ns_group.add_argument("--netns-path", help="Path to network namespace")

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=-1,
        help="Increase verbosity",
    )
    parser.add_argument(
        "--ready-fd",
        type=int,
        default=-1,
        help="Ready signal file descriptor",
    )
    subparsers = parser.add_subparsers(help="TAP streaming target", required=True)

    server_parser = subparsers.add_parser("server", help="Run as a TCP server")
    server_parser.add_argument("address", type=ipaddress.ip_address, help="Bind address")
    server_parser.add_argument("port", type=int, help="Bind port")
    server_parser.set_defaults(func=server_main)

    client_parser = subparsers.add_parser("client", help="Connect to TCP server")
    client_parser.add_argument("host", help="Connect to host")
    client_parser.add_argument("port", type=int, help="Connect to port")
    client_parser.set_defaults(func=client_main)

    fd_parser = subparsers.add_parser("fd", help="Stream though file descriptor")
    fd_parser.add_argument("fd", type=int, help="File descriptor")
    fd_parser.add_argument(
        "out_fd",
        type=int,
        nargs="?",
        default=None,
        help="Output file descriptor, if different than input",
    )
    fd_parser.set_defaults(func=fd_main)

    stdio_parser = subparsers.add_parser("stdio", help="Stream through stdin/stdout")
    stdio_parser.set_defaults(func=stdio_main)

    args = parser.parse_args()

    if args.verbose >= 1:
        level = logging.DEBUG
    elif args.verbose >= 0:
        level = logging.INFO
    else:
        level = logging.WARNING
    root = logging.getLogger()
    root.setLevel(level)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    formatter = logging.Formatter(f"{os.getpid()}: %(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    root.addHandler(handler)

    rsock, wsock = socket.socketpair()

    with closing(rsock), closing(wsock):
        pid = os.fork()
        if pid == 0:
            # Child
            if args.netns_path:
                nsenter(args.netns_path, CLONE_NEWNET)
            elif args.netns_pid:
                nsenter(f"/proc/{args.netns_pid}/ns/user", CLONE_NEWUSER)
                nsenter(f"/proc/{args.netns_pid}/ns/net", CLONE_NEWNET)

            with create_tap(args.tap_name, args.device) as fd:
                socket.send_fds(wsock, [b"\x00"], [fd.fileno()])
            return 0

        wsock.close()
        _, fds, _, _ = socket.recv_fds(rsock, 1024, 1024)

    logging.debug("Waiting for child %d", pid)
    _, status = os.waitpid(pid, 0)
    returncode = os.waitstatus_to_exitcode(status)
    if returncode != 0:
        logging.error("Child %d exited with %d", pid, returncode)
        return 1

    logging.debug("TAP is FD %d", fds[0])

    with os.fdopen(fds[0]) as tap_fd, ReadyFD(args.ready_fd) as ready:
        t = TapStream(tap_fd.fileno())
        return await args.func(args, t, ready)

    return 0


def main():
    return asyncio.run(amain())


if __name__ == "__main__":
    sys.exit(main())
