from __future__ import annotations

import os
import signal
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import utils
from cipher import HEADER_SIZE, StreamCipherSession
from playerman import PlayerManager
from rankman import RankManager
from stageman import StageManager


class PacketType:
    REGISTER = 0
    LOGIN = 1
    LOGOUT = 2
    RETRIEVE = 3
    LIST = 4
    GET = 5
    PUT = 6
    MAILLIST = 7
    MAILGET = 8
    MAILDEL = 9
    MAILPUT = 10
    SCORE = 11
    RANKING = 12
    DLNOTIFY = 16


class ServerStatus:
    OK = b"OK"
    NG = b"NG"
    SC = b"SC"
    IM = b"IM"
    DN = b"DN"
    EX = b"EX"
    DU = b"DU"
    NF = b"NF"
    MO = b"MO"
    BD = b"BD"


LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 80
DEFAULT_HEADER_BUFFER = b"MOZIBURIBON         "
SESSION_TIMEOUT_SECONDS = 3 * 60
_STOP_EVENT = threading.Event()


@dataclass
class ClientState:
    player_id: str | None = None
    logged_in: bool = False


class SessionRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, str] = {}
        self._ciphers: dict[str, StreamCipherSession] = {}
        self._cipher_headers: dict[str, bytes] = {}
        self._last_seen: dict[str, float] = {}

    def touch(self, client_id: str) -> None:
        with self._lock:
            self._last_seen[client_id] = time.time()

    def bind(self, client_id: str, player_id: str) -> None:
        with self._lock:
            self._sessions[client_id] = player_id
            self._last_seen[client_id] = time.time()

    def get_player(self, client_id: str) -> str | None:
        with self._lock:
            return self._sessions.get(client_id)

    def get_or_create_cipher(
        self, client_id: str, header: bytes
    ) -> StreamCipherSession:
        with self._lock:
            cipher = self._ciphers.get(client_id)
            last_header = self._cipher_headers.get(client_id)
            if cipher is None or last_header != header:
                cipher = StreamCipherSession()
                cipher.initialize(header)
                self._ciphers[client_id] = cipher
                self._cipher_headers[client_id] = header
            self._last_seen[client_id] = time.time()
            return cipher

    def set_cipher(
        self, client_id: str, header: bytes, cipher: StreamCipherSession
    ) -> None:
        with self._lock:
            self._ciphers[client_id] = cipher
            self._cipher_headers[client_id] = header
            self._last_seen[client_id] = time.time()

    def clear(self, client_id: str) -> None:
        with self._lock:
            self._sessions.pop(client_id, None)
            self._ciphers.pop(client_id, None)
            self._cipher_headers.pop(client_id, None)
            self._last_seen.pop(client_id, None)

    def cleanup_expired(self, max_age_seconds: int) -> int:
        now = time.time()
        removed = 0
        with self._lock:
            expired = [
                key for key, ts in self._last_seen.items() if now - ts > max_age_seconds
            ]
            for key in expired:
                self._sessions.pop(key, None)
                self._ciphers.pop(key, None)
                self._cipher_headers.pop(key, None)
                self._last_seen.pop(key, None)
                removed += 1
        return removed


class MojibHttpServer(ThreadingHTTPServer):
    player_manager: PlayerManager
    session_registry: SessionRegistry
    rank_manager: RankManager
    stage_manager: StageManager


class MojibRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args) -> None:
        return

    def _send_binary(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        remote = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[conn] accepted {remote}")
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length)

            if utils.get_global_bool("SERVER_MAINTENANCE", False):
                self._send_binary(ServerStatus.IM)
                return

            if len(body) < HEADER_SIZE:
                self._send_binary(ServerStatus.NG)
                return

            server: MojibHttpServer = self.server  # type: ignore[assignment]
            session_registry = server.session_registry
            player_manager = server.player_manager
            rank_manager = server.rank_manager
            stage_manager = server.stage_manager

            client_id = self.client_address[0]
            inbound_key = body[:HEADER_SIZE]
            session_registry.touch(client_id)
            state = ClientState(player_id=session_registry.get_player(client_id))
            state.logged_in = state.player_id is not None

            if inbound_key == DEFAULT_HEADER_BUFFER:
                cipher = StreamCipherSession()
                cipher.initialize(inbound_key)
            else:
                cipher = session_registry.get_or_create_cipher(client_id, inbound_key)

            try:
                decrypted = cipher.decrypt_packet(body, includes_header=True)
            except Exception as exc:
                print(f"[conn] decrypt error from {remote} -> {exc}")
                self._send_binary(ServerStatus.SC)
                return

            payload = decrypted.payload
            if not payload:
                self._send_binary(ServerStatus.NG)
                return

            command = payload[0]
            data = payload[1:]
            reply_payload = b""
            status = ServerStatus.OK
            next_session_key: bytes | None = None
            reset_session = False

            def _check_auth(cmd_name: str) -> None:
                nonlocal status
                if not state.player_id:
                    raise ValueError(
                        f"{cmd_name} requires player id (REGISTER or LOGIN first)"
                    )
                if not player_manager.has_player(state.player_id):
                    raise ValueError(f"{cmd_name} rejected: unknown secret key")
                restriction = player_manager.get_account_restriction_status(
                    state.player_id
                )
                if restriction in (ServerStatus.DN, ServerStatus.EX):
                    status = restriction
                    raise ValueError(f"{cmd_name} blocked by account restriction")

            try:
                match command:
                    case PacketType.REGISTER:
                        result = player_manager.handle_register(data)
                        state.player_id = result.player_id
                        reply_payload = result.reply_payload
                    case PacketType.LOGIN:
                        result = player_manager.handle_login(data)
                        restriction = player_manager.get_account_restriction_status(
                            result.player_id
                        )
                        if restriction in (ServerStatus.DN, ServerStatus.EX):
                            status = restriction
                            reset_session = True
                            reply_payload = b""
                            raise ValueError("LOGIN blocked by account restriction")
                        state.player_id = result.player_id
                        state.logged_in = True
                        session_registry.bind(client_id, result.player_id)
                        next_session_key = os.urandom(HEADER_SIZE)
                        reply_payload = next_session_key
                    case PacketType.LOGOUT:
                        reset_session = True
                    case PacketType.RETRIEVE:
                        _check_auth("RETRIEVE")
                        reply_payload = player_manager.consume_retrieve_payload(
                            state.player_id
                        )
                    case PacketType.SCORE:
                        _check_auth("SCORE")
                        player_manager.handle_score(state.player_id, data)
                        reply_payload = b"\x00"
                    case PacketType.RANKING:
                        players = player_manager.list_players()
                        reply_payload = rank_manager.build_ranking_payload(players)
                    case PacketType.PUT:
                        _check_auth("PUT")
                        reply_payload = stage_manager.handle_put(
                            data, state.player_id, player_manager
                        )
                    case PacketType.GET:
                        _check_auth("GET")
                        reply_payload = stage_manager.handle_get(data, player_manager)
                    case PacketType.LIST:
                        players = player_manager.list_players()
                        reply_payload = stage_manager.build_list_payload(players)
                    case PacketType.MAILPUT:
                        _check_auth("MAILPUT")
                        reply_payload = stage_manager.handle_mailput(
                            data, state.player_id, player_manager
                        )
                    case PacketType.MAILLIST:
                        _check_auth("MAILLIST")
                        players = player_manager.list_players()
                        reply_payload = stage_manager.build_maillist_payload(
                            players, state.player_id
                        )
                    case PacketType.MAILGET:
                        _check_auth("MAILGET")
                        reply_payload = stage_manager.handle_mailget(
                            data, state.player_id, player_manager
                        )
                    case PacketType.MAILDEL:
                        _check_auth("MAILDEL")
                        reply_payload = stage_manager.handle_maildel(
                            data, state.player_id, player_manager
                        )
                    case PacketType.DLNOTIFY:
                        print("ECHO(DLNOTIFY)")
                        reply_payload = data
                    case _:
                        print(f"[conn] command={command} not implemented")
                        status = ServerStatus.NG
            except ValueError as exc:
                err_str = str(exc)
                print(f"[conn] command={command} handler error -> {exc}")
                if "Recipient not found" in err_str or "Mail not found" in err_str:
                    status = ServerStatus.NF
                elif "Mailbox is full" in err_str:
                    status = ServerStatus.MO
                else:
                    if status == ServerStatus.OK:
                        status = ServerStatus.NG
            except Exception as exc:
                print(f"[conn] command={command} handler error -> {exc}")
                if status == ServerStatus.OK:
                    status = ServerStatus.NG

            if status == ServerStatus.OK:
                encrypted_reply = cipher.encrypt_payload(
                    reply_payload, include_header=False
                )
                response_body = ServerStatus.OK + encrypted_reply
            else:
                response_body = status

            self._send_binary(response_body)

            if status == ServerStatus.OK and next_session_key is not None:
                # get_or_create_cipher() will reinitialize when header changes.
                pass
            if status == ServerStatus.OK and reset_session:
                session_registry.clear(client_id)
        finally:
            print(f"[conn] closed {remote}")


def run_server(host: str = LISTEN_HOST, port: int = LISTEN_PORT) -> None:
    player_manager = PlayerManager()
    session_registry = SessionRegistry()
    rank_manager = RankManager()
    stage_manager = StageManager()
    server = MojibHttpServer((host, port), MojibRequestHandler)
    server.player_manager = player_manager
    server.session_registry = session_registry
    server.rank_manager = rank_manager
    server.stage_manager = stage_manager

    def _session_reaper() -> None:
        while not _STOP_EVENT.is_set():
            removed = session_registry.cleanup_expired(SESSION_TIMEOUT_SECONDS)
            if removed:
                print(f"[session] expired {removed} stale session(s)")
            _STOP_EVENT.wait(30.0)

    def _handle_signal(signum, frame) -> None:
        print(f"[main] signal {signum} received, shutting down")
        _STOP_EVENT.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    threading.Thread(target=_session_reaper, daemon=True).start()

    print(f"[main] listening on {host}:{port}")
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        print("[main] server stopped")


if __name__ == "__main__":
    run_server()
