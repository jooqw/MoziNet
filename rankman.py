from __future__ import annotations

from typing import Any

import utils


class RankManager:
    def build_ranking_payload(self, players: list[dict[str, Any]]) -> bytes:
        sorted_players = sorted(
            players,
            key=lambda p: int(p.get("hesori_toku", 0) or 0),
            reverse=True,
        )

        out = bytearray()
        out.extend(len(sorted_players).to_bytes(4, "little"))

        for player in sorted_players:
            email = utils.encode_euc_jp_fixed(str(player.get("email_hiragana", "")), 16)

            name = utils.encode_euc_jp_fixed(str(player.get("player_name", "")), 16)

            dan = int(player.get("dan", 0) or 0) & 0xFFFF

            description = utils.encode_profile_qa_160(player.get("profile_qa"))

            toku = int(player.get("hesori_toku", 0) or 0) & 0xFFFFFFFF

            out.extend(email)
            out.extend(name)
            out.extend(dan.to_bytes(2, "little"))
            out.extend(description)
            out.extend(toku.to_bytes(4, "little"))

        return bytes(out)
