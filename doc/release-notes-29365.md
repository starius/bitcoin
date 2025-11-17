P2P and network changes
-----------------------

- Signet challenge parsing now supports `OP_RETURN` wrapped parameters (e.g.
  block spacing). The encoding format is documented in contrib/signet/README.md
  and the `contrib/signet/miner` tool gained a `makechallenge` helper plus a
  `generate --challenge` override. Minimal push opcodes inside wrapped
  challenges are now accepted, matching Core's parser (#29365).
