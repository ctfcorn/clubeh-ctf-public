# example-dynamic

**Category:** misc  **Points:** 100  **Type:** dynamic (one instance per player)

## Description (auto-registered in CTFd from challenge.yml)
A door with a password. Press Start to get your own copy; the flag is unique
to your instance. Connect with nc.

## Intended solution
The password is hard-coded in the (shipped) source; send it. Trivial on
purpose — this challenge exists to prove the per-player pipeline works.

## Notes for authors
Per-instance flags mean a flag copied from a friend is simply wrong for you.
`server.py` shows the mandatory pattern: read `FLAG` once, `pop` it from the
environment, never write it to disk.
