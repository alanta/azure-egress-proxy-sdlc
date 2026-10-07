#!/usr/bin/python3
"""Run a command with SDLC_GITHUB_TOKEN set from the GNOME keyring.

The scan needs a read-only GitHub token. In CI it comes from the repository secret; locally
it lives in the Login keyring (add it with Seahorse), so it is never written to a file or
printed. If SDLC_GITHUB_TOKEN is already set, the command runs unchanged.

Usage: scripts/with-github-token.py <command> [args...]
       SDLC_GITHUB_TOKEN_LABEL overrides the keyring item name.

Runs with the system Python, which has the libsecret bindings (python3-gi).
"""

import os
import sys

DEFAULT_LABEL = "azure-egress-proxy-sdlc read-only token"


def token_from_keyring(label: str) -> str:
    import gi

    gi.require_version("Secret", "1")
    from gi.repository import Secret

    service = Secret.Service.get_sync(Secret.ServiceFlags.LOAD_COLLECTIONS, None)
    matches = []
    for collection in service.get_collections():
        collection.load_items_sync(None)
        matches += [item for item in collection.get_items() if item.get_label() == label]
    if len(matches) != 1:
        found = "no keyring item" if not matches else f"{len(matches)} keyring items"
        sys.exit(f"error: {found} labelled {label!r}; add exactly one with Seahorse.")
    item = matches[0]
    if item.get_locked():
        service.unlock_sync([item], None)
    item.load_secret_sync(None)
    secret = item.get_secret()
    if secret is None or not secret.get_text():
        sys.exit(f"error: keyring item {label!r} is empty.")
    return secret.get_text().strip()


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    env = dict(os.environ)
    if not env.get("SDLC_GITHUB_TOKEN"):
        env["SDLC_GITHUB_TOKEN"] = token_from_keyring(
            env.get("SDLC_GITHUB_TOKEN_LABEL", DEFAULT_LABEL)
        )
    os.execvpe(sys.argv[1], sys.argv[1:], env)  # noqa: S606 - runs the caller's command


if __name__ == "__main__":
    main()
