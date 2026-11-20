"""Encryption at rest for each person's private data: message text and Gmail tokens.

Each person has their own key (users/<id>/key.sealed), sealed with a master key that is NOT stored with
the data: GUARDIAN_MASTER_KEY in the environment (in production, a secrets manager). "Delete my data"
removes the sealed key first, so any copy of the encrypted files left on a disk or in a backup can no
longer be read (crypto-shredding).

For local development only, if GUARDIAN_MASTER_KEY is not set, a master key is created in
users/master.key (owner-only) and a warning is printed. Never use that in production.
"""
import json
import os
import sys

from cryptography.fernet import Fernet, InvalidToken

_master = None


class VaultError(Exception):
    pass


def _users_dir():
    import core
    return core.USERS


def master():
    global _master
    if _master is not None:
        return _master
    key = os.environ.get("GUARDIAN_MASTER_KEY", "").strip()
    if not key:
        path = os.path.join(_users_dir(), "master.key")
        if os.path.exists(path):
            with open(path) as f:
                key = f.read().strip()
        else:
            os.makedirs(_users_dir(), exist_ok=True)
            key = Fernet.generate_key().decode()
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(key)
            sys.stderr.write("WARNING: no GUARDIAN_MASTER_KEY set; created a development master key in %s\n" % path)
    try:
        _master = Fernet(key.encode())
    except (ValueError, TypeError):
        raise VaultError("GUARDIAN_MASTER_KEY is not a valid key")
    return _master


def _sealed_path(user_dir):
    return os.path.join(user_dir, "key.sealed")


def _user_key(user_dir, create=False):
    path = _sealed_path(user_dir)
    if not os.path.exists(path):
        if not create:
            raise VaultError("this person's key is gone")
        key = Fernet.generate_key()
        with open(path, "wb") as f:
            f.write(master().encrypt(key))
        os.chmod(path, 0o600)
        return Fernet(key)
    with open(path, "rb") as f:
        try:
            return Fernet(master().decrypt(f.read()))
        except InvalidToken:
            raise VaultError("this person's key cannot be unsealed with this master key")


def create_key(user_dir):
    _user_key(user_dir, create=True)


def write_json(user_dir, name, obj):
    """Encrypt and write. `name` is a file name inside the person's folder."""
    token = _user_key(user_dir).encrypt(json.dumps(obj).encode())
    path = os.path.join(user_dir, name)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(token)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def read_json(user_dir, name, default=None):
    path = os.path.join(user_dir, name)
    if not os.path.exists(path):
        return default
    with open(path, "rb") as f:
        try:
            return json.loads(_user_key(user_dir).decrypt(f.read()))
        except InvalidToken:
            raise VaultError("%s could not be decrypted" % name)


def shred(user_dir):
    """Destroy the person's key: everything encrypted with it becomes unreadable."""
    path = _sealed_path(user_dir)
    if os.path.exists(path):
        with open(path, "r+b") as f:
            f.write(os.urandom(os.path.getsize(path)))
        os.remove(path)
