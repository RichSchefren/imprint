from __future__ import annotations

import inspect

import imprint.store.service as service


def test_product_never_unlinks_sqlite_sidecars() -> None:
    source = inspect.getsource(service)
    for suffix in ("-wal", "-shm", "-journal"):
        assert f'{suffix}").unlink' not in source
        assert f"{suffix}').unlink" not in source

