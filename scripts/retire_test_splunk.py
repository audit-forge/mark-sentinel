#!/usr/bin/env python3
"""Explicitly retire only the orphaned splunk-test integration; retain private evidence."""
import argparse
import json
import os
from pathlib import Path
import stat
import tempfile
from urllib.parse import urlsplit


def retire(config: Path, backup: Path) -> bool:
    info = config.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Expected regular configuration file')
    original = config.read_bytes()
    document = json.loads(original)
    splunk = document.get('splunk')
    if splunk is None:
        return False
    if not isinstance(splunk, dict) or urlsplit(splunk.get('hec_url', '')).hostname != 'splunk-test':
        raise ValueError('Not the approved orphaned test integration; no changes made')
    if not backup.parent.is_dir() or stat.S_IMODE(backup.parent.stat().st_mode) & 0o077:
        raise ValueError('Backup parent must already be private')
    with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    del document['splunk']
    fd, temporary = tempfile.mkstemp(prefix='.retire-splunk-', dir=config.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(document, stream, indent=2)
            stream.write('\n')
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.fchmod(stream.fileno(), 0o600)
            stream.flush()
            os.fsync(stream.fileno())
        if config.read_bytes() != original:
            raise ValueError('Configuration changed concurrently; retry after review')
        os.replace(temporary, config)
        directory = os.open(config.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--backup', type=Path, required=True)
    args = parser.parse_args()
    changed = retire(args.config, args.backup)
    print('Orphaned test integration retired' if changed else 'Already retired; no changes')


if __name__ == '__main__':
    main()
