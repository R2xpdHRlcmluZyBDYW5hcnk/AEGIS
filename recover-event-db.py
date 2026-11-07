#!/usr/bin/env python3
"""Recover a sealed event-database snapshot into a new, isolated directory.

Never activates a candidate or opens the original files with SQLite. A successful
integrity check proves structural validity, not completeness of recovered data.
"""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import struct
import subprocess
import tempfile


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(8 << 20), b''):
            value.update(block)
    return value.hexdigest()


def read_snapshot(snapshot):
    snapshot = Path(snapshot).resolve()
    manifest = json.loads((snapshot / 'snapshot.json').read_text(encoding='utf-8'))
    name = Path(manifest['database_path']).name
    entries = manifest['files']
    allowed = {name, name + '-wal', name + '-shm'}
    if name not in entries or not set(entries) <= allowed:
        raise ValueError('Snapshot must contain only the database and its WAL/SHM group')
    for item, entry in entries.items():
        source = snapshot / 'original' / item
        if source.is_symlink() or source.resolve().parent != snapshot / 'original':
            raise ValueError('Snapshot file escapes its original directory')
        if source.stat().st_size != entry['bytes'] or digest(source) != entry['sha256']:
            raise ValueError('Snapshot checksum mismatch: ' + item)
    return snapshot, manifest, name


def normalize_values(statement):
    """Encode damaged TEXT literals as byte-preserving SQL, leaving BLOBs intact."""
    if not re.match(rb'\s*INSERT\b', statement, re.I):
        return statement
    match = re.search(rb'\bVALUES\s*\(', statement, re.I)
    if not match:
        return statement
    body = statement[match.end():].rstrip(b'\r\n')
    if not re.search(rb'[\x00-\x1f]', body):
        try:
            body.decode('utf-8')
            return statement
        except UnicodeDecodeError:
            pass
    result = bytearray(statement[:match.end()])
    position = match.end()
    while position < len(statement):
        if statement[position] != 39:
            result.append(statement[position])
            position += 1
            continue
        start = position
        position += 1
        value = bytearray()
        while position < len(statement):
            byte = statement[position]
            position += 1
            if byte == 39:
                if position < len(statement) and statement[position] == 39:
                    value.append(39)
                    position += 1
                    continue
                break
            value.append(byte)
        else:
            raise ValueError('Unterminated recovered SQL literal')
        is_blob = start > 0 and statement[start - 1:start].upper() == b'X'
        unsafe = any(byte < 32 for byte in value)
        try:
            value.decode('utf-8')
        except UnicodeDecodeError:
            unsafe = True
        if unsafe and not is_blob:
            result.extend(b"CAST(X'" + value.hex().encode('ascii') + b"' AS TEXT)")
        else:
            result.extend(statement[start:position])
    return bytes(result)


def relay_recovery(source, target):
    statement = bytearray()
    limit = 64 << 20
    while True:
        line = source.readline(limit - len(statement) + 1)
        if not line:
            break
        if len(statement) + len(line) > limit:
            raise ValueError('Recovered statement exceeds the private-buffer limit')
        if not statement and line.startswith(b'.'):
            target.write(line)
            continue
        statement.extend(line)
        # complete_statement checks syntax boundaries; latin1 keeps every byte.
        boundary_text = statement.replace(b'\0', b' ').decode('latin1')
        if sqlite3.complete_statement(boundary_text):
            target.write(normalize_values(bytes(statement)))
            statement.clear()
    if statement.strip():
        raise ValueError('Recovery output ended inside an SQL statement')


def import_recovery(cli, source, target, logs):
    """Keep SQL private, stream it, and reject either half of a failed pipeline."""
    with (logs / 'recover.log').open('wb') as errors, (logs / 'import.log').open('wb') as output:
        producer = subprocess.Popen(
            [str(cli), '-readonly', str(source), '.recover --ignore-freelist'],
            stdout=subprocess.PIPE, stderr=errors)
        try:
            consumer = subprocess.Popen(
                [str(cli), '-batch', '-bail', '-cmd', '.dbconfig defensive off',
                 str(target)], stdin=subprocess.PIPE, stdout=output, stderr=output)
        except BaseException:
            producer.stdout.close()
            producer.terminate()
            producer.wait()
            raise
        try:
            consumer.stdin.write(b'PRAGMA cache_size=-65536; PRAGMA temp_store=FILE; PRAGMA synchronous=FULL;\n')
            # Relay complete statements so damaged TEXT can be encoded safely
            # without materializing the entire recovery SQL stream.
            relay_recovery(producer.stdout, consumer.stdin)
            consumer.stdin.close()
            producer.stdout.close()
            import_code = consumer.wait()
            recover_code = producer.wait()
        except BaseException:
            for process in (producer, consumer):
                if process.poll() is None:
                    process.terminate()
            producer.wait()
            consumer.wait()
            raise
    if recover_code or import_code:
        raise RuntimeError('Recovery/import failed (%s/%s); inspect private logs' %
                           (recover_code, import_code))


def probe_cli(cli, directory):
    # AUTOINCREMENT exercises sqlite_sequence, which a simple table misses.
    with tempfile.TemporaryDirectory(prefix='cli-probe-', dir=directory) as folder:
        folder = Path(folder)
        source, target = folder / 'input.db', folder / 'output.db'
        with closing(sqlite3.connect(source)) as conn:
            conn.execute('CREATE TABLE probe(id INTEGER PRIMARY KEY AUTOINCREMENT,value TEXT)')
            conn.execute("INSERT INTO probe(value) VALUES('verified')")
            conn.commit()
        import_recovery(cli, source, target, folder)
        with closing(sqlite3.connect(target)) as conn:
            if conn.execute('SELECT * FROM probe').fetchall() != [(1, 'verified')]:
                raise RuntimeError('Recovery tool self-test failed')


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def table_fingerprints(path):
    """Read all table values directly; never trust secondary indexes for salvage."""
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)) as conn:
        conn.execute('PRAGMA query_only=ON')
        conn.execute('PRAGMA cache_size=-65536')
        tables = [row[0] for row in conn.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")]
        conn.text_factory = bytes
        result = {}
        for name in tables:
            hashed, count = hashlib.sha256(), 0
            for row in conn.execute('SELECT * FROM ' + quote(name) + ' NOT INDEXED ORDER BY rowid'):
                hashed.update(repr(row).encode('utf-8') + b'\n')
                count += 1
            result[name] = dict(rows=count, sha256=hashed.hexdigest())
        return result


def rebuild_indexes(source, candidate):
    """Copy readable table values internally, then rebuild every secondary index."""
    source, candidate = Path(source).resolve(), Path(candidate).resolve()
    if candidate.exists() or candidate == source:
        raise FileExistsError('Index repair requires a new candidate')
    before = table_fingerprints(source)  # Any unreadable table aborts before copying.
    with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as old, \
            closing(sqlite3.connect(candidate, uri=True)) as new:
        new.execute('PRAGMA cache_size=-65536')
        new.execute('ATTACH DATABASE ? AS original', (source.as_uri() + '?mode=ro',))
        definitions = old.execute("SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY rowid").fetchall()
        for kind, name, sql in definitions:
            if kind == 'table' and name != 'sqlite_sequence':
                new.execute(sql)
                columns = [row[1] for row in old.execute('PRAGMA table_info(' + quote(name) + ')')]
                selected = ','.join(['rowid'] + [quote(column) for column in columns])
                # Keep empty BLOBs, embedded NULs, invalid UTF-8 TEXT and hidden
                # row IDs inside SQLite; shell text/binding paths can alter them.
                new.execute('INSERT INTO main.' + quote(name) + '(' + selected + ') SELECT ' + selected +
                            ' FROM original.' + quote(name) + ' NOT INDEXED ORDER BY rowid')
        if 'sqlite_sequence' in before:
            new.execute('CREATE TABLE "_recovery_sequence_probe"(id INTEGER PRIMARY KEY AUTOINCREMENT)')
            new.execute('DROP TABLE "_recovery_sequence_probe"')
            new.execute('DELETE FROM sqlite_sequence')
            new.execute('INSERT INTO main.sqlite_sequence SELECT * FROM original.sqlite_sequence')
        for kind, name, sql in definitions:
            if kind != 'table':
                new.execute(sql)
        for setting in ('application_id', 'user_version'):
            new.execute('PRAGMA ' + setting + '=' + str(old.execute('PRAGMA ' + setting).fetchone()[0]))
        new.commit()
        schema = "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"
        if old.execute(schema).fetchall() != new.execute(schema).fetchall():
            raise RuntimeError('Rebuilt schema differs from the source')
    if table_fingerprints(candidate) != before:
        raise RuntimeError('Rebuilt table values differ from the source')
    report = validate(candidate)
    report['source_table_fingerprints'] = before
    report['all_table_values_preserved'] = True
    return report


def varint(data, position):
    value = 0
    for index in range(9):
        if position >= len(data):
            raise ValueError('Truncated SQLite varint')
        byte = data[position]
        position += 1
        if index == 8:
            return (value << 8) | byte, position
        value = (value << 7) | (byte & 127)
        if byte < 128:
            return value, position
    raise ValueError('Invalid SQLite varint')


def index_key_candidates(page, wanted):
    """Read small UTF-8 (64-hex-key,rowid) index cells; candidates are untrusted."""
    if len(page) < 12 or page[0] not in (2, 10):
        return
    header = 12 if page[0] == 2 else 8
    cells = int.from_bytes(page[3:5], 'big')
    if header + cells * 2 > len(page):
        return
    sizes = {1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 8: 0, 9: 0}
    for cell in range(cells):
        pointer = header + cell * 2
        offset = int.from_bytes(page[pointer:pointer + 2], 'big')
        if offset < header + cells * 2:
            continue
        try:
            length, start = varint(page, offset + (4 if page[0] == 2 else 0))
            if not 67 <= length <= 80 or start + length > len(page):
                continue
            payload = page[start:start + length]
            header_size, position = varint(payload, 0)
            first, position = varint(payload, position)
            second, position = varint(payload, position)
            if position != header_size or first != 141 or second not in sizes:
                continue
            size = sizes[second]
            if header_size + 64 + size != len(payload):
                continue
            key = payload[header_size:header_size + 64]
            if not re.fullmatch(b'[0-9a-f]{64}', key):
                continue
            identity = second - 8 if second in (8, 9) else int.from_bytes(payload[-size:], 'big', signed=True)
            if identity in wanted:
                yield identity, key.decode('ascii')
        except (ValueError, IndexError):
            continue


def table_row_candidates(page, wanted, reserved=0):
    """Read inline table leaf cells; overflow records require separate recovery."""
    if len(page) < 8 or page[0] != 13:
        return
    cells = int.from_bytes(page[3:5], 'big')
    if 8 + cells * 2 > len(page):
        return
    for cell in range(cells):
        offset = int.from_bytes(page[8 + cell * 2:10 + cell * 2], 'big')
        if offset < 8 + cells * 2:
            continue
        try:
            length, position = varint(page, offset)
            identity, position = varint(page, position)
            if identity not in wanted or length > len(page) - reserved - 35:
                continue
            if position + length > len(page) - reserved:
                continue
            payload = page[position:position + length]
            header_size, cursor = varint(payload, 0)
            serials = []
            while cursor < header_size:
                serial, cursor = varint(payload, cursor)
                serials.append(serial)
            if cursor != header_size:
                continue
            values, cursor = [], header_size
            sizes = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}
            for serial in serials:
                if serial in (10, 11):
                    raise ValueError('Reserved serial type')
                size = sizes[serial] if serial < 10 else (serial - 12) // 2
                if cursor + size > len(payload):
                    raise ValueError('Truncated record')
                data = payload[cursor:cursor + size]
                cursor += size
                if serial == 0:
                    value = None
                elif serial in (8, 9):
                    value = serial - 8
                elif serial == 7:
                    value = struct.unpack('>d', data)[0]
                elif serial < 7:
                    value = int.from_bytes(data, 'big', signed=True)
                elif serial % 2:
                    value = data.decode('utf-8')
                else:
                    value = data
                values.append(value)
            if cursor == len(payload):
                yield identity, values
        except (ValueError, IndexError, UnicodeDecodeError, struct.error):
            continue


def wal_checksum(data, checksum, endian):
    first, second = checksum
    for left, right in struct.iter_unpack(endian + 'II', data):
        first = (first + left + second) & 0xffffffff
        second = (second + right + first) & 0xffffffff
    return first, second


def committed_wal_rows(path, wanted, stats, reserved=0):
    """Yield historical inline rows only from checksum-valid committed frames."""
    stats.update(valid_frames=0, commits=0, stopped_reason='end_of_file')
    with Path(path).open('rb') as handle:
        header = handle.read(32)
        if len(header) != 32:
            raise ValueError('Incomplete WAL header')
        magic, version, page_size = struct.unpack('>III', header[:12])
        if magic not in (0x377f0682, 0x377f0683) or version != 3007000:
            raise ValueError('Unsupported WAL header')
        if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
            raise ValueError('Invalid WAL page size')
        endian = '<' if magic == 0x377f0682 else '>'
        checksum = wal_checksum(header[:24], (0, 0), endian)
        if checksum != struct.unpack('>II', header[24:32]):
            raise ValueError('Invalid WAL header checksum')
        pending = {}
        while True:
            frame = handle.read(24 + page_size)
            if not frame:
                break
            if len(frame) != 24 + page_size:
                stats['stopped_reason'] = 'incomplete_frame'
                break
            if frame[8:16] != header[16:24]:
                stats['stopped_reason'] = 'salt_mismatch'
                break
            calculated = wal_checksum(frame[:8], checksum, endian)
            calculated = wal_checksum(frame[24:], calculated, endian)
            if calculated != struct.unpack('>II', frame[16:24]):
                stats['stopped_reason'] = 'checksum_mismatch'
                break
            checksum = calculated
            stats['valid_frames'] += 1
            page_number, database_pages = struct.unpack('>II', frame[:8])
            pending.pop(page_number, None)
            rows = list(table_row_candidates(frame[24:], wanted, reserved))
            if rows:
                pending[page_number] = rows
            if database_pages:
                stats['commits'] += 1
                for page, records in pending.items():
                    if page <= database_pages:
                        for identity, values in records:
                            yield page, identity, values
                pending.clear()
        # Any final transaction without a commit marker is deliberately ignored.


def forensic_wal_rows(path, wanted, stats, start_frame=0, reserved=0):
    """Extract historical candidates after WAL resets, never current DB state.

    Old generation headers are unavailable. A stored checksum seeds each segment;
    only subsequent checksum-consistent complete transactions are examined. Every
    resulting row still needs independent current ID/key/timestamp validation.
    """
    stats.update(segments=0, consistent_frames=0, checksum_gaps=0, complete_transactions=0)
    with Path(path).open('rb') as handle:
        header = handle.read(32)
        if len(header) != 32 or int.from_bytes(header[:4], 'big') not in (0x377f0682, 0x377f0683):
            raise ValueError('Invalid WAL header')
        page_size = int.from_bytes(header[8:12], 'big')
        if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
            raise ValueError('Invalid WAL page size')
        endian = '<' if int.from_bytes(header[:4], 'big') == 0x377f0682 else '>'
        handle.seek(32 + start_frame * (24 + page_size))
        salt, checksum, boundary, pending = None, None, False, {}
        while True:
            frame = handle.read(24 + page_size)
            if len(frame) != 24 + page_size:
                break
            page_number, database_pages = struct.unpack('>II', frame[:8])
            stored = struct.unpack('>II', frame[16:24])
            if frame[8:16] != salt:
                stats['segments'] += 1
                salt, checksum, boundary, pending = frame[8:16], stored, bool(database_pages), {}
                continue
            calculated = wal_checksum(frame[:8], checksum, endian)
            calculated = wal_checksum(frame[24:], calculated, endian)
            checksum = stored
            if calculated != stored:
                stats['checksum_gaps'] += 1
                boundary, pending = bool(database_pages), {}
                continue
            stats['consistent_frames'] += 1
            if boundary:
                pending.pop(page_number, None)
                rows = list(table_row_candidates(frame[24:], wanted, reserved))
                if rows:
                    pending[page_number] = rows
            if database_pages:
                if boundary:
                    stats['complete_transactions'] += 1
                    for page, records in pending.items():
                        if page <= database_pages:
                            for identity, values in records:
                                yield page, identity, values
                boundary, pending = True, {}


def scan_index_keys(cli, source, wanted, destination):
    """Extract candidates on a working copy; never treat them as restored rows."""
    destination.execute('CREATE TABLE IF NOT EXISTS key_candidates('
                        'id INTEGER,event_key TEXT,PRIMARY KEY(id,event_key))')
    sql = ("SELECT pgno,hex(data) FROM sqlite_dbpage WHERE substr(data,1,1) IN (x'0A',x'02')"
           " AND instr(data,x'04810D')>0;")
    process = subprocess.Popen([str(cli), '-readonly', '-separator', '|', str(source), sql],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pages = 0
    try:
        for line in iter(process.stdout.readline, b''):
            _, encoded = line.strip().split(b'|', 1)
            page = bytes.fromhex(encoded.decode('ascii'))
            destination.executemany('INSERT OR IGNORE INTO key_candidates VALUES(?,?)',
                                    index_key_candidates(page, wanted))
            pages += 1
        error = process.stderr.read()
        if process.wait():
            raise RuntimeError('Read-only page scan failed: ' + error.decode(errors='replace')[:200])
        destination.commit()
        return {'index_pages_examined': pages,
                'candidate_identities': destination.execute('SELECT COUNT(DISTINCT id) FROM key_candidates').fetchone()[0]}
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait()
        process.stdout.close()
        process.stderr.close()


def find_eve_cursor(backend, eve, event_key, stored_timestamp):
    """Locate an original event exactly, rather than guessing a timestamp cutoff."""
    pattern = re.compile(rb'"timestamp"\s*:\s*"([^"]+)"')
    offset = 0
    with Path(eve).open('rb') as handle:
        for line in handle:
            offset += len(line)
            if not line.endswith(b'\n'):
                break
            raw = line[:-1]
            match = pattern.search(raw[:160])
            if not match:
                continue
            timestamp = backend.parse_ts(match.group(1).decode('ascii'))
            milliseconds = timestamp * 1000
            if milliseconds != stored_timestamp and int(milliseconds) != stored_timestamp:
                continue
            identity = hashlib.sha256((repr(timestamp) + '\n' + raw.decode('utf-8', 'replace')).encode()).hexdigest()
            if identity == event_key:
                return offset
    raise ValueError('Last stored event was not found in the retained EVE prefix')


def replay_eve(backend, connection, eve, offset, minimum_id):
    """Replay after an exact file cursor on an offline candidate, without retention."""
    # Bulk inserts touch many indexes. A bounded page cache avoids repeatedly
    # spilling the same pages to slow storage during a single transaction.
    connection.execute('PRAGMA cache_size=-65536')
    columns = [name for name, _ in backend.EventDB.COLUMNS]
    converter = backend.EventDB.__new__(backend.EventDB)
    insert = ('INSERT INTO events(id,' + ','.join(quote(name) for name in columns) + ')'
              ' VALUES(' + ','.join('?' for _ in range(len(columns) + 1)) + ')'
              ' ON CONFLICT(event_key) WHERE event_key IS NOT NULL DO NOTHING')
    identity = max(minimum_id, connection.execute('SELECT COALESCE(MAX(id),0) FROM events').fetchone()[0])
    before = connection.total_changes
    records, completed_offset, batch = 0, offset, []
    with connection, Path(eve).open('rb') as handle:
        if offset:
            handle.seek(offset - 1)
            if handle.read(1) != b'\n':
                raise ValueError('EVE cursor is not at a line boundary')
        handle.seek(offset)
        for line in handle:
            if not line.endswith(b'\n'):
                break
            completed_offset += len(line)
            raw = line[:-1]
            parsed = backend.EventStore._parse(raw)
            if not parsed:
                continue
            record, original_line = parsed
            identity += 1
            records += 1
            batch.append([identity] + converter._values(record, original_line.decode('utf-8', 'replace')))
            if len(batch) >= 1000:
                connection.executemany(insert, batch)
                batch.clear()
        if batch:
            connection.executemany(insert, batch)
    return {'parsed_records': records, 'inserted': connection.total_changes - before,
            'completed_offset': completed_offset, 'last_allocated_id': identity}


def compare_readable_rows(conn, source, issues=None):
    """Compare every readable source field; isolate corrupt ranges by row ID."""
    source_uri = Path(source).resolve().as_uri() + '?mode=ro'
    report = dict(matched=0, mismatched=0, unreadable=0, absent_from_table=0)
    if issues is not None:
        issues.execute('CREATE TABLE IF NOT EXISTS issues(id INTEGER PRIMARY KEY,kind TEXT NOT NULL)')
    with closing(sqlite3.connect(source_uri, uri=True)) as original:
        original.execute('PRAGMA query_only=ON')
        original.execute('PRAGMA cache_size=-65536')
        columns = [row[1] for row in original.execute('PRAGMA table_info(events)')]
        fields = ','.join(quote(column) for column in columns)
        id_position = columns.index('id')
        sql = 'SELECT ' + fields + ' FROM events WHERE id>=? AND id<=? ORDER BY id'
        original.text_factory = bytes
        previous_factory = conn.text_factory
        conn.text_factory = bytes

        def compare(ids):
            bounds = ids[0], ids[-1]
            try:
                old_rows = original.execute(sql, bounds).fetchall()
            except sqlite3.DatabaseError as exc:
                if getattr(exc, 'sqlite_errorcode', 0) & 255 != sqlite3.SQLITE_CORRUPT:
                    raise
                if len(ids) > 1:
                    middle = len(ids) // 2
                    compare(ids[:middle])
                    compare(ids[middle:])
                else:
                    report['unreadable'] += 1
                    if issues is not None:
                        issues.execute('INSERT OR REPLACE INTO issues VALUES(?,?)', (ids[0], 'unreadable'))
                return
            recovered = {row[id_position]: row for row in conn.execute(sql, bounds)}
            found = set()
            for row in old_rows:
                identity = row[id_position]
                found.add(identity)
                key = 'matched' if recovered.get(identity) == row else 'mismatched'
                report[key] += 1
                if key == 'mismatched' and issues is not None:
                    issues.execute('INSERT OR REPLACE INTO issues VALUES(?,?)', (identity, 'mismatched'))
            absent = set(ids) - found
            report['absent_from_table'] += len(absent)
            if issues is not None:
                issues.executemany('INSERT OR REPLACE INTO issues VALUES(?,?)',
                                   ((identity, 'absent_from_table') for identity in absent))

        try:
            cursor = conn.execute('SELECT id FROM reference.expected ORDER BY id')
            while True:
                rows = cursor.fetchmany(2000)
                if not rows:
                    break
                compare([row[0] for row in rows])
        finally:
            conn.text_factory = previous_factory
    if issues is not None:
        issues.commit()
    return report


def validate(candidate, reference=None, source=None):
    uri = Path(candidate).resolve().as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        conn.execute('PRAGMA query_only=ON')
        conn.execute('PRAGMA cache_size=-65536')
        checks = [row[0] for row in conn.execute('PRAGMA integrity_check')]
        if checks != ['ok']:
            raise RuntimeError('Recovered database failed integrity_check')
        tables = [row[0] for row in conn.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        counts = {name: conn.execute('SELECT COUNT(*) FROM ' + quote(name)).fetchone()[0]
                  for name in tables}
        foreign_keys = sum(1 for _ in conn.execute('PRAGMA foreign_key_check'))
        report = {'integrity_check': checks, 'table_counts': counts,
                  'foreign_key_violations': foreign_keys,
                  'activation_performed': False, 'completeness_proven': False}
        if reference:
            # Reference format: expected(id INTEGER PRIMARY KEY,ts NUMERIC).
            reference_uri = Path(reference).resolve().as_uri() + '?mode=ro'
            conn.execute('ATTACH DATABASE ? AS reference', (reference_uri,))
            report['identity_comparison'] = {
                'expected': conn.execute('SELECT COUNT(*) FROM reference.expected').fetchone()[0],
                'missing': conn.execute('SELECT COUNT(*) FROM reference.expected r LEFT JOIN events e'
                                       ' ON e.id=r.id WHERE e.id IS NULL').fetchone()[0],
                'unexpected': conn.execute('SELECT COUNT(*) FROM events e LEFT JOIN reference.expected r'
                                          ' ON e.id=r.id WHERE r.id IS NULL').fetchone()[0],
                'timestamp_mismatches': conn.execute('SELECT COUNT(*) FROM events e JOIN reference.expected r'
                                                   ' ON e.id=r.id WHERE e.ts IS NOT r.ts').fetchone()[0],
            }
            if source:
                report['source_row_comparison'] = compare_readable_rows(conn, source)
        return report


def recover(snapshot, output, cli, reference=None, indexes_only=False):
    snapshot, manifest, name = read_snapshot(snapshot)
    output = Path(output).resolve()
    if output == snapshot or output.is_relative_to(snapshot / 'original') or snapshot.is_relative_to(output):
        raise ValueError('Recovery output must be separate from sealed originals')
    output.mkdir(mode=0o700)  # Existing candidates must never be overwritten.
    if not indexes_only:
        cli = Path(cli).resolve(strict=True)
        probe_cli(cli, output)
    work = output / 'input'
    work.mkdir(mode=0o700)
    # SHM is transient state. SQLite reconstructs it for this separate copy.
    for item in (name, name + '-wal'):
        if item in manifest['files']:
            target = work / item
            shutil.copyfile(snapshot / 'original' / item, target)
            if digest(target) != manifest['files'][item]['sha256']:
                raise RuntimeError('Working copy checksum mismatch')
    candidate = output / 'candidate.db'
    if indexes_only:
        report = rebuild_indexes(work / name, candidate)
    else:
        import_recovery(cli, work / name, candidate, output)
        report = validate(candidate, reference, work / name)
    (output / 'validation.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sqlite-cli', type=Path, help='Required for page salvage; unused with --rebuild-indexes')
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--rebuild-indexes', action='store_true',
                        help='Require every table to be readable and preserve all schema and table values')
    args = parser.parse_args()
    if not args.rebuild_indexes and args.sqlite_cli is None:
        parser.error('--sqlite-cli is required unless --rebuild-indexes is selected')
    print(json.dumps(recover(args.snapshot, args.output, args.sqlite_cli, args.reference,
                             args.rebuild_indexes), indent=2))


if __name__ == '__main__':
    main()
