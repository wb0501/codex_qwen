#!/usr/bin/env python3
"""HumanEval through Codex CLI, with filesystem isolation and traffic evidence.

Specify --range, --limit, or explicit --all; no implicit batch run. --range is 1-based,
inclusive. HTTP/WS use the configured provider URL; they do not imply TLS.
The TLS inspection proxy is enabled by default, including for auxiliary HTTPS.
No host Codex settings or authentication files are modified.
The host auth.json is NOT copied by default; opt in with --with-auth-json.
Code Mode helper is mounted to allow tool execution.
Each task retains the original files plus optional server_traffic.pcapng and server_timeline.jsonl: codex_output.json, raw_traffic.pcapng,
task_prompt.txt, codex_timeline.jsonl, result.json. TLS keys are embedded in
the PCAPNG; metadata and diagnostics are stored in result.json.
"""
from __future__ import annotations

import argparse
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import subprocess
import struct
import sys
import tempfile
import time
import tomllib
import traceback
import shlex
import errno
import zipfile
from datetime import datetime, timezone
from contextlib import contextmanager
from spark_measurement import SparkSession
from urllib.parse import parse_qsl, urlparse

ROOT = Path(__file__).resolve().parent
_interrupt_requested = False


def plugin_resource_findings(config_home):
    """Document the native paths, independently of installed plugin state."""
    snapshot = config_home / '.tmp/plugins'
    revision = config_home / '.tmp/plugins.sha'
    return {
        'reuse_enabled': True,
        'status': 'verified_resources_only; warm_network_validation_pending',
        'native_resource_directory': '$CODEX_HOME/.tmp/plugins',
        'native_revision_file': '$CODEX_HOME/.tmp/plugins.sha',
        'native_sync_lock': '$CODEX_HOME/.tmp/plugins.sync.lock',
        'host_manifest_present': (snapshot / '.agents/plugins/marketplace.json').is_file(),
        'host_revision': revision.read_text().strip() if revision.exists() else None,
        'observed_download_chain': ['GitHub repository/ref/zipball',
                                    'chatgpt.com/backend-api/plugins/export/curated',
                                    'files.openai.com/content (codex-plugins.zip)'],
        'policy': 'Only archive-verified static files plus the observed native revision are reused. '
                  'Every task receives private writable copies; the shared cache is never mounted. '
                  'Unverified host snapshots, installed plugins, sync locks, auth, and session state are not imported. '
                  'Native startup synchronization and all network requests remain enabled.',
    }


def sha256_file(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def plugin_tree_inventory(root):
    """List resource paths and sizes; reject links and special files."""
    if not root.is_dir() or root.is_symlink():
        raise ValueError('No regular native plugin resource directory')
    inventory = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        if parent == root:
            dirs[:] = [name for name in dirs if name != '.git']
        for name in dirs:
            if (parent / name).is_symlink():
                raise ValueError('Symlink in plugin resource tree')
        for name in files:
            if parent == root and name == '.git':
                continue
            path = parent / name
            if path.is_symlink() or not path.is_file():
                raise ValueError('Non-regular plugin resource file')
            inventory[path.relative_to(root).as_posix()] = path.stat().st_size
    return inventory


def observe_native_plugin_snapshot(home):
    """Called after CLI exit; never persist these task-derived bytes directly."""
    try:
        if home.is_symlink() or (home / '.tmp').is_symlink():
            raise ValueError('Symlink in native plugin cache ancestry')
        marker = home / '.tmp/plugins.sha'
        if marker.is_symlink() or marker.stat().st_size > 128:
            raise ValueError('Invalid native plugin revision marker')
        revision = marker.read_text().strip()
        if not re.fullmatch('[0-9a-f]{40}', revision):
            raise ValueError('Native revision is not a Git SHA-1; refusing to guess its meaning')
        return {'revision': revision, 'files': plugin_tree_inventory(home / '.tmp/plugins')}
    except (OSError, ValueError) as exc:
        return {'error': str(exc)}


def unpack_plugin_archive(archive, destination):
    """Accept only a bounded, regular-file marketplace tree from the ZIP."""
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > 20000 or sum(m.file_size for m in members) > 256 * 1024 * 1024:
            raise ValueError('Plugin archive exceeds resource limits')
        manifests = [m.filename for m in members
                     if m.filename.endswith('/.agents/plugins/marketplace.json')]
        if len(manifests) != 1:
            raise ValueError('Expected exactly one native marketplace manifest')
        prefix = manifests[0][:-len('.agents/plugins/marketplace.json')]
        seen = set()
        for member in members:
            name = member.filename
            if ('\\' in name or name.startswith('/') or '..' in name.split('/')
                    or ':' in name or '\x00' in name or not name.startswith(prefix)):
                raise ValueError('Unsafe or out-of-root plugin archive path')
            relative = name[len(prefix):].rstrip('/')
            if not relative:
                continue
            if relative.startswith('/') or any(part in ('', '.', '..') for part in relative.split('/')):
                raise ValueError('Non-canonical plugin resource path')
            if relative.split('/')[0] == '.git':
                # Server export ZIPs contain Git config, logs and objects. None
                # of these belong in the reusable static resource snapshot.
                continue
            if '.git' in relative.split('/'):
                raise ValueError('Git metadata is not a static plugin resource')
            mode = member.external_attr >> 16
            kind = mode & 0o170000
            if kind not in (0, 0o040000, 0o100000):
                raise ValueError('Symlinks and special archive entries are forbidden')
            path = destination / relative
            if member.is_dir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            if relative in seen:
                raise ValueError('Duplicate archive file')
            seen.add(relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as incoming, path.open('xb') as output:
                shutil.copyfileobj(incoming, output)
            path.chmod(0o755 if mode & 0o111 else 0o644)
        manifest = json.loads((destination / '.agents/plugins/marketplace.json').read_text())
        if not isinstance(manifest.get('plugins'), list):
            raise ValueError('Invalid native marketplace manifest')


def plugin_archive_revision(archive):
    """Read only Git HEAD/ref text, never execute or retain Git configuration.

    The curated export can be an older backup than GitHub main. Native 0.160.1
    explicitly reads the backup archive's Git HEAD; using main's SHA for this
    export would falsely label its contents as a newer revision.
    """
    with zipfile.ZipFile(archive) as bundle:
        names = set(bundle.namelist())
        heads = [name for name in names if name.endswith('/.git/HEAD')]
        if not heads:
            return None
        if len(heads) != 1 or bundle.getinfo(heads[0]).file_size > 4096:
            raise ValueError('Ambiguous archive Git HEAD')
        head = bundle.read(heads[0]).decode('ascii').strip()
        if re.fullmatch('[0-9a-f]{40}', head):
            return head
        if not head.startswith('ref: '):
            raise ValueError('Invalid archive Git HEAD')
        reference = head[5:]
        if not re.fullmatch(r'refs/[A-Za-z0-9_./-]+', reference) or '..' in reference.split('/'):
            raise ValueError('Unsafe archive Git ref')
        prefix = heads[0][:-len('HEAD')]
        ref_path = prefix + reference
        if ref_path in names:
            if bundle.getinfo(ref_path).file_size > 4096:
                raise ValueError('Oversized archive Git ref')
            revision = bundle.read(ref_path).decode('ascii').strip()
            if re.fullmatch('[0-9a-f]{40}', revision):
                return revision
        packed = prefix + 'packed-refs'
        if packed in names and bundle.getinfo(packed).file_size < 1024 * 1024:
            for line in bundle.read(packed).decode('ascii').splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1] == reference and re.fullmatch('[0-9a-f]{40}', parts[0]):
                    return parts[0]
        raise ValueError('Cannot resolve archive Git HEAD')


def restore_plugin_resources(cache, home, binary_hash):
    """Restore copies into this task's fresh CODEX_HOME, with no shared mount."""
    result = {'hit': False, 'cache_directory': str(cache), 'status': 'cold'}
    pointer = cache / 'current'
    if not pointer.exists():
        return result
    try:
        identity = pointer.read_text().strip()
        if not re.fullmatch('[0-9a-f]{64}', identity):
            raise ValueError('Invalid plugin cache object id')
        snapshot = cache / identity
        metadata = json.loads((snapshot / 'manifest.json').read_text())
        if metadata.get('schema') != 1 or metadata.get('binary_sha256') != binary_hash:
            raise ValueError('Cache manifest or CLI identity mismatch')
        revision = (snapshot / 'plugins.sha').read_text().strip()
        if revision != metadata['revision'] or not re.fullmatch('[0-9a-f]{40}', revision):
            raise ValueError('Cache revision mismatch')
        # Check resource types only; cached file contents are not hashed.
        files = plugin_tree_inventory(snapshot / 'plugins')
        target = home / '.tmp'
        target.mkdir(parents=True, exist_ok=True)
        shutil.copytree(snapshot / 'plugins', target / 'plugins')
        (target / 'plugins.sha').write_text(revision + '\n')
        result.update(hit=True, status='restored_private_copy', revision=revision,
                      object_id=identity, file_count=len(files))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # A broken cache must not leave a partial snapshot masquerading as warm.
        shutil.rmtree(home / '.tmp/plugins', ignore_errors=True)
        (home / '.tmp/plugins.sha').unlink(missing_ok=True)
        result.update(status='rejected', error=str(exc))
    return result


def publish_plugin_resources(cache, binary_hash, native, archives, observed_revisions):
    """Publish server ZIP resources with the native revision, paths and sizes.

    Session/task files can never enter the cache: the payload is extracted from
    the server ZIP, not copied back from the task home. Different paths/sizes
    or missing/unknown native markers prevent publication.
    """
    if 'error' in native:
        return {'published': False, 'reason': native['error']}
    if not archives:
        return {'published': False, 'reason': 'No complete, CRC-valid upstream plugin ZIP was recovered'}
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    failures = []
    for archive in archives:
        try:
            archive_revision = plugin_archive_revision(archive)
            if archive_revision is not None:
                if native.get('revision') != archive_revision:
                    raise ValueError('Native revision differs from the curated export Git HEAD')
            elif native.get('revision') not in observed_revisions:
                raise ValueError('Native revision is not corroborated by archive or upstream requests')
            with tempfile.TemporaryDirectory(prefix='.building-', dir=cache) as temporary:
                stage = Path(temporary)
                unpack_plugin_archive(archive, stage / 'plugins')
                files = plugin_tree_inventory(stage / 'plugins')
                if files != native['files']:
                    raise ValueError('Downloaded archive differs from native plugin tree; refusing task-state export')
                metadata = {'schema': 1, 'binary_sha256': binary_hash, 'revision': native['revision'],
                            'archive_revision': archive_revision,
                            'files': files}
                identity = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()
                (stage / 'plugins.sha').write_text(native['revision'] + '\n')
                write_json(stage / 'manifest.json', metadata)
                with (cache / '.lock').open('a') as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    if not (cache / identity).exists():
                        os.rename(stage, cache / identity)
                    # Use a unique temporary pointer for concurrent independent runs.
                    with tempfile.NamedTemporaryFile(mode='w', prefix='.current-', dir=cache, delete=False) as pointer:
                        pointer.write(identity + '\n')
                        pointer_path = Path(pointer.name)
                    os.replace(pointer_path, cache / 'current')
                return {'published': True, 'object_id': identity, 'revision': native['revision'],
                        'file_count': len(files), 'archive_bytes': archive.stat().st_size}
        except (OSError, ValueError, zipfile.BadZipFile, KeyError) as exc:
            failures.append(str(exc))
    return {'published': False, 'reason': '; '.join(failures)}


def plugin_stream_objects(pcap, key_options, diagnostics, stream):
    subset = diagnostics / f'plugin-stream-{stream}.pcapng'
    export = diagnostics / f'plugin-objects-{stream}'
    if export.exists():
        return export
    export.mkdir()
    selected = subprocess.run(['tshark', '-r', str(pcap), '-Y', f'tcp.stream == {stream}',
                               '-w', str(subset)], capture_output=True, text=True, timeout=60)
    if selected.returncode:
        raise RuntimeError('Cannot isolate plugin stream: ' + selected.stderr[-1000:])
    exported = subprocess.run(['tshark', '-r', str(subset), *key_options, '-q',
                               '--export-objects', f'http,{export}'],
                              capture_output=True, text=True, timeout=60)
    if exported.returncode:
        raise RuntimeError('Cannot export plugin response: ' + exported.stderr[-1000:])
    return export


def plugin_download_evidence(pcap, keys, diagnostics):
    """Measure server and proxy legs separately; CRC-check exported ZIPs.

    Exports and temporary packet subsets never become task artifacts. Signed
    URLs, cookies, headers, and non-resource bodies are never cached.
    """
    result = {'downloads': [], 'complete_external_zip_count': 0,
              'complete_zip_observed': False, 'status': 'not_observed',
              'notice': 'Local proxy and external legs are the same download. '
                        'A missing exported body means unknown, not zero bytes. '
                        'Wire bytes include protocol overhead and retransmissions.'}
    if not pcap.exists() or not pcap.stat().st_size:
        result['status'] = 'no_capture'
        return result, [], set()
    key_options = ['-o', f'tls.keylog_file:{keys}'] if keys.exists() else []
    fields = ['tcp.stream', 'http2.streamid', 'http2.headers.authority', 'http2.headers.path',
              'http2.headers.status', 'http2.headers.content_type', 'http2.headers.content_disposition',
              'tcp.dstport', 'ip.dst']
    cmd = ['tshark', '-r', str(pcap), *key_options, '-Y',
           'http2.headers.authority || http2.headers.status', '-T', 'fields']
    for field in fields:
        cmd += ['-e', field]
    read = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if read.returncode:
        raise RuntimeError('Cannot inspect plugin requests: ' + read.stderr[-1000:])
    rows = [dict(zip(fields, line.split('\t'))) for line in read.stdout.splitlines()]
    revisions, streams, metadata_streams, request_urls = set(), {}, set(), {}
    request_counts = {}
    def url_identity(url):
        parsed = urlparse(url)
        return parsed.hostname, parsed.path, tuple(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    for row in rows:
        host, path = row.get('http2.headers.authority'), row.get('http2.headers.path', '').split('?')[0]
        if host:
            request_counts[row['tcp.stream']] = request_counts.get(row['tcp.stream'], 0) + 1
        match = re.fullmatch('/repos/openai/plugins/zipball/([0-9a-f]{40})', path)
        if host == 'api.github.com' and match:
            revisions.add(match[1])
        if host == 'chatgpt.com' and path == '/backend-api/plugins/export/curated':
            metadata_streams.add(row['tcp.stream'])
        if host == 'files.openai.com' and path == '/content':
            stream = row['tcp.stream']
            request_urls[stream] = url_identity('https://files.openai.com' + row['http2.headers.path'])
            streams[stream] = {'tcp_stream': int(stream), 'host': host, 'path': path,
                               'leg': 'external' if row.get('tcp.dstport') == '443' else 'local_proxy',
                               'status_code': None, 'zip_complete': None,
                               'exported_body_bytes': None, 'wire_inbound_bytes': 0}
    for row in rows:
        stream = row['tcp.stream']
        if stream in streams and row.get('http2.headers.status'):
            entry = streams[stream]
            entry.update(status_code=row['http2.headers.status'],
                         content_type=row.get('http2.headers.content_type'),
                         content_disposition=row.get('http2.headers.content_disposition'))
    trusted_urls = set()
    for stream in metadata_streams:
        if request_counts.get(stream) != 1:
            # The object exporter does not expose HTTP/2 stream IDs. Do not
            # associate a body from a different multiplexed request with this API.
            continue
        for body in plugin_stream_objects(pcap, key_options, diagnostics, stream).iterdir():
            if not body.is_file() or body.stat().st_size > 128 * 1024:
                continue
            try:
                metadata = json.loads(body.read_bytes())
                if isinstance(metadata, dict) and set(metadata) == {'download_url'}:
                    url = metadata['download_url']
                    if isinstance(url, str) and urlparse(url).scheme == 'https' and urlparse(url).hostname == 'files.openai.com':
                        trusted_urls.add(url_identity(url))
            except (ValueError, UnicodeError):
                pass
    archives = []
    for stream, entry in streams.items():
        entry['curated_metadata_url_verified'] = request_urls[stream] in trusted_urls
        entry['request_count_on_connection'] = request_counts.get(stream, 0)
        sizes = subprocess.run(['tshark', '-r', str(pcap), '-Y', f'tcp.stream == {stream}',
                                '-T', 'fields', '-e', 'tcp.srcport', '-e', 'frame.len'],
                               capture_output=True, text=True, timeout=60)
        if sizes.returncode:
            raise RuntimeError('Cannot measure plugin TCP stream: ' + sizes.stderr[-1000:])
        entry['wire_inbound_bytes'] = sum(int(parts[1]) for line in sizes.stdout.splitlines()
                                          if len(parts := line.split('\t')) == 2 and parts[0] == '443')
        if entry['status_code'] != '200' or 'codex-plugins.zip' not in (entry.get('content_disposition') or ''):
            continue
        export = plugin_stream_objects(pcap, key_options, diagnostics, stream)
        for body in export.iterdir():
            if not body.is_file():
                continue
            # This filtered connection must contain only the single content request.
            with body.open('rb') as prefix:
                is_zip_body = prefix.read(4) == b'PK\x03\x04'
            if not is_zip_body:
                continue
            entry['exported_body_bytes'] = max(entry['exported_body_bytes'] or 0, body.stat().st_size)
            entry['zip_complete'] = False
            try:
                with zipfile.ZipFile(body) as archive:
                    if (len(archive.infolist()) > 20000
                            or sum(x.file_size for x in archive.infolist()) > 256 * 1024 * 1024):
                        continue
                    if archive.testzip() is not None:
                        continue
                    entry.update(zip_complete=True, zip_members=len(archive.infolist()),
                                 zip_sha256=sha256_file(body))
                    if entry['curated_metadata_url_verified'] and request_counts.get(stream) == 1:
                        archives.append(body)
            except (zipfile.BadZipFile, OSError, RuntimeError, EOFError):
                pass
    result['downloads'] = list(streams.values())
    result['complete_external_zip_count'] = sum(x['zip_complete'] is True and x['leg'] == 'external'
                                               for x in streams.values())
    result['complete_zip_observed'] = any(x['zip_complete'] is True for x in streams.values())
    result['status'] = 'observed' if streams else 'not_observed'
    return result, archives, revisions


def pcapng_capture_counters(path):
    """Read packet counts and final Interface Statistics Blocks before editcap.

    Some rewrite tools discard ISBs. Missing ifdrop is unknown, never zero.
    Only a single capture section is expected from this runner's dumpcap.
    """
    result = {'packet_blocks': None, 'interface_statistics': [], 'parse_error': None}
    if path is None or not path.exists() or not path.stat().st_size:
        return result
    endian, section, packets, statistics = '<', -1, 0, {}
    try:
        with path.open('rb') as stream:
            while True:
                header = stream.read(12)
                if not header:
                    break
                if len(header) != 12:
                    raise ValueError('Truncated PCAPNG block header')
                if header[:4] == b'\x0a\x0d\x0d\x0a':
                    if header[8:12] not in (b'\x4d\x3c\x2b\x1a', b'\x1a\x2b\x3c\x4d'):
                        raise ValueError('Invalid PCAPNG byte order')
                    endian = '<' if header[8:12] == b'\x4d\x3c\x2b\x1a' else '>'
                    section += 1
                kind, size = struct.unpack_from(endian + 'II', header)
                if section < 0 or size < 12 or size % 4:
                    raise ValueError('Invalid PCAPNG block length or missing section header')
                if kind == 5:
                    if size > 1024 * 1024:
                        raise ValueError('Oversized interface statistics block')
                    block = header + stream.read(size - 12)
                    if len(block) != size:
                        raise ValueError('Truncated PCAPNG statistics block')
                    interface = struct.unpack_from(endian + 'I', block, 8)[0]
                    entry = {'section': section, 'interface': interface}
                    offset = 20
                    while offset + 4 <= size - 4:
                        code, length = struct.unpack_from(endian + 'HH', block, offset)
                        offset += 4
                        if code == 0:
                            break
                        if offset + length > size - 4:
                            raise ValueError('Truncated PCAPNG statistics option')
                        if code in (4, 5, 7) and length == 8:
                            key = {4: 'received_packets', 5: 'dropped_packets', 7: 'os_dropped_packets'}[code]
                            entry[key] = struct.unpack_from(endian + 'Q', block, offset)[0]
                        offset += (length + 3) // 4 * 4
                    statistics[(section, interface)] = entry
                    trailer = block[-4:]
                else:
                    stream.seek(size - 16, 1) if size >= 16 else None
                    trailer = stream.read(4) if size >= 16 else header[-4:]
                    if kind in (2, 3, 6):
                        packets += 1
                if len(trailer) != 4 or struct.unpack(endian + 'I', trailer)[0] != size:
                    raise ValueError('Invalid or truncated PCAPNG block trailer')
        result.update(packet_blocks=packets, interface_statistics=list(statistics.values()))
    except (OSError, ValueError, struct.error) as exc:
        result['parse_error'] = str(exc)
    return result


def capture_statistics(log, pcap, args, exit_code=None):
    counters = pcapng_capture_counters(pcap)
    captured_matches = re.findall(r'Packets captured:\s*(\d+)', log)
    captured = int(captured_matches[-1]) if captured_matches else counters['packet_blocks']
    interfaces = {}
    for match in re.finditer(r"Packets received/dropped on interface '([^']+)':\s*(\d+)/(\d+)([^\n]*)", log):
        name, received, dropped, tail = match.groups()
        interfaces[name] = {'interface': name, 'received_packets': int(received),
                            'dropped_packets': int(dropped),
                            'breakdown': {k: int(v) for k, v in re.findall(
                                r'(pcap|dumpcap|flushed|ps_ifdrop):(\d+)', tail)}}
    source, dropped = None, None
    if interfaces:
        dropped, source = sum(x['dropped_packets'] for x in interfaces.values()), 'dumpcap_final_summary'
    elif counters['interface_statistics'] and all('dropped_packets' in x for x in counters['interface_statistics']):
        dropped = sum(x['dropped_packets'] for x in counters['interface_statistics'])
        source = 'pcapng_interface_statistics'
    denominator = captured + dropped if captured is not None and dropped is not None else None
    rate = dropped / denominator if denominator else None
    warnings = []
    if dropped is None:
        warnings.append('Dropped packets were not reported; zero loss is NOT established.')
    elif dropped:
        warnings.append(f'Capture lost {dropped} packets ({rate * 100:.6f}%). Zero-loss target NOT met.'
                        if rate is not None else f'Capture lost {dropped} packets. Zero-loss target NOT met.')
    if not captured:
        warnings.append('No captured packets were confirmed.')
    if exit_code != 0:
        warnings.append('dumpcap did not complete normally, or capture never started.')
    if counters['parse_error']:
        warnings.append('Capture file parse error: ' + counters['parse_error'])
    if (captured_matches and counters['packet_blocks'] is not None
            and captured != counters['packet_blocks']):
        warnings.append('Captured packet summary differs from packet blocks written to disk.')
    quality_ok = (dropped == 0 and captured is not None and captured > 0 and not warnings)
    return {'captured_packets': captured, 'dropped_packets': dropped, 'drop_rate': rate,
            'drop_rate_percent': rate * 100 if rate is not None else None,
            'drop_rate_formula': 'dropped / (captured + dropped)',
            'statistics_source': source, 'zero_loss_verified': quality_ok,
            'status': 'zero_loss' if quality_ok else 'packet_loss' if dropped else 'unverified',
            'warnings': warnings, 'interfaces': list(interfaces.values()),
            'pcapng_counters_before_tls_embedding': counters, 'dumpcap_exit_code': exit_code,
            'interface': 'any', 'capture_filter': None,
            'kernel_buffer_mib_requested': args.capture_buffer_mib,
            'kernel_buffer_mib_effective': None,
            'userspace_queue_mib': args.capture_queue_mib,
            'write_strategy': 'temporary spool; copy to result after dumpcap stops',
            'spool_directory': str(args.capture_spool_dir)}


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    """Replace resume metadata atomically; never retain a partial JSON file."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def finishing():
    """Let the first Ctrl+C stop work; defer further ones during evidence cleanup."""
    def remember_interrupt(signum, frame):
        global _interrupt_requested
        _interrupt_requested = True
    previous = signal.signal(signal.SIGINT, remember_interrupt)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


def stop(proc):
    """Stop a child session, escalating only when its leader does not exit."""
    if proc is None:
        return
    for sig, timeout in [(signal.SIGINT, 5), (signal.SIGTERM, 2), (signal.SIGKILL, 2)]:
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            proc.wait(timeout=timeout)
            return
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            continue
        # Remove any remaining members after the session leader exits.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return
    raise RuntimeError(f'Process cleanup did not finish: {proc.pid}')


@contextmanager
def task_runtime(diagnostics, stop_capture):
    with tempfile.TemporaryDirectory(prefix='humaneval-codex-') as temp:
        runtime = Path(temp)
        try:
            yield runtime
        finally:
            with finishing():
                try:
                    stop_capture()
                finally:
                    keys = runtime / 'home/codex_tls_keys.log'
                    if keys.exists():
                        shutil.copyfile(keys, diagnostics / 'codex_tls_keys.log')


def completed_task(saved, task_dir):
    """A wrong solution is complete; interrupted executions are retryable."""
    try:
        if not isinstance(saved, dict):
            return False
        output = json.loads((task_dir / 'codex_output.json').read_text())
        if saved.get('experiment', {}).get('capture_server'):
            measurement = saved.get('measurement', {})
            if (not measurement.get('server_record_complete') or not measurement.get('coverage', {}).get('local_covers_agent')
                    or measurement.get('quality_passed') is False
                    or (measurement.get('data_quality') or {}).get('quality_passed') is False):
                return False
            for name in ['server_traffic.pcapng', 'server_timeline.jsonl']:
                path = task_dir / name
                if not path.is_file() or path.stat().st_size != measurement['server_collection']['files'][name]['bytes']:
                    return False
        capture = saved.get('capture', {})
        traffic = saved.get('traffic', {})
        counters = pcapng_capture_counters(task_dir / 'raw_traffic.pcapng')
        return (saved.get('status', 'completed') == 'completed'
                and saved.get('setup_ok') and not saved.get('error')
                and output.get('succeeded') is True and output.get('exit_code') == 0
                and not output.get('timed_out') and not output.get('interrupted')
                and isinstance(saved.get('verification'), dict)
                and saved['verification'].get('passed') is True
                and saved.get('quality_passed', True) is True
                and saved.get('cleanup_status', 'confirmed') == 'confirmed'
                and capture.get('zero_loss_verified') is True
                and not counters['parse_error']
                and (counters['packet_blocks'] or 0) > 0
                and counters['packet_blocks'] == capture.get('captured_packets')
                and traffic.get('transport_verified') is True
                and (not saved.get('experiment', {}).get('tls_inspection', True)
                     or traffic.get('tls_keys_embedded') is True)
                and all((task_dir / name).is_file() for name in
                        ['task_prompt.txt', 'codex_timeline.jsonl', 'raw_traffic.pcapng'])
                and (task_dir / 'raw_traffic.pcapng').stat().st_size > 0)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return False


def infrastructure_error(result, reason, exc=None):
    """Keep failure domains independent; only this domain blocks a batch."""
    result.setdefault('infrastructure_errors', []).append(str(reason))
    result['error'] = result.get('error') or str(reason)
    if exc is not None:
        result.setdefault('tracebacks', []).append(traceback.format_exc())
        print(result['tracebacks'][-1], file=sys.stderr, flush=True)


def task_outcome(result, args, output):
    """Classify without changing any packet/SSE completeness predicate."""
    measurement = result.get('measurement') or {}
    capture = result.get('capture') or {}
    traffic = result.get('traffic') or {}
    if not isinstance(output, dict):
        output = {}
        result.setdefault('quality_issues', []).append('invalid_codex_output')
    interrupted = (result.get('status') == 'interrupted' or output.get('interrupted')
                   or _interrupt_requested)
    if interrupted:
        agent_status = 'interrupted'
    elif output.get('timed_out'):
        agent_status = 'timed_out'
    elif not result.get('setup_ok') or output.get('status') == 'not_started':
        agent_status = 'not_started'
    elif not output.get('succeeded'):
        agent_status = 'failed'
    elif result.get('verify_passed') is False:
        agent_status = 'verification_failed'
    elif result.get('verify_passed') is True:
        agent_status = 'passed'
    else:
        agent_status = 'verification_unavailable'
    quality = []
    if not capture.get('zero_loss_verified'):
        quality.append('local_capture_quality')
    if not traffic.get('transport_verified'):
        quality.append('transport_unverified')
    if not args.no_tls_inspection and not traffic.get('tls_keys_embedded'):
        quality.append('tls_keys_unverified')
    if args.capture_server:
        if not measurement.get('server_record_complete'):
            quality.append('server_record_incomplete')
        if not measurement.get('coverage', {}).get('local_covers_agent'):
            quality.append('local_agent_coverage_unverified')
        if (measurement.get('quality_passed') is False
                or (measurement.get('data_quality') or {}).get('quality_passed') is False):
            quality.append('server_quality_failed')
    if result.get('quality_passed') is False:
        quality.append('existing_quality_failed')
    quality.extend(result.get('quality_issues', []))
    if result.get('error') and agent_status == 'passed' and not result.get('infrastructure_errors') and not quality:
        quality.append('existing_task_error')
    result.update(agent_status=agent_status, quality_passed=not quality,
                  quality_issues=list(dict.fromkeys(quality)))
    if interrupted:
        status = 'interrupted'
    elif result.get('infrastructure_errors') or result.get('cleanup_status') != 'confirmed':
        status = 'infrastructure_failed'
    elif agent_status != 'passed' or quality:
        status = 'failed'
    else:
        status = 'completed'
    result.update(status=status, completed=(status == 'completed'))
    if status != 'completed' and not result.get('error'):
        result['error'] = ('Interrupted by user' if interrupted else
                           '; '.join(result.get('infrastructure_errors', [])) or
                           (agent_status if agent_status != 'passed' else ', '.join(quality)))
    if status == 'interrupted':
        result['interruption_reason'] = 'user_interrupt'
    elif result.get('error'):
        result['interruption_reason'] = result['error']
    return status


def resume_outcome(saved, directory):
    """Read both new and legacy results without modifying them."""
    if not isinstance(saved, dict):
        return 'unfinished'
    if completed_task(saved, directory):
        return 'completed'
    if saved.get('status') in ('running', 'interrupted', 'infrastructure_failed'):
        return saved['status']
    if (saved.get('infrastructure_errors') or not saved.get('setup_ok')
            or saved.get('cleanup_status') == 'unconfirmed'):
        return 'infrastructure_failed'
    # Legacy records lack a dedicated cleanup flag. Require positive evidence
    # before treating one as an ordinary failed attempt that may be skipped.
    if 'cleanup_status' not in saved:
        if saved.get('capture', {}).get('dumpcap_exit_code') != 0:
            return 'unfinished'
        if saved.get('experiment', {}).get('capture_server'):
            if saved.get('measurement', {}).get('server_stopped', {}).get('state') != 'STOPPED':
                return 'unfinished'
    if saved.get('ended_at') and saved.get('status') in ('completed', 'failed'):
        return 'failed'
    return 'unfinished'


def archive_attempt(run_root, task_dir):
    """Move a whole old attempt atomically, never truncate its seven files."""
    history = run_root / '.attempt-history' / task_dir.name
    history.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = history / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + str(time.time_ns()))
    if destination.exists():
        raise FileExistsError(destination)
    task_dir.rename(destination)
    for parent in (history, history.parent, run_root):
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return str(destination.relative_to(run_root))


def batch_checkpoint(run_root, experiment, task_id=None, state=None, result=None):
    progress = experiment['progress']
    if task_id is not None:
        entry = progress[task_id]
        if state == 'running':
            for key in ('agent_status', 'quality_passed', 'cleanup_status', 'error', 'infrastructure_errors', 'quality_issues'):
                entry.pop(key, None)
        entry.update(state=state, updated_at=now(), scheduled=state not in ('completed', 'failed'))
        if result is not None:
            for key in ('agent_status', 'quality_passed', 'cleanup_status', 'error',
                        'infrastructure_errors', 'quality_issues'):
                if key in result:
                    entry[key] = result[key]
    experiment['next_task_id'] = next((key for key, entry in progress.items()
                                      if entry.get('scheduled', True)), None)
    write_json(run_root / 'experiment.json', experiment)


def server_cleanup_check(spark, task_measurement, result):
    """Evaluate ownership/safety AFTER capture shutdown, not SSE completeness."""
    confirmed = True
    if task_measurement is not None:
        measurement = result.get('measurement') or {}
        stopped = measurement.get('server_stopped') or {}
        if getattr(task_measurement, 'started', True) and stopped.get('state') != 'STOPPED':
            confirmed = False
            infrastructure_error(result, 'Remote capture stop not confirmed: ' + str(stopped))
        if stopped.get('stop_reason') == 'model/watchdog resource safety failed':
            infrastructure_error(result, stopped['stop_reason'])
        last = measurement.get('last_server_status') or {}
        if last.get('model', {}).get('safe') is False:
            infrastructure_error(result, 'Model/watchdog unsafe during task')
    if spark is not None and result.get('status') != 'interrupted' and not _interrupt_requested:
        try:
            if spark.tunnel is None or spark.tunnel.poll() is not None:
                raise RuntimeError('SSH inference tunnel is not running')
            state = spark.call('model', timeout=25)
            result['post_task_model_health'] = state
            if not state.get('safe') or state.get('health') != 200:
                raise RuntimeError('Spark model/watchdog not safe or HTTP health not 200')
            old_id = (spark.meta.get('ready_state') or {}).get('container_id')
            if old_id and old_id != state.get('container_id'):
                raise RuntimeError('Spark model container changed during batch')
            # Outside both capture intervals: do not add traffic to any sample.
            spark.http('/health', timeout=5)
        except Exception as exc:
            infrastructure_error(result, 'Post-task Spark health check: ' + str(exc), exc)
    return confirmed


def recover_server_raw(spark, task_measurement, task_dir, result):
    """Parser failure must not prevent recovery of the original remote PCAPNG.

    Use the existing SSH config and result path. Never change remote files.
    """
    measurement = result.get('measurement') or {}
    if (measurement.get('server_stopped') or {}).get('state') != 'STOPPED':
        return
    dest = task_dir / 'server_traffic.pcapng'
    reported = (measurement.get('server_collection') or {}).get('files', {}).get('server_traffic.pcapng', {}).get('bytes')
    if dest.is_file() and dest.stat().st_size > 0 and (reported is None or dest.stat().st_size == reported):
        return
    from spark_measurement import REMOTE
    remote = f'{REMOTE}/logs/agent-capture/{spark.run_id}/{task_measurement.task}/server_traffic.pcapng'
    try:
        expected = int(reported) if reported is not None else int(spark.raw('stat -c %s -- ' + shlex.quote(remote), timeout=20).strip())
        subprocess.run(['scp', '-F', str(ROOT / 'config/ssh_config'), '-o', 'BatchMode=yes',
                        '-o', 'ConnectTimeout=8', f'spk:{remote}', str(dest)],
                       check=True, capture_output=True, timeout=120)
        if expected <= 0 or dest.stat().st_size != expected:
            raise RuntimeError('Recovered server PCAPNG size mismatch')
        measurement['raw_capture_recovery'] = {'status': 'recovered', 'bytes': expected, 'remote': remote}
    except Exception as exc:
        measurement['raw_capture_recovery'] = {'status': 'failed', 'remote': remote, 'error': str(exc)}
        # The stopped session remains on Spark. Do not confuse a collection/
        # parsing failure with an unsafe worker. A separate health check follows.
        result.setdefault('quality_issues', []).append('server_raw_recovery_failed')
        result.setdefault('tracebacks', []).append(traceback.format_exc())
        print('[CAPTURE WARNING] Cannot recover server raw capture: ' + str(exc), file=sys.stderr, flush=True)
        if isinstance(exc, OSError) and exc.errno in (errno.ENOSPC, errno.EDQUOT):
            infrastructure_error(result, 'Disk space exhausted during raw capture recovery', exc)


def native_codex():
    executable = shutil.which('codex')
    if not executable:
        raise RuntimeError('codex is not in PATH')
    path = Path(executable).resolve()
    # Follow installed shell wrappers as data, never source their auth loaders.
    for _ in range(5):
        if not path.is_file() or path.read_bytes()[:2] != b'#!':
            break
        match = re.search(r'^\s*exec\s+(/[A-Za-z0-9_./-]+)', path.read_text(errors='replace'), re.M)
        if not match or not Path(match.group(1)).is_file():
            break
        candidate = Path(match.group(1)).resolve()
        if candidate == path:
            break
        path = candidate
    def is_elf(candidate):
        with candidate.open('rb') as handle:
            return handle.read(4) == b'\x7fELF'
    if is_elf(path):
        return path
    # npm installs a Node launcher next to a platform-specific native binary.
    package = path.parent.parent
    for candidate in package.glob('node_modules/@openai/codex-*/vendor/*/bin/codex'):
        if is_elf(candidate):
            return candidate
    for candidate in package.glob('vendor/*/bin/codex'):
        if is_elf(candidate):
            return candidate
    raise RuntimeError('Cannot locate the native Codex ELF binary')


def code_mode_host(binary, override=None):
    """Find the native helper matching the installed Codex CLI.

    Code-mode-only models cannot run tools without this executable. The CLI
    discovers the helper beside its own binary, so we must bind it to the same
    path inside bubblewrap instead of mounting only /opt/bin/codex.
    """
    if override is not None:
        candidates = [override.expanduser()]
    else:
        candidates = [binary.with_name('codex-code-mode-host')]
        launcher = shutil.which('codex')
        if launcher:
            launcher_dir = Path(launcher).resolve().parent
            candidates.extend([launcher_dir / 'codex-code-mode-host',
                               launcher_dir / 'bin' / 'codex-code-mode-host'])
        helper_on_path = shutil.which('codex-code-mode-host')
        if helper_on_path:
            candidates.append(Path(helper_on_path))
    for candidate in candidates:
        path = candidate.resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            continue
        with path.open('rb') as stream:
            if stream.read(4) == b'\x7fELF':
                return path
    raise RuntimeError(
        'Missing codex-code-mode-host (required for code-mode-only models). '
        f'Codex binary: {binary}. Install the helper from the SAME Codex '
        'CLI release, or pass --code-mode-host /absolute/path/to/codex-code-mode-host. '
        'Do not disable code_mode_host as a workaround: code-mode-only models '
        'would still be unable to call tools.'
    )


def isolated(runtime, binary, command, host_binary=None):
    cmd = ['bwrap', '--unshare-all', '--share-net', '--die-with-parent',
           '--new-session', '--cap-drop', 'ALL']
    for path in ['/usr', '/bin', '/sbin', '/lib', '/lib64', '/etc/ssl/certs',
                 '/etc/resolv.conf', '/etc/hosts', '/etc/nsswitch.conf', '/etc/os-release']:
        if Path(path).exists():
            cmd += ['--ro-bind', path, path]
    cmd += ['--ro-bind', str(binary), '/opt/bin/codex']
    if host_binary is not None:
        cmd += ['--ro-bind', str(host_binary), '/opt/bin/codex-code-mode-host']
    cmd += ['--bind', str(runtime / 'home'), '/home/runner',
            '--bind', str(runtime / 'work'), '/work',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--chdir', '/work']
    catalog = runtime / 'home/.codex/model_catalog.json'
    if catalog.is_file():
        cmd += ['--ro-bind', str(catalog), '/home/runner/.codex/model_catalog.json']
    return cmd + ['--'] + command


def start_proxy(run_root, args):
    if args.no_tls_inspection:
        return None, None, None
    executable = args.mitmdump or shutil.which('mitmdump')
    fallback = Path('/root/.local/share/claude-tls/venv/bin/mitmdump')
    if not executable and fallback.is_file():
        executable = str(fallback)
    if not executable:
        raise RuntimeError('TLS inspection requires mitmdump; install mitmproxy into .venv')
    try:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
    except OSError as exc:
        raise RuntimeError(f'TLS inspection proxy cannot open a local listening socket: {exc}') from exc
    confdir = run_root / 'tls_proxy_ca'
    env = os.environ.copy()
    env['SSLKEYLOGFILE'] = str(run_root / 'tls_keys.log')
    log = (run_root / 'tls_proxy.log').open('wb')
    try:
        proc = subprocess.Popen([str(executable), '--listen-host', '127.0.0.1',
            '--listen-port', str(port), '--set', f'confdir={confdir}',
            '--set', 'connection_strategy=lazy', '--set', 'flow_detail=0'], env=env,
            stdout=log, stderr=log, start_new_session=True)
    finally:
        log.close()
    ca = confdir / 'mitmproxy-ca-cert.pem'
    try:
        for _ in range(100):
            if proc.poll() is not None:
                raise RuntimeError('TLS proxy exited; see experiment.diagnostics in result.json')
            if ca.exists():
                try:
                    with socket.create_connection(('127.0.0.1', port), .2):
                        return proc, f'http://127.0.0.1:{port}', ca
                except OSError:
                    pass
            time.sleep(.1)
        raise RuntimeError('TLS proxy startup timed out')
    except BaseException:
        stop(proc)
        raise


def solver_env(runtime, provider, proxy, ca):
    allowed = {'PATH', 'LANG', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
               'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
               'SSL_CERT_FILE', 'SSL_CERT_DIR', 'CODEX_CA_CERTIFICATE'}
    allowed.add(provider.get('env_key', 'OPENAI_API_KEY'))
    allowed.update(provider.get('env_http_headers', {}).values())
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env.update(HOME='/home/runner', CODEX_HOME='/home/runner/.codex',
               PATH='/opt/bin:/usr/bin:/bin', TMPDIR='/tmp',
               SSLKEYLOGFILE='/home/runner/codex_tls_keys.log')
    if proxy:
        env['HTTPS_PROXY'] = env['https_proxy'] = proxy
        env['HTTP_PROXY'] = env['http_proxy'] = proxy
        # Keep inference directly visible on the LAN, including WS upgrade.
        host = urlparse(provider.get('base_url', '')).hostname
        bypass = ','.join(filter(None, [env.get('NO_PROXY', env.get('no_proxy', '')),
                                       'localhost', '127.0.0.1', '::1', host]))
        env['NO_PROXY'] = env['no_proxy'] = bypass
        destination = runtime / 'home' / 'inspection-ca.pem'
        destination.write_bytes(Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()
                                + b'\n' + ca.read_bytes())
        env['CODEX_CA_CERTIFICATE'] = env['SSL_CERT_FILE'] = '/home/runner/inspection-ca.pem'
    return env


def run_codex(command, env, prompt, task_dir, timeout, diagnostics, observer=None):
    events, errors, final, count, tools = [], [], None, 0, 0
    started, timed_out, interrupted = now(), False, False
    proc, buffer, failure = None, b'', None
    def record(line, trace):
        nonlocal count, tools, final
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError('Non-object event')
        except ValueError:
            event = {'type': 'unparsed', 'text': line.decode(errors='replace')}
        count += 1
        trace.write(json.dumps({'timestamp_utc': now(), 'unix_ns': time.time_ns(),
                                'event': event}, ensure_ascii=False) + '\n')
        item = event.get('item') or {}
        if not isinstance(item, dict):
            item = {}
        if item.get('type') in ('command_execution', 'mcp_tool_call') and event.get('type') == 'item.started':
            tools += 1
        if item.get('type') == 'agent_message':
            final = item.get('text')
        if item.get('type') == 'error':
            errors.append(str(item.get('message', item.get('error', 'Codex emitted an error item'))))
        if event.get('type') in ('thread.started', 'turn.completed', 'turn.failed', 'error'):
            events.append(event)
            if event.get('type') in ('error', 'turn.failed'):
                errors.append(str(event.get('message', event.get('error', event.get('type')))))
    with (task_dir / 'codex_timeline.jsonl').open('w', buffering=1) as trace, \
         (diagnostics / 'codex_stderr.log').open('wb') as stderr:
        selector = selectors.DefaultSelector()
        try:
            proc = subprocess.Popen(command, env=env, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=stderr, start_new_session=True)
            proc.stdin.write(prompt.encode())
            proc.stdin.close()
            os.set_blocking(proc.stdout.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout
            exit_seen = None
            while selector.get_map():
                if observer is not None:
                    observer.poll()
                if time.monotonic() >= deadline:
                    timed_out = True
                    errors.append('Codex execution timed out')
                    break
                for key, _ in selector.select(.2):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    buffer += chunk
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        record(line, trace)
                        if errors:
                            break
                    if errors:
                        break
                if errors:
                    break
                if proc.poll() is not None:
                    exit_seen = exit_seen or time.monotonic()
                    if time.monotonic() - exit_seen >= 1:
                        break
            if not errors and not timed_out:
                try:
                    proc.wait(timeout=max(.1, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    errors.append('Codex execution timed out')
        except KeyboardInterrupt as exc:
            interrupted, failure = True, exc
            errors.append('Interrupted by user (Ctrl+C)')
        except Exception as exc:
            failure = exc
            errors.append(f'{type(exc).__name__}: {exc}')
            errors.append(traceback.format_exc())
        finally:
            with finishing():
                try:
                    stop(proc)
                except Exception as exc:
                    errors.append('Process cleanup: ' + str(exc))
                    failure = failure or exc
                # Preserve bytes already received, including a final line without newline.
                if proc is not None and proc.stdout:
                    os.set_blocking(proc.stdout.fileno(), False)
                    while True:
                        try:
                            chunk = os.read(proc.stdout.fileno(), 65536)
                        except (BlockingIOError, OSError):
                            break
                        if not chunk:
                            break
                        buffer += chunk
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    record(line, trace)
                if buffer:
                    record(buffer, trace)
                selector.close()
                if proc is not None:
                    if proc.stdout:
                        proc.stdout.close()
                    if proc.stdin and not proc.stdin.closed:
                        proc.stdin.close()
                output = {'final_message': final, 'events': events, 'errors': errors,
                          'exit_code': proc.returncode if proc else None,
                          'timed_out': timed_out, 'interrupted': interrupted,
                          'event_count': count, 'tool_call_count': tools,
                          'started_at': started, 'ended_at': now()}
                if _interrupt_requested and not interrupted:
                    interrupted = output['interrupted'] = True
                    errors.append('Interrupted by user during process cleanup')
                output['succeeded'] = (proc is not None and proc.returncode == 0
                                       and not timed_out and not interrupted and not failure
                                       and any(e.get('type') == 'turn.completed' for e in events)
                                       and not errors)
                write_json(task_dir / 'codex_output.json', output)
    if failure:
        raise failure
    return output


def score(task, runtime, binary, timeout):
    solution = runtime / 'work' / 'solution.py'
    if not solution.is_file():
        return {'passed': False, 'error': 'Codex did not create solution.py'}
    source = solution.read_text()
    # Hidden tests are introduced only after the agent has exited, in a fresh process.
    (runtime / 'work' / 'verify.py').write_text(source + '\n' + task['test']
                                               + f"\ncheck({task['entry_point']})\n")
    try:
        command = isolated(runtime, binary, ['/usr/bin/python3', '-I', '/work/verify.py'])
        command.remove('--share-net')
        proc = subprocess.Popen(command, env={'PATH': '/usr/bin:/bin', 'HOME': '/home/runner'},
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            stop(proc)
            raise
        finally:
            stop(proc)
        return {'passed': proc.returncode == 0, 'returncode': proc.returncode,
                'stdout': stdout[-4000:], 'stderr': stderr[-4000:], 'solution': source}
    except subprocess.TimeoutExpired:
        return {'passed': False, 'error': 'Hidden tests timed out', 'solution': source}


def traffic_report(task_dir, run_root, provider, mode, diagnostics):
    report = {'requested_mode': mode, 'transport_verified': False,
              'tls_decryption_verified': False, 'openai_tls_decryption_verified': False,
              'notice': 'No observed auxiliary request does not prove the harness never sends one. '
                        'Capture covers all interfaces and may include other processes; domain alone does not establish process attribution.'}
    pcap = task_dir / 'raw_traffic.pcapng'
    if not pcap.exists() or pcap.stat().st_size == 0:
        report['error'] = 'No capture available'
        return report
    keys = diagnostics / 'tls_keys.log'
    keys.write_bytes(b''.join(p.read_bytes() + b'\n' for p in
                     [run_root / 'tls_keys.log', diagnostics / 'codex_tls_keys.log'] if p.exists()))
    fields = ['frame.number', 'tcp.stream', 'ip.dst', 'tcp.dstport', 'http.host',
              'http.request.method', 'http.request.uri', 'http.response.code',
              'http2.headers.authority', 'http2.headers.method', 'http2.headers.path',
              'tls.handshake.extensions_server_name', 'websocket.opcode', 'dns.qry.name']
    port = urlparse(provider.get('base_url', '')).port or 443
    base = ['tshark', '-r', str(pcap), '-d', f'tcp.port=={port},http', '-T', 'fields']
    for field in fields:
        base += ['-e', field]
    decoded = {}
    for label, extra in [('without_keys', []), ('with_keys', ['-o', f'tls.keylog_file:{keys}'])]:
        proc = subprocess.run(base + extra, capture_output=True, text=True, timeout=60)
        if proc.returncode:
            report['error'] = proc.stderr[-2000:]
            return report
        rows = [dict(zip(fields, line.split('\t'))) for line in proc.stdout.splitlines()]
        decoded[label] = rows
    plain = {r['frame.number'] for r in decoded['without_keys']
             if r.get('http.request.method') or r.get('http2.headers.method')}
    rows = decoded['with_keys']
    decrypted = [r for r in rows if r['frame.number'] not in plain and
                 (r.get('http.request.method') or r.get('http2.headers.method'))]
    def is_openai(host):
        host = host.split(':')[0].lower()
        return any(host == d or host.endswith('.' + d) for d in
                   ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com'])
    report['tls_decryption_verified'] = bool(decrypted)
    report['openai_tls_decryption_verified'] = any(is_openai(r.get('http.host') or
                                                    r.get('http2.headers.authority', '')) for r in decrypted)
    report['decrypted_request_count'] = len(decrypted)
    report['observed_hosts'] = sorted({r.get(k) for r in rows for k in
        ['http.host', 'http2.headers.authority', 'tls.handshake.extensions_server_name', 'dns.qry.name'] if r.get(k)})
    inference = [r for r in rows if r.get('http.request.method') and
                 '/responses' in r.get('http.request.uri', '') and
                 str(port) == r.get('tcp.dstport')]
    streams = {r['tcp.stream'] for r in inference}
    ws_streams = {r['tcp.stream'] for r in rows if r.get('http.response.code') == '101'}
    ws_frames = any(r['tcp.stream'] in streams & ws_streams and r.get('websocket.opcode') for r in rows)
    http_post = any(r.get('http.request.method') == 'POST' for r in inference)
    report.update(http_responses_post_seen=http_post, websocket_frames_seen=ws_frames,
                  transport_verified=(ws_frames and not http_post) if mode == 'ws' else http_post)
    return report


def embed_tls_keys(pcap, keys):
    """Keep Wireshark decryption material inside the single requested PCAPNG."""
    if not pcap.exists() or not pcap.stat().st_size or not keys.exists() or not keys.stat().st_size:
        return False
    with tempfile.TemporaryDirectory(prefix='humaneval-pcap-') as directory:
        output = Path(directory) / 'capture.pcapng'
        proc = subprocess.run(['editcap', '--inject-secrets', f'tls,{keys}', str(pcap), str(output)],
                              capture_output=True, text=True, timeout=60)
        if proc.returncode:
            raise RuntimeError('Cannot embed TLS keys: ' + proc.stderr[-2000:])
        shutil.copyfile(output, pcap)
    return True


def initialize_task(task_dir, task):
    task_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    prompt = ('Implement the Python function below. Write the complete module to '
              '/work/solution.py. You may use local checks. Do not search for external '
              'solutions. End with a short completion message.\n\n' + task['prompt'])
    (task_dir / 'task_prompt.txt').write_text(prompt)
    (task_dir / 'codex_timeline.jsonl').write_text('')
    (task_dir / 'raw_traffic.pcapng').write_bytes(b'')
    write_json(task_dir / 'codex_output.json', {'status': 'not_started'})
    return prompt


def main():
    global _interrupt_requested
    _interrupt_requested = False
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--range', nargs=2, type=int, metavar=('START', 'END'))
    parser.add_argument('--mode', '--mode-', choices=['http', 'ws'], default='http')
    parser.add_argument('--provider', choices=['configured', 'spark'], default='configured')
    parser.add_argument('--capture-server', action='store_true')
    parser.add_argument('--experiment-profile', choices=['baseline-8k','context-16k','context-32k','context-64k'], default='context-32k')
    parser.add_argument('--metrics-interval', type=float, choices=[0,.5,1,2,5], default=1.)
    parser.add_argument('--tcp-interval', type=float, choices=[0,.5,1,2,5], default=1.)
    parser.add_argument('--no-detailed-events', action='store_false', dest='detailed_events')
    parser.add_argument('--kv-cache-memory-bytes', type=int, default=None)
    parser.add_argument('--stop-model', action='store_true', help='Explicitly stop our Spark service at exit')
    parser.add_argument('--tunnel-port', type=int, default=18000)
    parser.add_argument('--all', action='store_true', help='Explicitly select all tasks')
    parser.add_argument('--model')
    parser.add_argument('--effort', choices=['low', 'medium', 'middle', 'high', 'xhigh', 'max'], default=None)
    parser.add_argument('--dataset', type=Path, default=ROOT / 'DATASET/HumanEval/HumanEval.jsonl.gz')
    parser.add_argument('--results-root', type=Path, default=ROOT / 'results_codex_humaneval')
    parser.add_argument('--resume-dir', type=Path)
    parser.add_argument('--resume-unattempted', action='store_true',
                        help='On resume, keep finalized non-infrastructure failures; run pending/interrupted tasks only')
    parser.add_argument('--timeout', type=float, default=600)
    parser.add_argument('--test-timeout', type=float, default=10)
    parser.add_argument('--sudo-dumpcap', action='store_true')
    parser.add_argument('--capture-buffer-mib', type=int, default=128,
                        help='Requested libpcap kernel capture buffer (MiB); default 128')
    parser.add_argument('--capture-queue-mib', type=int, default=64,
                        help='dumpcap threaded userspace queue limit (MiB); default 64')
    parser.add_argument('--capture-spool-dir', type=Path, default=Path(tempfile.gettempdir()),
                        help='Temporary capture storage, copied after stop; default /tmp')
    parser.add_argument('--mitmdump')
    parser.add_argument('--code-mode-host', type=Path,
                        help='Codex code mode helper from the same CLI release')
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument('--with-auth-json', action='store_true',
                      help='Opt in to copying host auth.json; default does NOT copy it')
    auth.add_argument('--no-auth-json', action='store_true',
                      help='Explicitly select the default: do not copy host auth.json')
    parser.add_argument('--no-tls-inspection', action='store_true')
    parser.add_argument('--list-tasks', action='store_true')
    args = parser.parse_args()
    if args.resume_unattempted and not args.resume_dir:
        parser.error('--resume-unattempted requires --resume-dir')
    if not args.list_tasks and not args.all and not args.range and args.limit is None:
        parser.error('Specify --range, --limit, or explicit --all; no implicit 164-task run')
    if args.all and (args.range or args.limit is not None):
        parser.error('--all cannot be combined with task subsets')
    if (args.capture_server or args.stop_model) and args.provider != 'spark':
        parser.error('--capture-server/--stop-model require --provider spark')
    args.model = args.model or ('Qwen3.6-35B-A3B' if args.provider == 'spark' else 'gpt-6.1-sol')
    args.effort = args.effort or ('low' if args.provider == 'spark' else 'medium')
    if args.provider == 'spark':
        if args.mode != 'http' or args.with_auth_json or args.model != 'Qwen3.6-35B-A3B':
            parser.error('Spark uses verified HTTP Qwen model, isolated unauthenticated local provider')
        args.no_tls_inspection = True
    if args.limit is not None and args.limit < 1:
        parser.error('--limit must be positive')
    if args.range and (args.limit is not None or not 1 <= args.range[0] <= args.range[1]):
        parser.error('--range requires 1 <= START <= END and cannot be combined with --limit')
    if args.timeout <= 0 or args.test_timeout <= 0:
        parser.error('Timeouts must be positive')
    if args.capture_buffer_mib < 1 or args.capture_queue_mib < 1:
        parser.error('Capture buffer and queue sizes must be positive')
    args.capture_spool_dir = args.capture_spool_dir.resolve()
    copy_auth_json = args.with_auth_json
    if args.effort == 'middle':
        args.effort = 'medium'
    with gzip.open(args.dataset, 'rt') as stream:
        tasks = [json.loads(line) for line in stream if line.strip()]
    if args.range:
        if args.range[1] > len(tasks):
            parser.error('--range END exceeds dataset size')
        tasks = tasks[args.range[0] - 1:args.range[1]]
    if args.limit:
        tasks = tasks[:args.limit]
    if args.list_tasks:
        for task in tasks:
            print(task['task_id'])
        return 0
    run_root = (args.resume_dir.resolve() if args.resume_dir else
                args.results_root.resolve() / datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    if args.resume_dir:
        if not run_root.is_dir():
            parser.error('--resume-dir must be an existing experiment directory')
    else:
        run_root.mkdir(parents=True, mode=0o700)
    root_fd = os.open(run_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f'Another batch owns {run_root}', file=sys.stderr, flush=True)
            return 1
        try:
            return run_batch(args, tasks, run_root, copy_auth_json, parser)
        except KeyboardInterrupt:
            return 130
    finally:
        os.close(root_fd)


def run_batch(args, tasks, run_root, copy_auth_json, parser):
    previous = None
    if args.resume_dir:
        old_metadata = run_root / 'experiment.json'
        if old_metadata.exists():
            previous = json.loads(old_metadata.read_text())
        else:
            saved_results = sorted(run_root.glob('*/result.json'))
            if not saved_results:
                parser.error('No result.json found in --resume-dir')
            for saved_path in saved_results:
                try:
                    candidate = json.loads(saved_path.read_text()).get('experiment')
                except (OSError, ValueError, AttributeError):
                    continue
                if isinstance(candidate, dict):
                    previous = candidate
                    break
            if previous is None:
                parser.error('No readable experiment metadata in --resume-dir')
        expected = {'task_ids': [t['task_id'] for t in tasks], 'model': args.model,
                    'effort': args.effort, 'mode': args.mode, 'tls_inspection': not args.no_tls_inspection,
                    'copy_auth_json': copy_auth_json}
        expected['capture_settings'] = {'buffer_mib': args.capture_buffer_mib,
                                        'queue_mib': args.capture_queue_mib,
                                        'spool_directory': str(args.capture_spool_dir),
                                        'interface': 'any', 'filter': None}
        if args.provider == 'spark':
            expected.update(provider='spark', capture_server=args.capture_server,
                            experiment_profile=args.experiment_profile,
                            metrics_interval=args.metrics_interval,tcp_interval=args.tcp_interval,
                            detailed_events=args.detailed_events,kv_cache_memory_bytes=args.kv_cache_memory_bytes)
        if 'timeout' in previous and previous['timeout'] != args.timeout:
            parser.error('Resume timeout does not match experiment.json')
        if any(previous.get(k) != v for k, v in expected.items()):
            parser.error('Resume selection/model/effort/mode/TLS settings do not match experiment.json')
    print(f'Experiment dir: {run_root}', flush=True)
    experiment = {'created_at': now(), 'task_ids': [t['task_id'] for t in tasks],
                  'model': args.model, 'effort': args.effort, 'mode': args.mode,
                  'status': 'initializing', 'provider': args.provider, 'timeout': args.timeout,
                   'tls_inspection': not args.no_tls_inspection,
                  'timeline_notice': 'CLI event receipt times, not wire-level request timestamps',
                  'isolation': 'bubblewrap; dataset, references and previous results are not mounted',
                  'auxiliary_traffic': 'No telemetry-disable settings are added; all interfaces captured',
                   'copy_auth_json': copy_auth_json}
    experiment['capture_server'] = args.capture_server
    if args.provider=='spark':
        from scripts.experiment_config import ExperimentConfig
        experiment['experiment_profile']=args.experiment_profile
        experiment['requested_context']=ExperimentConfig.build(args.experiment_profile,args.metrics_interval,args.detailed_events,args.tcp_interval,args.kv_cache_memory_bytes).as_dict()
        experiment.update(metrics_interval=args.metrics_interval,tcp_interval=args.tcp_interval,
                          detailed_events=args.detailed_events,kv_cache_memory_bytes=args.kv_cache_memory_bytes)
    experiment['run_id'] = run_root.name + '-' + str(time.time_ns())
    experiment['capture_settings'] = {'buffer_mib': args.capture_buffer_mib,
                                      'queue_mib': args.capture_queue_mib,
                                      'spool_directory': str(args.capture_spool_dir),
                                      'interface': 'any', 'filter': None}
    if previous:
        experiment['created_at'] = previous.get('created_at', experiment['created_at'])
        experiment['resumed_at'] = now()
    completed = {}
    experiment['progress'] = {t['task_id']: {'state': 'pending', 'scheduled': True} for t in tasks}
    if args.resume_dir:
        for task in tasks:
            directory = run_root / task['task_id'].replace('/', '__')
            try:
                saved = json.loads((directory / 'result.json').read_text())
            except (OSError, ValueError):
                saved = None
            if isinstance(saved, dict) and saved.get('task_id') != task['task_id']:
                saved = None
            state = resume_outcome(saved, directory) if directory.exists() else 'pending'
            entry = experiment['progress'][task['task_id']]
            entry['state'] = state
            if isinstance(saved, dict):
                for key in ('agent_status', 'quality_passed', 'cleanup_status', 'error',
                            'infrastructure_errors', 'quality_issues'):
                    if key in saved:
                        entry[key] = saved[key]
                # Old records may lack the independent status fields.
                if state in ('completed', 'failed'):
                    entry.setdefault('cleanup_status', 'confirmed')
                    if state == 'completed':
                        entry.setdefault('agent_status', 'passed')
                        entry.setdefault('quality_passed', True)
                    else:
                        legacy_measurement = saved.get('measurement') or {}
                        if (legacy_measurement.get('server_record_complete') is False
                                or saved.get('capture', {}).get('zero_loss_verified') is False
                                or legacy_measurement.get('quality_passed') is False):
                            entry.setdefault('quality_passed', False)
                        if saved.get('codex_timed_out'):
                            entry.setdefault('agent_status', 'timed_out')
                        elif saved.get('verify_passed') is False:
                            entry.setdefault('agent_status', 'verification_failed')
                        elif saved.get('verify_passed') is True:
                            entry.setdefault('agent_status', 'passed')
                entry.setdefault('agent_status', 'legacy_unknown')
            if state == 'completed' or (args.resume_unattempted and state == 'failed'):
                completed[task['task_id']] = saved
                entry['scheduled'] = False
            history = run_root / '.attempt-history' / directory.name
            if history.is_dir():
                entry['prior_attempts'] = [str(x.relative_to(run_root)) for x in sorted(history.iterdir()) if x.is_dir()]
        if len(completed) == len(tasks):
            for task in tasks:
                print(f"SKIP {experiment['progress'][task['task_id']]['state']}: {task['task_id']}", flush=True)
            experiment['status'] = 'completed_with_failures' if any(e['state'] == 'failed' for e in experiment['progress'].values()) else 'completed'
            experiment['ended_at'] = now()
            batch_checkpoint(run_root, experiment)
            return 0
    batch_checkpoint(run_root, experiment)
    scratch = tempfile.TemporaryDirectory(prefix='humaneval-diagnostics-')
    scratch_root = Path(scratch.name)
    proxy_proc, rows = None, list(completed.values())
    spark = None
    try:
        for cmd in ['bwrap', 'dumpcap', 'tshark', 'editcap']:
            if not shutil.which(cmd):
                raise RuntimeError(f'Required command missing: {cmd}')
        binary = native_codex()
        host_binary = code_mode_host(binary, args.code_mode_host)
        if args.provider == 'spark':
            spark = SparkSession(args, experiment['run_id'], scratch_root)
            experiment['spark'] = spark.meta
            spark.prepare()
        config_home = spark.config_home if spark else Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex')))
        experiment['plugin_resources'] = plugin_resource_findings(config_home)
        config_text = (config_home / 'config.toml').read_text()
        config = tomllib.loads(config_text)
        provider_name = config.get('model_provider', 'openai')
        provider = config.get('model_providers', {}).get(provider_name, {})
        if provider.get('env_key') and not os.environ.get(provider['env_key']):
            raise RuntimeError(f"Missing credential environment variable: {provider['env_key']}")
        version = subprocess.run([str(binary), '--version'], capture_output=True, text=True).stdout.strip()
        experiment.update(codex_version=version, code_mode_host=str(host_binary), provider=provider_name,
                          base_url=provider.get('base_url'), status='running')
        binary_hash = sha256_file(binary)
        plugin_cache = args.results_root.resolve() / '.plugin_resources' / binary_hash
        experiment['plugin_resources'].update(cache_directory=str(plugin_cache),
                                              binary_sha256=binary_hash,
                                              cache_available=(plugin_cache / 'current').is_file())
        proxy_proc, proxy, ca = start_proxy(scratch_root, args)
        batch_checkpoint(run_root, experiment)
        for index, task in enumerate(tasks, 1):
            if _interrupt_requested:
                raise KeyboardInterrupt
            task_dir = run_root / task['task_id'].replace('/', '__')
            if task['task_id'] in completed:
                print(f"SKIP {experiment['progress'][task['task_id']]['state']}: {task['task_id']}", flush=True)
                continue
            if task_dir.exists():
                archived = archive_attempt(run_root, task_dir)
                experiment['progress'][task['task_id']].setdefault('prior_attempts', []).append(archived)
                print(f'PRESERVE prior attempt: {archived}', flush=True)
            task_dir.mkdir(mode=0o700, exist_ok=False)
            print(f"[{index}/{len(tasks)}] {task['task_id']} mode={args.mode}", flush=True)
            result = {'task_id': task['task_id'], 'started_at': now(), 'setup_ok': False,
                      'verify_passed': None, 'error': None, 'mode': args.mode,
                      'status': 'running', 'interruption_reason': None,
                      'infrastructure_errors': [], 'cleanup_status': 'unconfirmed',
                      'quality_issues': []}
            rows.append(result)
            # A crash before finalization is distinguishable from an unattempted task.
            result['experiment'] = {k: v for k, v in experiment.items() if k != 'progress'}
            write_json(task_dir / 'result.json', result)
            batch_checkpoint(run_root, experiment, task['task_id'], 'running')
            prompt = initialize_task(task_dir, task)
            diagnostics_temp = tempfile.TemporaryDirectory(prefix='humaneval-task-diagnostics-')
            diagnostics = Path(diagnostics_temp.name)
            capture = None
            task_measurement = None
            capture_command = None
            spool_temp = None
            local_cleanup_ok = True
            copy_error = None
            output = {}
            capture_spool = None
            capture_exit_code = None
            native_plugins = {'error': 'Codex did not start'}
            plugin_cache_state = {'hit': False, 'status': 'not_started'}
            try:
                with task_runtime(diagnostics, lambda: stop(capture)) as runtime:
                    (runtime / 'home/.codex').mkdir(parents=True)
                    (runtime / 'work').mkdir()
                    # Retain user routing, telemetry and other harness configuration.
                    # Host files referenced by that configuration remain outside the mount namespace.
                    (runtime / 'home/.codex/config.toml').write_text(config_text)
                    if spark:
                        shutil.copyfile(spark.config_home / 'model_catalog.json', runtime / 'home/.codex/model_catalog.json')
                    plugin_cache_state = restore_plugin_resources(
                        plugin_cache, runtime / 'home/.codex', binary_hash)
                    if copy_auth_json and (config_home / 'auth.json').exists():
                        shutil.copyfile(config_home / 'auth.json', runtime / 'home/.codex/auth.json')
                    env = solver_env(runtime, provider, proxy, ca)
                    probe = subprocess.run(isolated(runtime, binary, ['/usr/bin/python3', '-c',
                        'import os; assert not os.path.exists(' + repr(str(args.dataset.resolve())) + '); '
                        'assert not os.path.exists("/root/.codex"); assert os.getcwd()=="/work"; '
                        'assert os.access("/opt/bin/codex-code-mode-host", os.X_OK); print("isolated")'],
                        host_binary),
                        env=env, capture_output=True, text=True, timeout=15)
                    if probe.returncode or probe.stdout.strip() != 'isolated':
                        raise RuntimeError('Filesystem isolation unavailable: ' + probe.stderr.strip())
                    free_bytes = min(shutil.disk_usage(args.capture_spool_dir).free,
                                     shutil.disk_usage(task_dir).free)
                    if free_bytes < 256 * 1024 * 1024:
                        raise RuntimeError('Capture spool has less than 256 MiB free; refusing incomplete capture')
                    # Keep the spool recoverable if copying to the result directory fails.
                    spool_temp = Path(tempfile.mkdtemp(prefix='humaneval-capture-', dir=args.capture_spool_dir))
                    capture_spool = spool_temp / 'capture.pcapng'
                    result['capture_spool_path'] = str(capture_spool)
                    write_json(task_dir / 'result.json', result)
                    if spark and args.capture_server:
                        task_measurement = spark.task(task['task_id'], task_dir)
                        result['measurement'] = task_measurement.meta
                        task_measurement.start()
                    capture_command = (['sudo', '-n'] if args.sudo_dumpcap else []) + [
                        'dumpcap', '-q', '-i', 'any', '-B', str(args.capture_buffer_mib),
                        '-t', '-C', str(args.capture_queue_mib * 1024 * 1024),
                        '-N', '262144', '-w', str(capture_spool)]
                    with (diagnostics / 'capture.log').open('wb') as log:
                        capture = subprocess.Popen(capture_command,
                            stdout=log, stderr=log, start_new_session=True)
                    time.sleep(.5)
                    if capture.poll() is not None:
                        raise RuntimeError('Packet capture failed; see diagnostics in result.json')
                    if task_measurement:
                        task_measurement.local_ready(capture, capture_spool, diagnostics / 'capture.log')
                    result['setup_ok'] = True
                    cmd = ['/opt/bin/codex', '-c', 'approval_policy="never"',
                            '-c', 'features.code_mode_host=true', 'exec',
                           '--json', '--ephemeral', '--skip-git-repo-check', '--color', 'never',
                           '--dangerously-bypass-approvals-and-sandbox', '--model', args.model,
                           '-c', f'model_reasoning_effort="{args.effort}"',
                           '-c', f'model_providers.{provider_name}.supports_websockets={str(args.mode == "ws").lower()}', '-']
                    if task_measurement:
                        task_measurement.agent_begin()
                    output = run_codex(isolated(runtime, binary, cmd, host_binary), env, prompt, task_dir, args.timeout, diagnostics, task_measurement)
                    if task_measurement:
                        task_measurement.agent_end()
                        task_measurement.before_local_stop()
                    result.update(codex_exit_code=output['exit_code'], codex_timed_out=output['timed_out'],
                                  codex_event_count=output['event_count'], codex_tool_call_count=output['tool_call_count'],
                                  codex_errors=output['errors'])
                    time.sleep(.5)
                    stop(capture)
                    capture_exit_code = capture.returncode
                    if task_measurement:
                        task_measurement.local_stopped()
                    capture = None
                    keyfile = runtime / 'home/codex_tls_keys.log'
                    if keyfile.exists():
                        shutil.copyfile(keyfile, diagnostics / 'codex_tls_keys.log')
                    native_plugins = observe_native_plugin_snapshot(runtime / 'home/.codex')
                    if not output['succeeded']:
                        result['error'] = 'Codex failed or timed out: ' + ('; '.join(output['errors'][:2])
                                           or 'see codex_output.json and diagnostics in result.json')
                    else:
                        try:
                            verification = score(task, runtime, binary, args.test_timeout)
                        except UnicodeError as exc:
                            # Invalid Agent-written source is a failed solution, not a broken service.
                            verification = {'passed': False, 'error': str(exc)}
                            result.setdefault('tracebacks', []).append(traceback.format_exc())
                        result['verification'] = verification
                        result['verify_passed'] = verification['passed']
            except KeyboardInterrupt:
                result.update(status='interrupted', error='Interrupted by user (Ctrl+C)',
                              interruption_reason='user_interrupt')
            except Exception as exc:
                # Nonzero CLI exits/timeouts are returned normally by run_codex.
                # An exception here instead means setup, observer or cleanup failed.
                infrastructure_error(result, f'{type(exc).__name__}: {exc}', exc)
            finally:
                with finishing():
                    try:
                        stop(capture)
                    except Exception as exc:
                        local_cleanup_ok = False
                        infrastructure_error(result, 'Capture cleanup failed: ' + str(exc), exc)
                    if capture is not None:
                        capture_exit_code = capture.returncode
                        if task_measurement:
                            try:
                                task_measurement.agent_end()
                                if local_cleanup_ok:
                                    task_measurement.local_stopped()
                            except Exception as exc:
                                infrastructure_error(result, 'Capture lifecycle bookkeeping: ' + str(exc), exc)
                    try:
                        if capture_spool is not None and capture_spool.exists():
                            shutil.copyfile(capture_spool, task_dir / 'raw_traffic.pcapng')
                    except OSError as exc:
                        copy_error = f'Cannot retain capture spool: {exc}'
                        infrastructure_error(result, copy_error, exc)
                        result['retained_capture_spool'] = str(capture_spool)
                    log_path = diagnostics / 'capture.log'
                    try:
                        capture_log = log_path.read_text(errors='replace') if log_path.exists() else ''
                        capture_info = capture_statistics(capture_log, capture_spool, args, capture_exit_code)
                    except Exception as exc:
                        capture_info = {'zero_loss_verified': False, 'status': 'unverified',
                                        'warnings': ['Capture statistics failed: ' + str(exc)]}
                        result.setdefault('tracebacks', []).append(traceback.format_exc())
                    capture_info['command'] = capture_command
                    if copy_error:
                        capture_info['zero_loss_verified'] = False
                        capture_info['status'] = 'unverified'
                        capture_info['warnings'].append(copy_error)
                    result['capture'] = capture_info
                    if task_measurement:
                        try:
                            result['measurement'] = task_measurement.collect()
                        except Exception as exc:
                            result['measurement'] = task_measurement.meta
                            result['measurement']['server_record_complete'] = False
                            result['measurement'].setdefault('errors', []).append(repr(exc))
                            result.setdefault('tracebacks', []).append(traceback.format_exc())
                        recover_server_raw(spark, task_measurement, task_dir, result)
                        if not result['measurement'].get('server_record_complete') or not result['measurement'].get('coverage', {}).get('local_covers_agent'):
                            result['error'] = result['error'] or 'Dual capture incomplete: ' + str(result['measurement'].get('errors', []))
                    remote_cleanup_ok = server_cleanup_check(spark, task_measurement, result)
                    result['cleanup_status'] = ('confirmed' if local_cleanup_ok and remote_cleanup_ok else 'unconfirmed')
                    for warning in capture_info['warnings']:
                        print('[CAPTURE WARNING] ' + warning, file=sys.stderr, flush=True)
                    if not capture_info['zero_loss_verified'] and not result['error']:
                        result['error'] = 'Capture quality requirement not met: ' + '; '.join(capture_info['warnings'])
                    try:
                        traffic = traffic_report(task_dir, scratch_root, provider, args.mode, diagnostics)
                        try:
                            downloads, archives, revisions = plugin_download_evidence(
                                task_dir / 'raw_traffic.pcapng', diagnostics / 'tls_keys.log', diagnostics)
                            publication = publish_plugin_resources(
                                plugin_cache, binary_hash, native_plugins, archives, revisions)
                            # Warm runs with no download retain the immutable cache unchanged.
                            result['plugin_resources'] = {'restore': plugin_cache_state,
                                                          'downloads': downloads,
                                                          'publication': publication}
                            if not plugin_cache_state['hit'] and not publication['published']:
                                print('[PLUGIN CACHE WARNING] No reusable snapshot published: '
                                      + publication['reason'], file=sys.stderr, flush=True)
                            if plugin_cache_state['hit'] and downloads['downloads']:
                                print('[PLUGIN CACHE WARNING] Plugin ZIP requested despite cache hit; '
                                      'download reduction is not established.', file=sys.stderr, flush=True)
                        except Exception as exc:
                            result['plugin_resources'] = {'restore': plugin_cache_state,
                                                          'validation_error': str(exc)}
                            print('[PLUGIN CACHE WARNING] ' + str(exc), file=sys.stderr, flush=True)
                    except Exception as exc:
                        result.setdefault('tracebacks', []).append(traceback.format_exc())
                        if isinstance(exc, OSError) and exc.errno in (errno.ENOSPC, errno.EDQUOT):
                            infrastructure_error(result, 'Disk space exhausted during traffic analysis', exc)
                        traffic = {'error': str(exc), 'transport_verified': False,
                                   'tls_decryption_verified': False, 'openai_tls_decryption_verified': False}
                    keys = diagnostics / 'tls_keys.log'
                    try:
                        keys.write_bytes(b''.join(p.read_bytes() + b'\n' for p in
                            [scratch_root / 'tls_keys.log', diagnostics / 'codex_tls_keys.log'] if p.exists()))
                        traffic['tls_keys_embedded'] = embed_tls_keys(task_dir / 'raw_traffic.pcapng', keys)
                    except Exception as exc:
                        result.setdefault('tracebacks', []).append(traceback.format_exc())
                        if isinstance(exc, OSError) and exc.errno in (errno.ENOSPC, errno.EDQUOT):
                            infrastructure_error(result, 'Disk space exhausted during TLS key embedding', exc)
                        traffic['tls_keys_embedded'] = False
                        result['error'] = result['error'] or 'TLS key embedding failed: ' + str(exc)
                    if not traffic.get('transport_verified'):
                        result['error'] = result['error'] or 'Inference transport could not be verified'
                    if not args.no_tls_inspection and not traffic.get('tls_keys_embedded'):
                        result['error'] = result['error'] or 'TLS keys could not be embedded'
                    try:
                        partial = json.loads((task_dir / 'codex_output.json').read_text())
                        if not isinstance(partial, dict):
                            raise ValueError('Codex output is not a JSON object')
                        output = partial
                        for source, target in [('exit_code', 'codex_exit_code'), ('timed_out', 'codex_timed_out'),
                                               ('event_count', 'codex_event_count'), ('tool_call_count', 'codex_tool_call_count'),
                                               ('errors', 'codex_errors')]:
                            if source in partial:
                                result[target] = partial[source]
                    except (OSError, ValueError) as exc:
                        result.setdefault('quality_issues', []).append('codex_output_unreadable')
                        result.setdefault('tracebacks', []).append(traceback.format_exc())
                    if _interrupt_requested:
                        result.update(status='interrupted', error=result['error'] or 'Interrupted by user during cleanup',
                                      interruption_reason='user_interrupt')
                    result.update(ended_at=now(), traffic=traffic)
                    try:
                        result['diagnostics'] = {p.name: p.read_text(errors='replace') for p in
                                                 diagnostics.glob('*.log') if p.name not in ('tls_keys.log', 'codex_tls_keys.log')}
                        # Preserve recoverable keys even if editcap unexpectedly fails.
                        if not traffic.get('tls_keys_embedded') and (diagnostics / 'tls_keys.log').exists():
                            result['diagnostics']['tls_keys_fallback'] = (diagnostics / 'tls_keys.log').read_text()
                    except Exception as exc:
                        infrastructure_error(result, 'Cannot retain task diagnostics: ' + str(exc), exc)
                    # Do not delete recoverable raw data if copying or stopping failed.
                    if spool_temp is not None and not copy_error and local_cleanup_ok:
                        try:
                            shutil.rmtree(spool_temp)
                        except Exception as exc:
                            infrastructure_error(result, 'Capture spool cleanup failed: ' + str(exc), exc)
                            result['cleanup_status'] = 'unconfirmed'
                    elif spool_temp is not None:
                        result['retained_capture_spool'] = str(capture_spool)
                    try:
                        diagnostics_temp.cleanup()
                    except Exception as exc:
                        infrastructure_error(result, 'Task diagnostics cleanup failed: ' + str(exc), exc)
                        result['cleanup_status'] = 'unconfirmed'
                    task_outcome(result, args, output)
                    print(f"CLEANUP {task['task_id']}: {result['cleanup_status']}", flush=True)
                    write_json(task_dir / 'result.json', result)
                    batch_checkpoint(run_root, experiment, task['task_id'], result['status'], result)
            print('END ' + json.dumps({k: result[k] for k in ['task_id', 'status', 'agent_status',
                'verify_passed', 'quality_passed', 'cleanup_status', 'error']}, ensure_ascii=False), flush=True)
            if _interrupt_requested or result['status'] == 'interrupted':
                raise KeyboardInterrupt
            if result['status'] == 'infrastructure_failed':
                experiment.update(status='blocked', error='; '.join(result['infrastructure_errors']) or 'Task cleanup unconfirmed',
                                  stopped_at_task=task['task_id'])
                break
        else:
            experiment['status'] = ('completed_with_failures' if any(r.get('status') != 'completed' for r in rows)
                                    else 'completed')
    except Exception as exc:
        experiment.update(status='blocked', error=f'{type(exc).__name__}: {exc}', stopped_at_task=experiment.get('next_task_id'))
        experiment['traceback'] = traceback.format_exc()
        print(experiment['traceback'], file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        experiment.update(status='interrupted', error='Interrupted by user', stopped_at_task=experiment.get('next_task_id'))
    finally:
        with finishing():
            try:
                stop(proxy_proc)
            except Exception as exc:
                experiment.setdefault('cleanup_errors', []).append('Proxy: ' + str(exc))
                experiment.setdefault('cleanup_tracebacks', []).append(traceback.format_exc())
            if spark is not None:
                try:
                    spark.close()
                except Exception as exc:
                    experiment.setdefault('cleanup_errors', []).append('Spark: ' + str(exc))
                    experiment.setdefault('cleanup_tracebacks', []).append(traceback.format_exc())
            if _interrupt_requested:
                experiment.update(status='interrupted', error='Interrupted by user during cleanup')
            if experiment.get('cleanup_errors') and experiment['status'] != 'interrupted':
                experiment.update(status='blocked', error='; '.join(experiment['cleanup_errors']))
            experiment['ended_at'] = now()
            # Only repair the current unfinished record. Never rewrite completed or
            # historical attempts, including results produced by older versions.
            for row in rows:
                if row.get('status') != 'running':
                    continue
                row.update(status='interrupted' if experiment['status'] == 'interrupted' else 'infrastructure_failed',
                           completed=False, error=row.get('error') or experiment.get('error') or 'Task finalization incomplete',
                           cleanup_status='unconfirmed', ended_at=now())
                if row['status'] != 'interrupted':
                    row.setdefault('infrastructure_errors', []).append(row['error'])
                if experiment.get('traceback'):
                    row.setdefault('tracebacks', []).append(experiment['traceback'])
                row.setdefault('agent_status', 'unknown')
                row.setdefault('quality_passed', False)
                row['experiment'] = {k: v for k, v in experiment.items() if k != 'progress'}
                write_json(run_root / row['task_id'].replace('/', '__') / 'result.json', row)
                batch_checkpoint(run_root, experiment, row['task_id'], row['status'], row)
            try:
                experiment['diagnostics'] = {'tls_proxy_log': (scratch_root / 'tls_proxy.log').read_text(errors='replace')
                                             if (scratch_root / 'tls_proxy.log').exists() else ''}
                scratch.cleanup()
            except Exception as exc:
                experiment.setdefault('cleanup_errors', []).append(str(exc))
                experiment.setdefault('cleanup_tracebacks', []).append(traceback.format_exc())
                if experiment['status'] != 'interrupted':
                    experiment.update(status='blocked', error='Batch diagnostics cleanup failed: ' + str(exc))
            try:
                batch_checkpoint(run_root, experiment)
            except OSError:
                print('Cannot persist final batch checkpoint; previous checkpoint retained', file=sys.stderr, flush=True)
                traceback.print_exc()
                if experiment['status'] != 'interrupted':
                    experiment['status'] = 'blocked'
            print(f"BATCH {experiment['status']}: {run_root / 'experiment.json'}", flush=True)
    return 130 if experiment['status'] == 'interrupted' else 0 if experiment['status'] in ('completed', 'completed_with_failures') else 1


if __name__ == '__main__':
    raise SystemExit(main())
