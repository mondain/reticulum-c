#!/usr/bin/env python3
"""Validate build provenance and stage an allowlisted, identity-preserving web catalog.

Paths in catalog.json are relative to its containing firmware/ directory. No
source logs, merged images, ELF files, configuration or identity images are copied.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import struct
import tempfile
import zipfile
import urllib.error
import urllib.parse
import urllib.request

# Exact variants only: Supreme LR1121 and T-Beam v1.2 are not supported.
BOARDS = {
    'heltec_wifi_lora_32_v3': ('Heltec WiFi LoRa 32 V3', 'esp32s3', 'SX1262', False),
    'heltec_wifi_lora_32_v2': ('Heltec WiFi LoRa 32 V2', 'esp32', 'SX1276', False),
    'ttgo_t_beam': ('LilyGo T-Beam v1.0/1.1', 'esp32', 'SX1276', False),
    'lilygo_t3_s3': ('LilyGo T3-S3', 'esp32s3', 'SX1262', False),
    'lilygo_t_beam_supreme': ('LilyGo T-Beam Supreme SX1262', 'esp32s3', 'SX1262', True),
    'wiscore_rak4631': ('RAKwireless RAK4631', 'nrf52840', 'SX1262', False),
    'heltec_t114': ('Heltec Mesh Node T114', 'nrf52840', 'SX1262', False),
    'seeed_xiao_nrf52840_wio': ('Seeed XIAO nRF52840 Wio-SX1262', 'nrf52840', 'SX1262', True),
    'lilygo_t_echo': ('LilyGo T-Echo', 'nrf52840', 'SX1262', True),
}
ESP_FILES = {'bootloader.bin', 'partitions.bin', 'boot_app0.bin', 'reticulum-c-mcu.bin'}
# (application start, DFU softdevice_req) of the bootloader on each nRF52840 board. The default is the
# S140 6.1.1 layout of the Adafruit-style bootloaders; the Seeed XIAO bootloader carries S140 7.3.0.
NRF_LAYOUT = {'seeed_xiao_nrf52840_wio': (0x27000, 0x0123)}
NRF_LAYOUT_DEFAULT = (0x26000, 0x00B6)
NRF_FILES = {'dfu': 'reticulum-c-mcu-dfu.zip', 'uf2': 'reticulum-c-mcu.uf2'}
CHIPS = {'esp32': 'ESP32', 'esp32s3': 'ESP32-S3', 'nrf52840': 'nRF52840'}


def fingerprint(data):
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


def read_file(directory, name):
    path = directory / name
    if Path(name).name != name or path.is_symlink() or not path.is_file():
        raise ValueError(f'unsafe or missing file: {name}')
    return path.read_bytes()


def checked_file(directory, metadata, name):
    data = read_file(directory, name)
    if not data or metadata.get('files', {}).get(name) != fingerprint(data):
        raise ValueError(f'hash or size mismatch: {directory.name}/{name}')
    return data


def partitions(data):
    result = []
    for start in range(0, len(data) - 31, 32):
        magic, kind, sub, offset, size, label, _ = struct.unpack('<HBBII16sI', data[start:start + 32])
        if magic == 0xffff or magic == 0xebeb:  # erased tail or ESP-IDF table MD5
            break
        if magic != 0x50aa or size == 0:
            raise ValueError('invalid partition table')
        result.append((kind, sub, offset, size, label.rstrip(b'\0').decode('ascii')))
    if not result or not any(kind == 1 and sub == 2 for kind, sub, *_ in result):
        raise ValueError('partition table has no identity NVS')
    return result


def esp_parts(directory, metadata, chip):
    parts = metadata.get('parts', [])
    if {p.get('name') for p in parts} != ESP_FILES or len(parts) != len(ESP_FILES):
        raise ValueError('unexpected or missing ESP32 part files')
    files = {name: checked_file(directory, metadata, name) for name in ESP_FILES}
    merged = checked_file(directory, metadata, 'merged.bin')
    if metadata.get('mergedOffset') != 0:
        raise ValueError('merged image must start at zero')
    offsets = {p['name']: p.get('offset') for p in parts}
    if any(type(off) is not int or off < 0 or off % 4096 for off in offsets.values()):
        raise ValueError('invalid flash part offset')
    if offsets['bootloader.bin'] != (0x1000 if chip == 'esp32' else 0):
        raise ValueError('wrong chip bootloader offset')
    if offsets['partitions.bin'] != metadata.get('partitionTableOffset'):
        raise ValueError('partition table offset mismatch')
    table = partitions(files['partitions.bin'])
    nvs = [(off, off + size) for kind, sub, off, size, _ in table if kind == 1 and sub == 2]
    app = files['reticulum-c-mcu.bin']
    app_start = offsets['reticulum-c-mcu.bin']
    if not any(kind == 0 and off == app_start and len(app) <= size for kind, _, off, size, _ in table):
        raise ValueError('application outside app partition')
    spans = []
    for name, off in offsets.items():
        data = files[name]
        end = off + ((len(data) + 4095) // 4096) * 4096
        if any(off < stop and end > start for start, stop in nvs):
            raise ValueError(f'part would erase NVS: {name}')
        if any(off < stop and end > start for start, stop in spans):
            raise ValueError('overlapping flash parts')
        spans.append((off, end))
        chunk = merged[off:off + len(data)]
        if name == 'bootloader.bin':
            # merge_bin updates header flash mode/frequency/size and its appended
            # SHA256. Use that exact bootloader, because esptool-js writes verbatim.
            if len(chunk) < 24 or chunk[0] != 0xe9:
                raise ValueError('invalid merged bootloader')
            raw = bytearray(data)
            raw[2:4] = chunk[2:4]
            if raw[23] == 1:
                raw[-32:] = hashlib.sha256(raw[:-32]).digest()
            if bytes(raw) != chunk:
                raise ValueError('merged bootloader differs beyond flash header')
            files[name] = chunk
        elif chunk != data:
            raise ValueError(f'merged image mismatch: {name}')
    for name in ('bootloader.bin', 'reticulum-c-mcu.bin'):
        data = files[name]
        if len(data) < 24 or data[0] != 0xe9 or struct.unpack_from('<H', data, 12)[0] != {'esp32': 0, 'esp32s3': 9}[chip]:
            raise ValueError(f'wrong chip in {name}')
    modes = {'qio': 0, 'qout': 1, 'dio': 2, 'dout': 3}
    freqs = {'40m': 0, '26m': 1, '20m': 2, '80m': 15}
    sizes = {'1MB': 0, '2MB': 1, '4MB': 2, '8MB': 3, '16MB': 4}
    mode, freq, size = (metadata.get(k) for k in ('flashMode', 'flashFrequency', 'flashSize'))
    if mode not in modes or freq not in freqs or size not in sizes:
        raise ValueError('unsupported flash parameters')
    boot = files['bootloader.bin']
    if boot[2] != modes[mode] or boot[3] != (sizes[size] << 4 | freqs[freq]):
        raise ValueError('merged bootloader flash header disagrees with metadata')
    if max(end for _, end in spans) > int(size[:-2]) * 1024 * 1024:
        raise ValueError('flash parts exceed device size')
    return files, sorted(parts, key=lambda p: p['offset'])


def validate_nrf(files, key=None):
    """Only the app region may be updated; retain filesystem and bootloader."""
    app_start, softdevice = NRF_LAYOUT.get(key, NRF_LAYOUT_DEFAULT)
    uf2 = files[NRF_FILES['uf2']]
    if len(uf2) % 512:
        raise ValueError('invalid UF2 block size')
    blocks = {}
    count = len(uf2) // 512
    for start in range(0, len(uf2), 512):
        magic0, magic1, flags, address, size, number, total, family = struct.unpack_from('<8I', uf2, start)
        if (magic0, magic1, struct.unpack_from('<I', uf2, start + 508)[0]) != (0x0a324655, 0x9e5d5157, 0x0ab16f30):
            raise ValueError('invalid UF2 magic')
        if flags != 0x2000 or family != 0xADA52840:
            raise ValueError('wrong UF2 chip family or flags')
        if (size != 256 or address % 256 or address < app_start or address + size > 0xED000 or
                total != count or number >= count or number in blocks):
            raise ValueError('UF2 outside application region or incomplete blocks')
        blocks[number] = (address, uf2[start + 32:start + 32 + size])
    application = bytearray()
    for number in range(count):
        address, data = blocks[number]
        if address != app_start + len(application):
            raise ValueError('UF2 application is not contiguous')
        application.extend(data)
    try:
        with zipfile.ZipFile(io.BytesIO(files[NRF_FILES['dfu']])) as archive:
            manifest = json.loads(archive.read('manifest.json'))['manifest']
            if set(manifest) - {'application', 'dfu_version'} or 'application' not in manifest:
                raise ValueError('DFU must contain application only')
            app = manifest['application']
            init = app['init_packet_data']
            if init['device_type'] != 82 or init['softdevice_req'] != [softdevice]:
                raise ValueError('DFU target disagrees with pinned nRF52 board bootloader')
            binary, dat = app['bin_file'], app['dat_file']
            if {binary, dat, 'manifest.json'} != set(archive.namelist()) or len(archive.namelist()) != 3:
                raise ValueError('unexpected DFU archive files')
            if any(Path(name).name != name for name in archive.namelist()):
                raise ValueError('unsafe DFU path')
            data = archive.read(binary)
            if not data or len(data) > len(application) or application[:len(data)] != data or any(b != 0 for b in application[len(data):]):
                raise ValueError('DFU application differs from UF2')
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError) as error:
        raise ValueError(f'invalid DFU application archive: {error}') from error


def safe_version(version):
    return isinstance(version, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', version)


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin):
        self.origin = origin

    def redirect_request(self, request, fp, code, message, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if (target.scheme, target.netloc) != self.origin:
            raise ValueError('previous site redirect leaves the trusted origin')
        return super().redirect_request(request, fp, code, message, headers, newurl)


def history_reader(previous_site, previous_site_dir):
    if previous_site and previous_site_dir:
        raise ValueError('choose one previous site source')
    if previous_site:
        parsed = urllib.parse.urlsplit(previous_site)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('previous site must be an HTTPS site URL without credentials/query/fragment')
        base = previous_site.rstrip('/') + '/firmware/'
        opener = urllib.request.build_opener(SameOriginRedirect((parsed.scheme, parsed.netloc)))

        def read(path, initial=False):
            try:
                with opener.open(base + path, timeout=30) as response:
                    data = response.read((1024 * 1024 if initial else 16 * 1024 * 1024) + 1)
            except urllib.error.HTTPError as error:
                if initial and error.code in (403, 404):
                    return None
                raise ValueError(f'cannot fetch previous history: HTTP {error.code}') from error
            except urllib.error.URLError as error:
                raise ValueError(f'cannot fetch previous history: {error.reason}') from error
            if len(data) > (1024 * 1024 if initial else 16 * 1024 * 1024):
                raise ValueError('previous history response exceeds size bound')
            return data
        return read
    if previous_site_dir:
        if Path(previous_site_dir).is_symlink():
            raise ValueError('unsafe previous history directory symlink')
        root = Path(previous_site_dir) / 'firmware'

        def read(path, initial=False):
            target = root / path
            current = root
            if root.is_symlink():
                raise ValueError('unsafe previous history path')
            for component in Path(path).parts:
                current = current / component
                if current.is_symlink():
                    raise ValueError('unsafe previous history symlink path')
            if initial and not target.exists():
                return None
            if not target.is_file():
                raise ValueError(f'missing previous history asset: {path}')
            return target.read_bytes()
        return read
    return None


# Builds that must not be offered again. Before v0.7.1 the firmware for the ESP32-S3 boards with the built-in USB
# port lost bytes on the way to the host.
WITHDRAWN_BEFORE = {'lilygo_t_beam_supreme': (0, 7, 1), 'lilygo_t3_s3': (0, 7, 1)}


def withdrawn(version, key):
    tag = re.match(r'v(\d+)\.(\d+)\.(\d+)', version)
    return bool(tag) and key in WITHDRAWN_BEFORE and tuple(map(int, tag.groups())) < WITHDRAWN_BEFORE[key]


def retain_history(output, current_version, previous_site, previous_site_dir, allow_development):
    read = history_reader(previous_site, previous_site_dir)
    if read is None:
        return []
    data = read('catalog.json', initial=True)
    if data is None:
        return []
    catalog = json.loads(data)
    if catalog.get('schema') != 1 or not isinstance(catalog.get('releases'), list):
        raise ValueError('invalid previous history catalog')
    releases = catalog['releases']
    if len(releases) > 5:
        raise ValueError('previous history exceeds five releases')
    seen = set()
    retained = []
    # Keep tag releases ahead of older main snapshots when bounded history fills.
    candidates = sorted(releases, key=lambda r: str(r.get('version', '')).startswith('main-'))
    for release in candidates:
        version = release.get('version')
        if not safe_version(version) or version in seen:
            raise ValueError('invalid or duplicate previous history version')
        seen.add(version)
        keep = version != current_version and len(retained) < 4
        if not re.fullmatch(r'[0-9a-f]{40}', release.get('commit', '')):
            raise ValueError('invalid previous history commit')
        if type(release.get('development', False)) is not bool or (release.get('development', False) and not allow_development):
            raise ValueError('development history cannot be published as release firmware')
        boards = release.get('boards')
        if not isinstance(boards, list) or not boards or len(boards) > len(BOARDS):
            raise ValueError('invalid previous history boards')
        board_ids = set()
        for board in boards:
            key = board.get('id')
            if key not in BOARDS or key in board_ids:
                raise ValueError('unknown or duplicate previous board metadata')
            board_ids.add(key)
            name, chip, radio, tested = BOARDS[key]
            family = 'nrf52' if chip == 'nrf52840' else 'esp32'
            if any(board.get(k) != v for k, v in {'name': name, 'chip': CHIPS[chip], 'family': family,
                                                  'radio': radio, 'hardwareTested': tested}.items()):
                raise ValueError('previous board chip or metadata mismatch')
            parts = board.get('parts')
            descriptors = board.get('files')
            if not isinstance(parts, list) or not isinstance(descriptors, dict):
                raise ValueError('invalid previous board files')
            if set(descriptors) != ({'app'} if family == 'esp32' else {'dfu', 'uf2'}):
                raise ValueError('invalid previous board file roles')
            expected_names = ESP_FILES if family == 'esp32' else set(NRF_FILES.values())
            blobs = {}
            assets = parts + list(descriptors.values())
            for asset in assets:
                path = asset.get('path', '')
                components = path.split('/')
                if (len(components) != 3 or components[:2] != [version, key] or
                        components[2] not in expected_names or path != '/'.join(components)):
                    raise ValueError('unsafe previous history asset path')
                if (type(asset.get('size')) is not int or not 0 < asset['size'] <= 16 * 1024 * 1024 or
                        not re.fullmatch(r'[0-9a-f]{64}', asset.get('sha256', ''))):
                    raise ValueError('invalid previous history asset hash or size')
                filename = components[2]
                if filename not in blobs:
                    blobs[filename] = read(path)
                blob = blobs[filename]
                if fingerprint(blob) != {k: asset[k] for k in ('sha256', 'size')}:
                    raise ValueError('previous history asset hash or size mismatch')
            if set(blobs) != expected_names:
                raise ValueError('missing previous history board files')
            if family == 'esp32':
                if len(parts) != 4 or len({p['path'] for p in parts}) != 4:
                    raise ValueError('invalid previous ESP32 parts')
                metadata = {k: board.get(k) for k in ('flashMode', 'flashFrequency', 'flashSize', 'partitionTableOffset')}
                metadata['parts'] = [{'name': Path(p['path']).name, 'offset': p.get('offset')} for p in parts]
                metadata['mergedOffset'] = 0
                # Revalidate all retained split parts with the same partition/chip
                # checks as freshly built firmware, without publishing a merged image.
                merged = bytearray(b'\xff' * (16 * 1024 * 1024))
                end = 0
                for part in metadata['parts']:
                    offset = part['offset']
                    blob = blobs[part['name']]
                    if type(offset) is not int or offset < 0 or offset + len(blob) > len(merged):
                        raise ValueError('invalid previous flash part offset')
                    merged[offset:offset + len(blob)] = blob
                    end = max(end, offset + len(blob))
                with tempfile.TemporaryDirectory(prefix='history-check-') as check:
                    directory = Path(check)
                    check_files = {**blobs, 'merged.bin': bytes(merged[:end])}
                    metadata['files'] = {name: fingerprint(blob) for name, blob in check_files.items()}
                    for filename, blob in check_files.items():
                        (directory / filename).write_bytes(blob)
                    esp_parts(directory, metadata, chip)
                if descriptors['app']['path'] != f'{version}/{key}/reticulum-c-mcu.bin':
                    raise ValueError('previous app descriptor is not application firmware')
            else:
                if parts or any(descriptors[role]['path'] != f'{version}/{key}/{filename}' for role, filename in NRF_FILES.items()):
                    raise ValueError('invalid previous nRF file roles')
                validate_nrf(blobs, key)
            # Validate every old asset, including the oldest release dropped by
            # the bound, so corruption never silently discards established history.
            if keep and not withdrawn(version, key):
                dest = output / version / key
                dest.mkdir(parents=True)
                for filename, blob in blobs.items():
                    (dest / filename).write_bytes(blob)
        if keep:
            retained.append({**release, 'boards': [b for b in release['boards'] if not withdrawn(version, b['id'])]})
    return retained


def stage(firmware_root, site_dir, version, commit, allow_development=False, require_all=False,
          previous_site=None, previous_site_dir=None):
    if not safe_version(version):
        raise ValueError('unsafe version label')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('commit must be a complete Git SHA')
    firmware_root, site_dir = Path(firmware_root), Path(site_dir)
    if not firmware_root.is_dir():
        raise ValueError('firmware root is missing')
    builds = [p for p in sorted(firmware_root.iterdir()) if p.is_dir()]
    if not builds:
        raise ValueError('no firmware board directories')
    ids = [p.name.lower() for p in builds]
    if len(set(ids)) != len(ids) or any(key not in BOARDS for key in ids):
        raise ValueError('unknown or duplicate board directory')
    if require_all and set(ids) != set(BOARDS):
        raise ValueError('incomplete firmware set: all nine boards are required')
    site_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.firmware-', dir=site_dir) as temp:
        output = Path(temp)
        boards = []
        for directory in builds:
            if directory.is_symlink():
                raise ValueError('unsafe board directory path')
            key = directory.name.lower()
            name, chip, radio, tested = BOARDS[key]
            info = {}
            for line in read_file(directory, 'build-info.txt').decode().splitlines():
                if ':' in line and not line.startswith(' '):
                    k, v = line.split(':', 1)
                    info[k.strip()] = v.strip()
            if info.get('dev-wifi-defaults') != 'no':
                raise ValueError(f'dev-wifi-defaults must be no: {key}')
            if info.get('commit') != commit and not (allow_development and info.get('commit') == commit + '-dirty'):
                raise ValueError(f'source commit mismatch: {key}')
            if info.get('firmware', '').lower() != 'platformio-' + key:
                raise ValueError(f'firmware board provenance mismatch: {key}')
            metadata = json.loads(read_file(directory, 'flash.json'))
            family = 'nrf52' if chip == 'nrf52840' else 'esp32'
            if metadata.get('schema') != 1 or metadata.get('chip') != chip or metadata.get('family') != family:
                raise ValueError(f'wrong chip or metadata schema: {key}')
            if family == 'esp32':
                files, parts = esp_parts(directory, metadata, chip)
            else:
                files = {file: checked_file(directory, metadata, file) for file in NRF_FILES.values()}
                validate_nrf(files, key)
                parts = []
            dest = output / version / key
            dest.mkdir(parents=True)
            published = {}
            for filename, data in files.items():
                (dest / filename).write_bytes(data)
                published[filename] = {'path': f'{version}/{key}/{filename}', **fingerprint(data)}
            board = {'id': key, 'name': name, 'family': family, 'chip': CHIPS[chip],
                     'radio': radio, 'hardwareTested': tested,
                     'files': ({'app': published['reticulum-c-mcu.bin']} if family == 'esp32' else
                               {role: published[file] for role, file in NRF_FILES.items()}),
                     'parts': [{'offset': p['offset'], **published[p['name']]} for p in parts]}
            if family == 'esp32':
                for k in ('flashMode', 'flashFrequency', 'flashSize', 'partitionTableOffset'):
                    board[k] = metadata[k]
            boards.append(board)
        history = retain_history(output, version, previous_site, previous_site_dir, allow_development)
        catalog = {'schema': 1, 'releases': [{'version': version, 'commit': commit,
                   'development': allow_development, 'boards': boards}, *history]}
        (output / 'catalog.json').write_text(json.dumps(catalog, indent=2) + '\n')
        final = site_dir / 'firmware'
        if final.is_symlink():
            raise ValueError('unsafe firmware output directory')
        if final.exists():
            shutil.rmtree(final)
        shutil.move(str(output), final)
    return catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware-root', required=True, type=Path)
    parser.add_argument('--site-dir', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--allow-development', action='store_true', help='explicitly label local development staging')
    parser.add_argument('--require-all', action='store_true', help='require all nine supported boards')
    previous = parser.add_mutually_exclusive_group()
    previous.add_argument('--previous-site', help='trusted HTTPS Pages site URL to retain history from')
    previous.add_argument('--previous-site-dir', type=Path, help='previous site directory containing firmware/catalog.json')
    args = parser.parse_args()
    try:
        catalog = stage(args.firmware_root, args.site_dir, args.version, args.commit,
                        args.allow_development, args.require_all, args.previous_site, args.previous_site_dir)
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, f'firmware staging refused: {error}\n')
    print(f"staged {len(catalog['releases'][0]['boards'])} boards for {args.version} ({args.commit})")


if __name__ == '__main__':
    main()
