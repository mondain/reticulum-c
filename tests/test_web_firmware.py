"""Static firmware publication must preserve identity and reject ambiguous builds."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / '.github/scripts/build-web-flasher.py'
SHA = 'a' * 40


class WebFirmwareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fw = self.root / 'builds'
        self.board = self.fw / 'heltec_wifi_lora_32_V3'
        self.board.mkdir(parents=True)
        self.site = self.root / 'site'
        self.image = bytearray(64)
        self.image[0] = 0xe9
        struct.pack_into('<H', self.image, 12, 9)
        self.image[2:4] = b'\x00\x00'
        table = b''.join(struct.pack('<HBBII16sI', 0x50aa, kind, sub, off, size,
                                     label.encode(), 0) for kind, sub, off, size, label in [
            (1, 2, 0x9000, 0x5000, 'nvs'), (1, 0, 0xe000, 0x2000, 'otadata'),
            (0, 0, 0x10000, 0x100000, 'app0')]) + b'\xff' * 32
        self.files = {'bootloader.bin': bytes(self.image), 'partitions.bin': table,
                      'boot_app0.bin': b'\xff' * 8192, 'reticulum-c-mcu.bin': bytes(self.image)}
        self.parts = [{'name': name, 'offset': off} for name, off in [
            ('bootloader.bin', 0), ('partitions.bin', 0x8000),
            ('boot_app0.bin', 0xe000), ('reticulum-c-mcu.bin', 0x10000)]]
        merged = bytearray(b'\xff' * (0x10000 + len(self.image)))
        for part in self.parts:
            data = self.files[part['name']]
            merged[part['offset']:part['offset'] + len(data)] = data
        # esptool merge_bin patches the bootloader header for the board.
        merged[2:4] = b'\x02\x20'
        self.files['merged.bin'] = bytes(merged)
        self.metadata = {'schema': 1, 'family': 'esp32', 'chip': 'esp32s3',
                         'flashMode': 'dio', 'flashFrequency': '40m', 'flashSize': '4MB',
                         'mergedOffset': 0, 'partitionTableOffset': 0x8000, 'parts': self.parts}
        self.save()

    def save(self):
        for name, data in self.files.items():
            (self.board / name).write_bytes(data)
        self.metadata['files'] = {name: {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                                  for name, data in self.files.items()}
        (self.board / 'flash.json').write_text(json.dumps(self.metadata))
        (self.board / 'build-info.txt').write_text(f'commit: {SHA}\ndev-wifi-defaults: no\nfirmware: platformio-heltec_wifi_lora_32_V3\n')

    def stage(self):
        self.assertTrue(SCRIPT.is_file(), 'firmware staging script is missing')
        spec = importlib.util.spec_from_file_location('web_firmware', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.stage(self.fw, self.site, 'v1-test', SHA)

    def test_publishes_only_split_images_with_patched_bootloader_and_hashes(self):
        (self.board / 'identity.bin').write_bytes(b'secret')
        (self.board / 'build.log').write_text('secret')
        (self.board / 'reticulum-c-mcu.elf').write_bytes(b'secret')
        self.stage()
        base = self.site / 'firmware'
        catalog = json.loads((base / 'catalog.json').read_text())
        board = catalog['releases'][0]['boards'][0]
        self.assertEqual(board['chip'], 'ESP32-S3')
        self.assertEqual(board['radio'], 'SX1262')
        self.assertFalse(board['hardwareTested'])
        self.assertEqual((base / board['parts'][0]['path']).read_bytes()[2:4], b'\x02\x20')
        for part in board['parts']:
            data = (base / part['path']).read_bytes()
            self.assertEqual(part['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(part['size'], len(data))
        self.assertEqual({p.name for p in (base / 'v1-test' / self.board.name.lower()).iterdir()}, set(self.files) - {'merged.bin'})

    def nrf_fixture(self, address=0x26000, family=0xADA52840, board='lilygo_t_echo', softdevice=182):
        import io
        import shutil
        import zipfile
        shutil.rmtree(self.board)
        self.board = self.fw / board
        self.board.mkdir()
        app = bytes(range(250))
        uf2 = struct.pack('<8I', 0x0a324655, 0x9e5d5157, 0x2000, address,
                          256, 0, 1, family) + app + bytes(6) + bytes(220) + struct.pack('<I', 0x0ab16f30)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('manifest.json', json.dumps({'manifest': {'application': {
                'bin_file': 'firmware.bin', 'dat_file': 'firmware.dat',
                'init_packet_data': {'device_type': 82, 'softdevice_req': [softdevice]}}}}))
            z.writestr('firmware.bin', app)
            z.writestr('firmware.dat', bytes(14))
        self.files = {'reticulum-c-mcu-dfu.zip': archive.getvalue(), 'reticulum-c-mcu.uf2': uf2}
        self.metadata = {'schema': 1, 'family': 'nrf52', 'chip': 'nrf52840'}
        self.save()
        (self.board / 'build-info.txt').write_text(f'commit: {SHA}\ndev-wifi-defaults: no\nfirmware: platformio-{board}\n')

    def test_nrf52_publishes_dfu_and_uf2_only(self):
        self.nrf_fixture()
        self.stage()
        catalog = json.loads((self.site / 'firmware/catalog.json').read_text())
        board = catalog['releases'][0]['boards'][0]
        self.assertEqual(set(board['files']), {'dfu', 'uf2'})
        self.assertTrue(board['hardwareTested'])
        self.assertEqual(board['chip'], 'nRF52840')
        self.assertEqual(board['parts'], [])

    def test_xiao_uses_the_s140_7_layout(self):
        self.nrf_fixture(address=0x27000, board='seeed_xiao_nrf52840_wio', softdevice=0x0123)
        self.stage()
        catalog = json.loads((self.site / 'firmware/catalog.json').read_text())
        self.assertEqual(catalog['releases'][0]['boards'][0]['id'], 'seeed_xiao_nrf52840_wio')

    def test_xiao_rejects_the_s140_6_layout(self):
        self.nrf_fixture(address=0x26000, board='seeed_xiao_nrf52840_wio', softdevice=182)
        with self.assertRaisesRegex(ValueError, 'UF2|DFU|contiguous'):
            self.stage()

    def test_rejects_nrf_uf2_that_overwrites_identity_storage(self):
        self.nrf_fixture(address=0xED000)
        with self.assertRaisesRegex(ValueError, 'UF2|application'):
            self.stage()

    def test_rejects_nrf_uf2_wrong_family(self):
        self.nrf_fixture(family=0x12345678)
        with self.assertRaisesRegex(ValueError, 'UF2|family'):
            self.stage()

    def test_rejects_dfu_that_disagrees_with_uf2(self):
        self.nrf_fixture()
        import io
        import zipfile
        archive = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(self.files['reticulum-c-mcu-dfu.zip'])) as original:
            with zipfile.ZipFile(archive, 'w') as changed:
                for name in original.namelist():
                    changed.writestr(name, b'wrong app' if name == 'firmware.bin' else original.read(name))
        self.files['reticulum-c-mcu-dfu.zip'] = archive.getvalue()
        self.save()
        (self.board / 'build-info.txt').write_text(f'commit: {SHA}\ndev-wifi-defaults: no\nfirmware: platformio-lilygo_t_echo\n')
        with self.assertRaisesRegex(ValueError, 'DFU|UF2'):
            self.stage()

    def test_rejects_missing_file(self):
        (self.board / 'bootloader.bin').unlink()
        with self.assertRaisesRegex(ValueError, 'bootloader.bin'):
            self.stage()

    def test_rejects_tampered_file(self):
        (self.board / 'bootloader.bin').write_bytes(b'bad')
        with self.assertRaisesRegex(ValueError, 'hash|size'):
            self.stage()

    def test_rejects_credential_build(self):
        (self.board / 'build-info.txt').write_text(f'commit: {SHA}\ndev-wifi-defaults: yes\n')
        with self.assertRaisesRegex(ValueError, 'credential|dev-wifi'):
            self.stage()

    def test_rejects_mixed_commit(self):
        (self.board / 'build-info.txt').write_text(f'commit: {"b" * 40}\ndev-wifi-defaults: no\n')
        with self.assertRaisesRegex(ValueError, 'commit'):
            self.stage()

    def test_rejects_nvs_overlap(self):
        self.parts[2]['offset'] = 0x9000
        self.save()
        with self.assertRaisesRegex(ValueError, 'NVS|partition|merged'):
            self.stage()

    def test_rejects_wrong_chip(self):
        self.metadata['chip'] = 'esp32'
        self.save()
        with self.assertRaisesRegex(ValueError, 'chip'):
            self.stage()

    def test_rejects_traversal(self):
        self.parts[0]['name'] = '../identity.bin'
        self.save()
        with self.assertRaisesRegex(ValueError, 'file|path|part'):
            self.stage()

    def test_failed_validation_keeps_existing_catalog(self):
        self.stage()
        catalog = self.site / 'firmware/catalog.json'
        before = catalog.read_bytes()
        (self.board / 'reticulum-c-mcu.bin').write_bytes(b'broken')
        with self.assertRaisesRegex(ValueError, 'hash|size'):
            self.stage()
        self.assertEqual(catalog.read_bytes(), before)

    def test_rejects_symlinked_asset(self):
        target = self.root / 'outside.bin'
        target.write_bytes(self.files['bootloader.bin'])
        (self.board / 'bootloader.bin').unlink()
        (self.board / 'bootloader.bin').symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.stage()

    def test_rejects_merged_mismatch_even_when_hashes_match(self):
        merged = bytearray(self.files['merged.bin'])
        merged[0x10000 + 30] ^= 1
        self.files['merged.bin'] = bytes(merged)
        self.save()
        with self.assertRaisesRegex(ValueError, 'merged image mismatch'):
            self.stage()

    def test_rejects_patched_header_that_disagrees_with_flash_parameters(self):
        self.metadata['flashFrequency'] = '80m'
        self.save()
        with self.assertRaisesRegex(ValueError, 'header'):
            self.stage()

    def history_stage(self, version, previous=None, previous_url=None):
        spec = importlib.util.spec_from_file_location('web_firmware', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.stage(self.fw, self.site, version, SHA,
                            previous_site_dir=previous, previous_site=previous_url)

    def test_history_retains_and_bounds_verified_assets(self):
        self.stage()
        for number in range(7):
            self.history_stage(f'v{number}', self.site)
        releases = json.loads((self.site / 'firmware/catalog.json').read_text())['releases']
        self.assertEqual([r['version'] for r in releases], ['v6', 'v5', 'v4', 'v3', 'v2'])
        self.assertEqual({p.name for p in (self.site / 'firmware').iterdir()},
                         {'catalog.json', 'v6', 'v5', 'v4', 'v3', 'v2'})
        for release in releases:
            for part in release['boards'][0]['parts']:
                self.assertEqual(hashlib.sha256((self.site / 'firmware' / part['path']).read_bytes()).hexdigest(), part['sha256'])

    def test_history_corrupt_asset_preserves_catalog(self):
        self.stage()
        catalog = self.site / 'firmware/catalog.json'
        before = catalog.read_bytes()
        (self.site / 'firmware/v1-test/heltec_wifi_lora_32_v3/bootloader.bin').write_bytes(b'bad')
        with self.assertRaisesRegex(ValueError, 'hash|size'):
            self.history_stage('v2', self.site)
        self.assertEqual(catalog.read_bytes(), before)

    def test_history_unsafe_path_rejected(self):
        self.stage()
        path = self.site / 'firmware/catalog.json'
        catalog = json.loads(path.read_text())
        catalog['releases'][0]['boards'][0]['parts'][0]['path'] = '../secret.bin'
        path.write_text(json.dumps(catalog))
        with self.assertRaisesRegex(ValueError, 'path'):
            self.history_stage('v2', self.site)

    def test_history_wrong_chip_rejected(self):
        self.stage()
        path = self.site / 'firmware/catalog.json'
        catalog = json.loads(path.read_text())
        catalog['releases'][0]['boards'][0]['chip'] = 'ESP32'
        path.write_text(json.dumps(catalog))
        with self.assertRaisesRegex(ValueError, 'chip|metadata'):
            self.history_stage('v2', self.site)

    def test_history_duplicate_version_replaced(self):
        self.stage()
        catalog = self.history_stage('v1-test', self.site)
        self.assertEqual(len(catalog['releases']), 1)

    def test_history_initial_404_is_empty(self):
        from unittest.mock import patch
        from urllib.error import HTTPError
        # The network boundary is mocked; the actual 404 handling and staging execute.
        with patch('urllib.request.OpenerDirector.open', side_effect=HTTPError('https://example.com', 404, 'missing', {}, None)):
            catalog = self.history_stage('v2', previous_url='https://example.com/project/')
        self.assertEqual([r['version'] for r in catalog['releases']], ['v2'])

    def test_history_network_failure_must_not_erase_history(self):
        from unittest.mock import patch
        from urllib.error import URLError
        self.stage()
        before = (self.site / 'firmware/catalog.json').read_bytes()
        with patch('urllib.request.OpenerDirector.open', side_effect=URLError('offline')):
            with self.assertRaisesRegex(ValueError, 'history|previous|fetch'):
                self.history_stage('v2', previous_url='https://example.com/project/')
        self.assertEqual((self.site / 'firmware/catalog.json').read_bytes(), before)

    def test_history_symlink_asset_rejected(self):
        self.stage()
        asset = self.site / 'firmware/v1-test/heltec_wifi_lora_32_v3/bootloader.bin'
        external = self.root / 'external.bin'
        external.write_bytes(asset.read_bytes())
        asset.unlink()
        asset.symlink_to(external)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.history_stage('v2', self.site)

    def test_history_refuses_http_and_external_redirect(self):
        with self.assertRaisesRegex(ValueError, 'HTTPS'):
            self.history_stage('v2', previous_url='http://example.com/project/')
        import urllib.request
        spec = importlib.util.spec_from_file_location('web_firmware', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        handler = module.SameOriginRedirect(('https', 'example.com'))
        with self.assertRaisesRegex(ValueError, 'origin'):
            handler.redirect_request(urllib.request.Request('https://example.com/old'),
                                     None, 302, 'redirect', {}, 'https://other.example/new')

    def test_history_retains_tags_before_old_main_snapshots(self):
        self.stage()
        for version in ('main-0001', 'v2', 'main-0002', 'main-0003', 'main-0004'):
            self.history_stage(version, self.site)
        releases = self.history_stage('main-0005', self.site)['releases']
        self.assertEqual([r['version'] for r in releases], ['main-0005', 'v2', 'v1-test', 'main-0004', 'main-0003'])

    def test_history_withdraws_builds_known_to_lose_data(self):
        # releases before v0.7.1 had firmware for the two ESP32-S3 native USB boards that lost bytes to the host
        import shutil
        for name in ('lilygo_t_beam_supreme', 'lilygo_t3_s3'):
            other = self.fw / name
            shutil.copytree(self.board, other)
            info = other / 'build-info.txt'
            info.write_text(info.read_text().replace('platformio-heltec_wifi_lora_32_V3', 'platformio-' + name))
        everything = ['heltec_wifi_lora_32_v3', 'lilygo_t3_s3', 'lilygo_t_beam_supreme']
        self.history_stage('v0.7.0')
        self.history_stage('v0.7.1', self.site)
        releases = self.history_stage('main-0001', self.site)['releases']
        boards = {r['version']: sorted(b['id'] for b in r['boards']) for r in releases}
        self.assertEqual(boards, {'main-0001': everything, 'v0.7.1': everything,
                                  'v0.7.0': ['heltec_wifi_lora_32_v3']})
        self.assertEqual(sorted(p.name for p in (self.site / 'firmware/v0.7.0').iterdir()), ['heltec_wifi_lora_32_v3'])
        # and they stay out when the history is carried forward again
        releases = self.history_stage('main-0002', self.site)['releases']
        self.assertEqual([sorted(b['id'] for b in r['boards']) for r in releases if r['version'] == 'v0.7.0'],
                         [['heltec_wifi_lora_32_v3']])

    def test_rejects_unsafe_version(self):
        self.stage()
        spec = importlib.util.spec_from_file_location('web_firmware', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with self.assertRaisesRegex(ValueError, 'version'):
            module.stage(self.fw, self.site, '../escape', SHA)


if __name__ == '__main__':
    unittest.main()
