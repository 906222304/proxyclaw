"""Restore pinned, checksum-verified dependencies for a clean Windows build."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [
    ('quill', '7.5.0', 'quill.tar.gz', 'quill-7.5.0/include', 'quill::quill',
     'https://codeload.github.com/odygrd/quill/tar.gz/refs/tags/v7.5.0',
     '18846d7c50f2ffe753661b204004fac2df9143e59cf150ecbe77315bc0b232c4'),
    ('nlohmann_json', '3.12.0', 'json.tar.gz', 'json-3.12.0/include', 'nlohmann_json::nlohmann_json',
     'https://codeload.github.com/nlohmann/json/tar.gz/refs/tags/v3.12.0',
     '4b92eb0c06d10683f7447ce9406cb97cd4b453be18d7279320f7b2f025c10187'),
    ('httplib', '0.20.0', 'httplib.tar.gz', 'cpp-httplib-0.20.0', 'httplib::httplib',
     'https://codeload.github.com/yhirose/cpp-httplib/tar.gz/refs/tags/v0.20.0',
     '18064587e0cc6a0d5d56d619f4cbbcaba47aa5d84d86013abbd45d95c6653866'),
    ('asio', '1.30.2', 'asio.tar.gz', 'asio-asio-1-30-2/asio/include', 'asio::asio',
     'https://codeload.github.com/chriskohlhoff/asio/tar.gz/refs/tags/asio-1-30-2',
     '755bd7f85a4b269c67ae0ea254907c078d408cce8e1a352ad2ed664d233780e8'),
]
WINDIVERT_URL = 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'
WINDIVERT_SHA256 = '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15'
WEBVIEW_SHA256 = 'ef128016dd1e51c59178c827ed5b8aa3322c57afa8675d930f8109505542ad74'


def verify(path, expected):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError(f'SHA256 mismatch for {path.name}: {actual}')


def acquire(cache, name, url, sha256):
    path = cache / name
    if not path.exists():
        request = urllib.request.Request(url, headers={'User-Agent': 'ProxyClaw-release-build'})
        with urllib.request.urlopen(request, timeout=120) as response:
            path.write_bytes(response.read())
    verify(path, sha256)
    return path


def extract_zip(archive, target):
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.namelist():
            if not (target / member).resolve().is_relative_to(target.resolve()):
                raise RuntimeError(f'Archive path escapes destination: {member}')
        bundle.extractall(target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, default=ROOT / 'build/release-deps')
    parser.add_argument('--cache-dir', type=Path)
    args = parser.parse_args()
    destination = args.destination.resolve()
    cache = (args.cache_dir or destination / 'downloads').resolve()
    destination.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    for name, version, filename, include, target, url, sha256 in SOURCES:
        archive = acquire(cache, filename, url, sha256)
        with tarfile.open(archive) as bundle:
            bundle.extractall(destination, filter='data')
        include_path = destination / include
        if not include_path.is_dir():
            raise RuntimeError(f'Missing extracted include directory: {include_path}')
        config = destination / 'prefix/lib/cmake' / name / (name + 'Config.cmake')
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(f'add_library({target} INTERFACE IMPORTED)\n'
                          f'set_target_properties({target} PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "{include_path.as_posix()}")\n',
                          encoding='utf-8')
        print(f'Prepared {name} {version}', flush=True)
    windivert = acquire(cache, 'WinDivert-2.2.2-A.zip', WINDIVERT_URL, WINDIVERT_SHA256)
    extract_zip(windivert, destination)
    webview = ROOT / 'src/ui/third_party/webview2.nupkg'
    verify(webview, WEBVIEW_SHA256)
    extract_zip(webview, destination / 'webview2')
    for name in ('WinDivert.dll', 'WinDivert.lib', 'WinDivert64.sys'):
        if not (destination / 'WinDivert-2.2.2-A/x64' / name).is_file():
            raise RuntimeError(f'Missing WinDivert runtime/import library: {name}')
    print(json.dumps({'prefix': str(destination / 'prefix'),
                      'webview2': str(destination / 'webview2'),
                      'windivert': str(destination / 'WinDivert-2.2.2-A/x64')}))


if __name__ == '__main__':
    main()
