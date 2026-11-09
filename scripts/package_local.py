"""Create a complete local Windows package without publishing or changing git.

The frontend is required; packaging a lone GUI executable is an error.
"""
import argparse
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]


class Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key in ('src', 'href') and value and not value.startswith(('http:', 'https:', 'data:', '#')):
                self.paths.append(value.split('?', 1)[0].lstrip('/'))


def validate_frontend(frontend):
    index = frontend / 'index.html'
    if not index.is_file():
        raise RuntimeError(f'Missing frontend index: {index}')
    parser = Assets()
    parser.feed(index.read_text(encoding='utf-8'))
    for name in parser.paths:
        if not (frontend / name).is_file():
            raise RuntimeError(f'Missing asset referenced by index.html: {name}')
    if not list((frontend / 'assets').glob('*.js')):
        raise RuntimeError('Frontend JavaScript bundle is missing')
    return parser.paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--frontend-dist', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--version', default='local')
    args = parser.parse_args()
    references = validate_frontend(args.frontend_dist)
    required = ['proxyclaw.exe', 'WinDivert.dll', 'WinDivert64.sys']
    for name in required:
        if not (args.build_dir / name).is_file():
            parser.error(f'Missing runtime file: {args.build_dir / name}')
    if args.output_dir.exists():
        parser.error('Output directory already exists; choose a fresh directory')
    args.output_dir.mkdir(parents=True)
    for name in required:
        shutil.copy2(args.build_dir / name, args.output_dir / name)
    for dll in args.build_dir.glob('*.dll'):
        shutil.copy2(dll, args.output_dir / dll.name)
    shutil.copytree(args.frontend_dist, args.output_dir / 'frontend/dist')
    shutil.copytree(ROOT / 'assets', args.output_dir / 'assets')
    for name in ['LICENSE', 'THIRD_PARTY_NOTICES.md']:
        shutil.copy2(ROOT / name, args.output_dir / name)
    for name in ['README.md', 'README.en.md']:
        shutil.copy2(ROOT / name, args.output_dir / name)
    licenses = args.output_dir / 'licenses'
    licenses.mkdir()
    shutil.copy2(ROOT / 'WinDivert-2.2.2-A/LICENSE', licenses / 'WinDivert-LICENSE.txt')
    shutil.copy2(ROOT / 'src/ui/third_party/WebView2/LICENSE.txt', licenses / 'WebView2-LICENSE.txt')
    if args.config:
        json.loads(args.config.read_text(encoding='utf-8-sig'))
        shutil.copy2(args.config, args.output_dir / 'proxyclaw.json')
    validate_frontend(args.output_dir / 'frontend/dist')
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    metadata = {'application': 'ProxyClaw', 'version': args.version,
                'architecture': 'x64', 'frontend_references': references,
                'sha256': {p.relative_to(args.output_dir).as_posix(): digest(p)
                           for p in args.output_dir.rglob('*') if p.is_file()}}
    (args.output_dir / 'BUILDINFO.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    archive = args.output_dir.parent / (args.output_dir.name + '.zip')
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for file in args.output_dir.rglob('*'):
            if file.is_file():
                bundle.write(file, file.relative_to(args.output_dir.parent))
    print(json.dumps({'package': str(args.output_dir), 'zip': str(archive),
                      'frontend_references_checked': len(references)}))


if __name__ == '__main__':
    main()
