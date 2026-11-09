"""Export the project PNG to Windows ICO and web assets (requires Pillow).

Run: python scripts/export_icon.py
The original generated PNG remains unchanged; exports only resize/encode.
"""
from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SIZES = (16, 20, 24, 32, 40, 48, 64, 96, 128, 256)

def main():
    source = ROOT / 'assets/proxyclaw.png'
    with Image.open(source) as image:
        if image.mode != 'RGBA' or image.width != image.height:
            raise ValueError('The master icon must be a square RGBA PNG')
        image.save(ROOT/'assets/proxyclaw.ico',format='ICO',sizes=[(n,n) for n in SIZES])
        public = ROOT/'frontend/public'; public.mkdir(parents=True,exist_ok=True)
        image.save(public/'favicon.ico',format='ICO',sizes=[(n,n) for n in (16,32,48,64)])
        assets = ROOT/'frontend/src/assets'; assets.mkdir(parents=True,exist_ok=True)
        image.resize((128,128),Image.Resampling.LANCZOS).save(assets/'proxyclaw-icon.png')
    print(f'Exported {source.name}: ICO sizes {SIZES}, favicon and UI PNG')

if __name__ == '__main__':
    main()
