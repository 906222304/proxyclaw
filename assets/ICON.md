# ProxyClaw icon

The transparent master image is `proxyclaw.png`, generated with the built-in imagegen tool. Native resolution: 1254 × 1254 RGBA. It is the source for the Windows application/tray icon, frontend title bar, browser favicon, and README mark.

Generation used the built-in tool with `transparent_background: true`. Exact prompt:

> Use case: logo-brand. Asset type: a new premium high-resolution square Windows desktop application icon for ProxyClaw, a process-level network proxy and routing tool. Create one original cohesive emblem: a stylized compact geometric claw with three thick curved talons gently holding a single central network node; the negative space between the talons suggests branching traffic routes. Bold, simple, highly recognizable silhouette, professional developer-tool identity. Match the application's slate/dark neutral and blue interface: saturated electric blue merging into restrained cyan highlights, with subtle dimensional polished enamel shading, precise crisp edges, no tiny thin lines. Centered front-on mark, roughly 82% of the square canvas, generous equal padding, isolated on a genuinely transparent background with alpha. Very high resolution, aim for 2048x2048 or highest available native square resolution. Design must remain recognizable at 16, 24 and 32 pixels. One icon only, no app mockup, no icon grid, no tile or backdrop, no text, no letters, no slogan, no watermark, no shield, no padlock, no animal face, no severed claw marks. This is a visual identity, not a functional diagram.

Run `python scripts/export_icon.py` (Pillow required) to export Windows ICO sizes 16, 20, 24, 32, 40, 48, 64, 96, 128, and 256 pixels, plus the favicon and 128-pixel frontend PNG. Export only resizes/encodes the image; the master remains unchanged.
