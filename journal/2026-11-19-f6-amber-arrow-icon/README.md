# F6: new app icon, the white "side, then drop" arrow on an amber background

## What I did
- Replaced `icon.svg` with the design the brief describes. The viewBox is still 0 0 100 100 and the output is still 180×180. It has:
  - the 6-stop amber background, top to bottom (#ffd99b → #f48614)
  - a soft glow. The concept was CSS (`circle at 50% 56%`, white .28 fading to 0 at 48%), so I gave the SVG radialGradient a radius of 75: CSS measures to the farthest corner, and √(50²+56²) ≈ 75. The last stop sits at offset .48.
  - one white arrow on the brief's exact path: stroke width 10, round caps and joins, and a vertical #fff → #e4e9ef stroke gradient set in user space (y 29–79, the edges of the stroke).
  - a drop shadow: dy 1.6, blur 1.4, black at .35. I built it from feGaussianBlur, feOffset, feFlood and feComposite instead of feDropShadow, so older librsvg versions render it too.
  - no disc, outline, gloss or rays.
- Rendered `icon.png` with `rsvg-convert -w 180 icon.svg -o icon.png`.
- `static/og.png` showed the old icon, so I redid it. The card has no source file, so I left everything else in it as it was and pasted the new icon over the old one:
  - I measured the old icon box from the pixels: 300×300 at (150, 209), corner radius ≈ 60.
  - I rendered the icon at 300 px (`rsvg-convert -w 300 icon.svg`) and pasted it with an 8× supersampled rounded mask. The script is `og.py` in this folder: `python og.py static/og.png icon300.png`.
  - The old drop shadow under the icon stays, since the shape is the same. I zoomed in on a corner at 4× and found no fringe left from the old navy icon.

## Checks
- I looked at icon.png at 180 px and at a 60 px render. The arrow reads clearly at both sizes.
- Centring: the arrow, stroke included, spans x 15–78 and y 29–79. Its box centre is (46.5, 54), so it sits 3.5 units left and 4 units low of true centre. By eye it still looks centred, because the arrowhead is wider than the bar. I kept the brief's path exactly as written, because the user picked that design from the concept canvas.
- I looked at og.png at full size: the new icon is in place, and the text, nav bar and pinstripes are unchanged.

## Tried and failed
- none

## Not verified
- How the icon looks on a real home screen (iPhone 7 or Safari "Add to Home Screen"). That needs a deploy, and this session must not publish.
- Link previews in iMessage or Discord using the new og.png, for the same reason. Their caches may keep showing the old card for a while after deploy.
