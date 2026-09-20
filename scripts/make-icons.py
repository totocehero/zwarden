"""
Derives the toolbar icon variants from the one drawing.

    python3 scripts/make-icons.py

Reads `public/images/icon{16,32,48,128}.png` — the white padlock — and writes
two derivatives next to each:

  * `-dark`    the same drawing in the application's dark colour, for a light
               toolbar. `chrome.action.setIcon` swaps to it once the service
               worker has read the colour scheme (`src/shared/theme.ts`).
  * `-outline` the white drawing with a dark rim, readable on either background.
               Used where no swap is possible: `action.default_icon`, which
               Chrome paints between launching the browser and waking the worker,
               and `manifest.icons`, which accepts no theme variant at all.

Not part of the build, and deliberately not on the npm side: it runs once when
the drawing changes, and needs Pillow, which has no business in an extension's
dependency tree. Regenerating is idempotent in the only sense that matters: the
`-dark` files it writes are pixel-identical to the committed ones. The bytes
differ, because two PNG encoders rarely agree on compression — which is why the
check worth running is on the pixels, not on a checksum.

The rim is dilated in place, so the glyph keeps its exact size and position and
the swap from the outlined icon to the themed one moves nothing. The one
consequence, stated rather than hidden: the drawing sits flush against the
bottom of its canvas, so the rim is clipped along that single edge. The shape
reads regardless — the bottom of a padlock is not where the eye finds it.
"""

from PIL import Image, ImageFilter

SIZES = (16, 32, 48, 128)

# The application's background, so the dark drawing belongs to the same palette
# as the popup it opens.
DARK = (0x1C, 0x1F, 0x26, 0xFF)

# The rim, in pixels, at each size: one device pixel at 16, and the same
# apparent weight at every multiple of it.
RIM = {16: 1, 32: 2, 48: 3, 128: 8}

# The mask is dilated at this multiple of the icon's own resolution, then scaled
# back down: a rim computed at 1:1 has visibly square corners at 16 pixels.
SUPERSAMPLE = 4


def recolour(image: Image.Image, colour: tuple[int, int, int, int]) -> Image.Image:
    """The same drawing in another colour: only the RGB changes, alpha is kept."""
    out = Image.new("RGBA", image.size, colour)
    out.putalpha(image.getchannel("A"))
    return out


def rim(image: Image.Image, width: int, colour: tuple[int, int, int, int]) -> Image.Image:
    """The drawing's silhouette, grown by `width` pixels, in `colour`."""
    w, h = image.size
    mask = image.getchannel("A").resize((w * SUPERSAMPLE, h * SUPERSAMPLE), Image.NEAREST)
    grown = mask.filter(ImageFilter.MaxFilter(2 * width * SUPERSAMPLE + 1))
    shape = Image.new("RGBA", (w, h), colour)
    shape.putalpha(grown.resize((w, h), Image.LANCZOS))
    return shape


for size in SIZES:
    source = Image.open(f"public/images/icon{size}.png").convert("RGBA")

    recolour(source, DARK).save(f"public/images/icon{size}-dark.png")

    outlined = Image.alpha_composite(rim(source, RIM[size], DARK), source)
    outlined.save(f"public/images/icon{size}-outline.png")

    print(f"icon{size}: -dark and -outline written (rim {RIM[size]}px)")
