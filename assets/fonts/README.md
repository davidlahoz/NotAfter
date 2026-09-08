# Font sources

The files the app actually serves live in `app/static/fonts/` and are
**subsets** built from the sources here. Nothing is fetched at run time — the
whole point is that the app serves every asset itself.

| Source | Served as | Used for |
|---|---|---|
| `Nabla-Regular.ttf` | `nabla-wordmark.woff2` (~5 KB) | The “No After” wordmark, and nothing else |
| *(downloaded, see below)* | `inter-variable.woff2` (~119 KB) | All body text |

Both are licensed under the SIL Open Font License 1.1; the licences are
served alongside the fonts in `app/static/fonts/`.

## Rebuilding the subsets

    make fonts

Nabla is subset to the eight characters of the wordmark, which is why five
kilobytes buys a chromatic display face. Its `SVG ` table is dropped: the
`COLR`/`CPAL` tables carry the same colour layers and every browser the app
supports reads them.

Inter is subset to Latin and Latin Extended, keeping both variable axes —
`wght` for weights and `opsz` for optical sizing, which is what stops the big
countdown from looking loose. Its source is not committed; `make fonts`
fetches the release, and the version is pinned in the Makefile.
