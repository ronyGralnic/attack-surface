# Desk kit

Shared base for every Desk site (Blueprint, After Action, Attack Surface, Decision Log, Hidden Algorithm, Teardown).
Each site copies this folder to `kit/` and builds its own identity on top, in `assets/site.css`.

| File | What it gives you |
|---|---|
| `kit.css` | Tokens (light + dark via `[data-theme]`), RTL Hebrew typography, header/footer, buttons, chips, cards, callouts, bridges, glossary popovers, code blocks, stat tiles, tables, print rules |
| `fonts.css` + `fonts/` | Self-hosted Heebo (variable), Frank Ruhl Libre 400/700, IBM Plex Mono 400/600. Hebrew + Latin subsets. All OFL |
| `kit.js` | `Desk.h` DOM builder, `Desk.rich` inline markup (`**bold**`, `[[termId]]`, `[[termId|label]]`), glossary popovers (bottom sheet ≤600px, Esc closes, focus returns), theme toggle, copy buttons, GoatCounter (production host only), date helpers |
| `theme-boot.html` | Inline snippet for the top of `<head>`: sets the theme before first paint |
| `og-template.html` | 1200×630 Open Graph card. Fill with `window.fill({site,badge,title,sub,left,right,accent})` and screenshot |

## Conventions
- Pages are `lang="he" dir="rtl"`. Code, URLs and numbers that must read LTR get `dir="ltr"` or `.ltr`.
- Light/dark: only `[data-theme="dark"]` overrides tokens. Never hard-code colors in components; use tokens.
- Every interactive component must work with keyboard and be readable at 390px with no horizontal page scroll.
- Glossary entries: `{ term, en, def, example }`. Every term is defined before (or at) first use.
- Storage is a convenience only (`desk-theme`), always wrapped in try/catch.
