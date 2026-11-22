# Attack Surface

Threat models, defensive only, of systems from the news. Part of **Desk**.
Live: https://ronygralnic.github.io/attack-surface/

Each item: a trailer, the story in a minute, an interactive data-flow diagram with trust boundaries, assets, a STRIDE heat table with threat cards, an attack tree with control toggles, a before/after risk matrix, controls with residual risk, an ATT&CK mapping, takeaways, and a downloadable Threat Model document (Hebrew and English, DOCX and PDF).

## Structure
```
index.html, about.html        home (STRIDE explainer + filtered gallery), about
assets/                       site.css (identity on top of kit), item.js (item renderer), home.js, og.png, favicon.svg
kit/                          shared Desk kit (tokens, RTL type, glossary popovers, theme). Fonts: run kit/fetch-fonts.sh
items/<ID>/                   item.json (source), doc-en.json (English text for the document), generated: data.js, index.html, og.png, dfd-*.png, threat-model-*.{docx,pdf}
items/index.json, items/data.js   gallery index (generated)
tools/                        build_item.py, og.py, build_docs.py, check.py, item-template.html
interview/                    private notes, git-ignored
```

## A new item = a new folder
```
mkdir items/<ID> && write items/<ID>/item.json + doc-en.json
python3 tools/build_item.py <ID>      # validates, writes data.js + index.html, rebuilds the index
python3 tools/og.py <ID>              # Open Graph card
python3 tools/build_docs.py <ID>      # DOCX + PDF, he + en (captures the diagram from the page)
python3 tools/check.py --item <ID>    # 1280/390 × light/dark × http/file:// + interactions + docs
```
Needs Python 3 with `playwright` and `python-docx`, and Google Chrome at /usr/bin/google-chrome.

Works from disk (file://): pages load data through `<script src="data.js">`, never fetch, and every link points to a file.
Analytics: GoatCounter (`attack-surface`), only on `*.github.io`.
