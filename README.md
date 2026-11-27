# Attack Surface

Threat models, defensive only, of systems from the news. Part of **Desk**.
Live: https://ronygralnic.github.io/attack-surface/

Identity: a "night dossier" (dark by default, light theme as classified paper). Each item is a case file built to be read once and learned from:
a short trailer; the story in a minute with a live illustration per paragraph and a fictional cast; a data-flow diagram that builds step by step with
an in-frame inspector and clickable legend; assets with owners and a "what if it's breached" flip; STRIDE threats grouped by component with a reminder
of what each letter means; an attack tree with control toggles and an animated minimal cut; before/after risk matrices side by side with a floating
detail; a coverage grid; a detection rule in a terminal with line notes; ATT&CK tiles; a "method" strip at the head of every section and a
"build it yourself" recap; and a professional Threat Model document (Hebrew and English, DOCX and PDF) with figures.

## Structure
```
index.html, about.html        home (four-question hero, STRIDE cards, seven-step path, case-file gallery), about
assets/                       site.css (identity on top of kit), item.js (item renderer), home.js, og.png, favicon.svg
kit/                          shared Desk kit (tokens, RTL type, glossary popovers, theme). Fonts: run kit/fetch-fonts.sh
items/<ID>/                   item.json (source), doc-en.json (English text for the document), generated: data.js, index.html, og.png, dfd-*.png, threat-model-*.{docx,pdf}
items/index.json, items/data.js   gallery index (generated)
tools/                        build_item.py, og.py, build_docs.py (+ doc_figures.py), check.py, item-template.html
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
Needs Python 3 with `playwright` and `python-docx`, Google Chrome at /usr/bin/google-chrome, and `pdftoppm` (poppler) for document previews.

Works from disk (file://): pages load data through `<script src="data.js">`, never fetch, and every link points to a file.
Analytics: GoatCounter (`attack-surface`), only on `*.github.io`.

## Optional item.json fields (engine v2)
`characters[{id,name,role,color,initials}]` · `minute[{text, scene, voice:{who,text}}]` where scene (or a list of scenes) is
`route | stats | timeline | versus | chat` · `facts[].term` · `dfd.steps[{title,text,add:[node|flow|"zone:<id>"],focus}]` ·
`assets.items[].who/.say` · `mitigations.rule.notes[{line,text}]` · `docs[].preview` · `method{<section>:[3 steps]}` to override the default method strip.
doc-en.json may add `ruleNotes[{line,text}]`.
