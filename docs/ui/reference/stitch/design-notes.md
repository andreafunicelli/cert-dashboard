# Stitch mockup — design reference

The operator produced a mockup of the certificate inventory in Google Stitch
(project *Cert Dashboard Redesign*, screen *Certificate Inventory & Expiry Monitor*). This directory
holds it as a **visual reference**, not as a specification.

- `mockup.png` — the screen as exported from Stitch (2560×4526)
- `mockup.html` — the export, Tailwind + Material Symbols, useful for reading exact values
- `design-notes.md` — this file

## Take from it

| Element | Why it helps | How to land it in this app |
| --- | --- | --- |
| Dark palette with a cyan accent | reads well at night, one accent keeps actions unambiguous | map to the existing token names (`--surface`, `--accent`…), both themes kept |
| Material-3 dark neutrals (`#0b1326` surface, `#171f33` container, `#2d3449` variant) | layered surfaces without borders everywhere | one token per layer, no ad-hoc greys |
| Inter for text, JetBrains Mono for numbers and fingerprints | figures line up, identifiers scan | system stack fallback; monospace only where it earns it |
| Status carried by a left colour bar + word + icon in the row | state visible while scanning vertically | reuse the existing status pill, add the row accent |
| KPI strip above the table | answers "how bad is it" before the list | the four counters we already have, one line, no cards |
| Filter chips showing the active filters | you can see why the list is filtered | chips only when a filter is active |
| Sticky table header, monospaced right-aligned dates | reading a 40-row list | already partially there; make it stick |
| Comfortable row height with two lines maximum | less fatigue than one dense line | 56–64 px, never more |

## Do not take from it

- **Modules that do not exist**: *Mesh Scanner*, *observability*, *Ansible deployment*, *zero-downtime
  canary*, *4-eye approval*, *SCIM*, *cross-tenant drift*, *data residency*, *HSM*. The product has none
  of these. Adding them to the interface would promise features we do not have — the opposite of a
  README you can trust.
- **Three-level left sidebar.** Our navigation has 8 pages; a sidebar with a workspace selector, an
  infrastructure tree and a filter rail adds chrome without adding capability. Card 2 groups the
  navigation into four areas; that is as deep as this product needs.
- **A hero panel above the data.** On the list page the list is the point; the mockup's large
  "Certificate Inventory & Expiry Monitor" block pushes the first row below the fold.
- **Decorative icons in every cell** and the density of the KPI cards: the numbers matter, the framing
  does not.

## Palette, for reference (Material-3 dark, from the Stitch project)

```
surface                #0b1326      on-surface            #dae2fd
surface-container      #171f33      on-surface-variant    #bcc9cd
surface-container-high #222a3d      outline               #869397
surface-variant        #2d3449      outline-variant       #3d494c
primary                #4cd7f6      secondary             #c0c1ff
primary-container      #06b6d4      tertiary              #1bbd85
error                  #ffb4ab      error-container       #93000a
```

Type: Inter (400/500/600/700), JetBrains Mono for labels and figures. Roundness: 4 px.
