# Common-password denylist

The first 1000 entries (in upstream order) from SecLists `Passwords/Common-Credentials/10k-most-common.txt`, commit `913b327317496d062bcc7cace524aaad8a693be2`. These are publicly known weak-password examples, never application credentials.

Source: https://github.com/danielmiessler/SecLists/blob/913b327317496d062bcc7cace524aaad8a693be2/Passwords/Common-Credentials/10k-most-common.txt

MIT license: see [common-passwords.LICENSE](common-passwords.LICENSE).

Upstream file SHA-256: `68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce`.
Vendored UTF-8/LF file SHA-256: `17044b38f1c16e358db3c11a8eccdfa6b57a91e0ef8c9ea3cb57a920df702588`.

Reviewed for exactly 1000 unique nonempty entries. Matching is case-insensitive, with no trimming or normalization of the actual password. This small list supplements the 12-character minimum; it is not an exhaustive breached-password corpus. Authentication and runtime startup never download a list. Updates require a reviewed commit and refreshed provenance/digests.
