# Bundled data

`eff_large_wordlist.txt` is the EFF Large Wordlist for passphrases (7,776 words,
five-dice index + word, tab-separated), by the Electronic Frontier Foundation,
licensed under [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).
Source: https://www.eff.org/dice. Attribution must appear in the app's About
window and in the CLI's `--licenses` output.

SHA-256: `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`.
eff.org was not reachable from the build environment, so the file came from two
independent GitHub mirrors that agreed byte for byte. Re-check this hash against
the copy on eff.org before the first release.

The wordlist ships in the app bundle and CLI binary. It is never written to the
YubiKey.
