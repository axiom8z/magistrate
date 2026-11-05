# Secret scanner: S1 and S2

**Both failure lines from DESIGN section 8 were crossed.** Known-format recall was 89.81%, under the 95% line. False hits were 1.1691 per 1,000 strings, over the line of 1. Each set was scored once, against the frozen rule table `2d687b53f1316ea3d84295868a8d7424169bd7eef077ee2d9d75cbd71a359004`, and nothing was changed to improve either number. `score.out` holds the tables exactly as printed, with every miss and false hit by case ID.

## Who wrote the sets

The sets are self-written, so they aren't independent. They were written by a fresh AI session that never saw the patterns: it didn't open or search `internal/secrets`, and it saw only `go doc`. This is the test method. The session wrote each format from vendor docs where they publish one, and from public knowledge where they don't. It didn't open gitleaks' rules or test cases. But the rule table derives from gitleaks, those rules are public, and the session remembered some of them, so it was blind to this table and not to its public source.

The order was: record the hashes (`hashes.out`), generate (`generate.out`), scan once, score once. No script changed after the hashes were recorded.

## Results

| S1, fake credentials | Cases | Blocked | Recall | Wilson 95% |
|---|---|---|---|---|
| **All** | 34,080 | 30,608 | **89.81%** | 89.48-90.12% |
| plain | 7,200 | 6,480 | 90.00% | 89.28-90.67% |
| percent | 4,455 | 3,939 | 88.41% | 87.44-89.32% |
| base64 | 5,160 | 4,652 | 90.15% | 89.31-90.93% |
| hex | 4,305 | 3,873 | 89.96% | 89.03-90.82% |
| nested to depth 3 | 6,480 | 5,832 | 90.00% | 89.24-90.70% |
| split across sibling leaves | 6,480 | 5,832 | 90.00% | 89.24-90.70% |

Expected misses were 3,600 and stay out of recall: 1,440 reversed, none of them blocked, and 2,160 split across calls, 277 of them blocked anyway because a piece still matched a rule.

| S2, harmless look-alikes | Strings | False hits | Per 1,000 | Wilson 95% |
|---|---|---|---|---|
| **All** | 38,490 | 45 | **1.1691** | 0.8739-1.5638 |
| `placeholder-full` | 40 | 25 | | |
| `private-mention` | 20 | 14 | | |
| `url-template` | 30 | 5 | | |
| `sibling-leaves` | 500 | 1 | | |
| The other 34 classes | 37,900 | 0 | | |

No scan in either set stopped over budget. Percentages and rates are cut, never rounded.

## What drove them

**Misses are about which formats the rules cover, not about encoding.** 16 of the 109 format variants were never caught in any form, which is 3,388 of the 3,472 misses:

- `gitlab-token`: `oauth-secret`, `runner-registered`, `job`, `trigger`, `feed`, `incoming-mail`, `agent`, `workspace`, `scim`, `feature-flags`. GitLab's docs list these prefixes. Most body shapes are public knowledge or a guess.
- `vault-token`: `service-short`, `recovery`, `service-before-1-10`. Vault's docs say 24 or more random characters follow the prefix, and these use 24.
- `pypi-token/test-pypi` and `huggingface-token/organization`: public knowledge, not checked against a vendor page.
- `stripe-key/organization`: Stripe's docs give only the prefix, so the body is a guess.

The other 84 misses are all `private-key` under percent encoding: `form-plus` 30 of 30, `first-only` 30 of 30, `some` 24 of 30. Fully encoded keys were caught. On the 93 other variants recall was 30,608/30,692 (99.72%), but that is a reading made after the fact and not a score. 18 of the 24 rules reached 100%. Taken alone, `gitlab-token` was 33.47%, `vault-token` 40.25%, `pypi-token` 49.47%, `huggingface-token` 50.53%, `stripe-key` 86.58% and `private-key` 94.36%.

One format is caught only because its body is a JWT: GitHub's stateless installation tokens, the default since 2026-10-02, were blocked 188 of 188 times by `jwt` and never by `github-token`.

**44 of the 45 false hits come from three classes the set's writer added** beyond the classes first listed for S2. They total 90 strings, 0.23% of the set, and their sizes were a choice. `placeholder-full` has the right prefix and length with an empty body. `private-mention` has a private key's markers with no key. `url-template` has placeholders where a login goes. The line falls at 39 false hits, and the interval includes it. Leaving out `placeholder-full` (20/38,450, 0.5201 per 1,000) or `private-mention` (31/38,470, 0.8058 per 1,000) would put the rate under the line, so this crossing rests on a choice made when writing the set. It still stands as measured. The last false hit is a placeholder webhook URL whose text, joined to the next leaf, looks like a real webhook.

## What these numbers don't show

- **The headline depends on the list of formats.** Each rule weighs the same and shares its fakes evenly among its variants, so a rare GitLab prefix counts as much as the common one. Since variants are nearly all-or-nothing, a different list would move recall a long way. Whether a rule ever claimed a missed variant is not something a blind test can say.
- **The intervals are too narrow.** They treat every case as independent, and 34,080 cases come from only 720 fake values in 109 variants.
- **The S2 rate is a stress rate.** Its mix of classes was chosen, so it says little about real traffic. S3 is the set meant to measure that.
- **The fakes are random.** Bodies are uniform random text in the right shape, with no valid checksums, so a real token could behave differently.
- **Only `ScanCall` was scored.** `Redact` and the gateway's own leaf extraction weren't. Split leaves were adjacent and in order, and leaves with another leaf between them weren't tried. Nothing tried to exhaust the scan budget.

## After the first score: post-hoc

The first score above stands, and these don't replace it. Having read which formats and which placeholders failed, the author changed the rules, which gives a new table, `26c7217fa824123d7b36d1018e3561782a21eb492fd4fec74ad915a8f4740511`, and then reran the same generator, once on the first seed and once on a new one. `post-hoc/` holds the tables, and the ledger holds them with the label `post-hoc`.

| Post-hoc, table `26c7217f...` | S1 recall | S2 false hits |
|---|---|---|
| The first seed, 20261104 | 34,074/34,080 (99.98%) | 1/38,490 (0.0259 per 1,000) |
| A new seed, 20261105 | 34,072/34,078 (99.98%) | 2/38,490 (0.0519 per 1,000) |

**These show the changes work on these sets, and no more than that.** The changes were made from these sets' misses, and a new seed only redraws the random values within the same formats and classes, so both lines being clear now says little about formats or placeholders nobody listed. The next first scores for this table are S3 and S4.

What changed:

- **More formats:** GitLab's other prefixes, Vault's shorter bodies, its recovery prefix and its oldest form, test PyPI, Hugging Face organization tokens, Stripe organization keys, and GitHub's stateless tokens under their own rule.
- **Private keys encoded in part:** a whole text is now also read as one percent run, and a plus can stand for a space in the key's markers.
- **Fewer false hits:** a token body that only repeats a short unit is a placeholder. A private key's markers need a body of at least 40 characters with real variety. A URL password that's a variable name or a word like `password` is a template.

The new table gave up some things to get there, and each is pinned by a test:

- A real private key cut down to under 40 characters of body passes, and so does a header on its own.
- A real URL password written as `$` and letters reads as a variable and passes.
- A token followed by repeats of its own last few bytes reads as a placeholder and passes. Rewriting a secret on purpose has always been conceded (DESIGN section 9), but this is one more way to do it.
- The oldest Vault form needs clear edges, so it passes when text touches it, as in the join of split leaves. That's all 6 misses left in each post-hoc S1, every one of them `vault-token/service-before-1-10/.../split/among-words`.
- That same form also needs upper case, lower case and digits, so a random token without all three passes. None came up in these sets.

The false hits left are one placeholder webhook URL joined to the next leaf on the first seed, and two random strings on the new seed that happened to hold a token's shape (`base64-random/00951` and `pem-public/00061`).

Under the new table, the `value` arm of T0 gives the same result as `docs/evidence/t0/value.out`, line for line.

## Rerun it

Rerunning the first score needs commit `cafbae2`, since the rules have changed since. On later commits, use the hash from `go run ./test/secretscore -hash`, and expect the post-hoc numbers.

Needs Go 1.27 and Python 3.14, nothing to install, no network. `<folder>` is a new folder outside the repo, since the sets hold fake credentials. The set hashes in `generate.out` should come out the same.

```console
python -I -X utf8 bench/secrets/make_sets.py <folder>
go run ./test/secretscore <folder>/s1.jsonl > <folder>/s1.results.jsonl
go run ./test/secretscore <folder>/s2.jsonl > <folder>/s2.results.jsonl
python -I -X utf8 bench/secrets/score.py <folder> --expect-rules 2d687b53f1316ea3d84295868a8d7424169bd7eef077ee2d9d75cbd71a359004 --date <date>
```

Leave out `--ledger`: `eval/ledger.jsonl` keeps first scores, and it refuses a set it already holds.
