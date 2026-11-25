# HTTP Message Signature Base Builder

Rebuild the RFC 9421 (HTTP Message Signatures) signature base from a raw HTTP message and its `Signature-Input` header, line by line, with the rule that produced each line. RFC 9421 only: the obsolete draft-cavage scheme, whose `Signature` header carries `keyId=...` and `headers="..."`, is **not supported** and will not parse here.

**Live demo:** https://0xelitesystem.github.io/http-message-signature-base-builder/

## Use

1. Paste a raw HTTP request or response into the message box: start line, header block, a blank line, then the body if you have it. The body is never hashed and is never silently used.
2. Paste the value of the `Signature-Input` field. A full Dictionary with several labels is fine, and a label selector appears; a bare inner list is accepted as a single unlabelled signature.
3. Read the base. Each line is labelled with the RFC 9421 rule that produced it, either field canonicalisation per Section 2.1 or the specific derived component section from 2.2.1 to 2.2.9. The last line is always the `"@signature-params"` line, and the base carries no trailing newline.
4. Optional. Paste the originating request when the message is a response and a component carries `;req`. Paste a base64 shared secret and the `Signature` value to get an HMAC-SHA-256 verdict.
5. Press **Run self test** to run the RFC's own printed vectors in your browser against the same code that just built your base.

The page opens with Appendix B.2.5 already loaded and already computed, so the first thing you see is a base you can check against the RFC before you trust the page with your own message.

### What aborts the build

Every one of these produces a diagnosis and **no base at all**, because Section 2.5 requires that all errors "MUST fail the algorithm immediately, without outputting a signature base". Every error found is reported, not just the first, ordered by position in the covered component list.

| Condition | RFC 9421 section |
| --- | --- |
| Duplicate component identifier, including its parameters | 2.5 step 2.1 |
| `@signature-params` enumerated inside the covered component list | 2.3 |
| `@status` used in a request | 2.2.9 |
| A request-targeted derived component used on a response without `;req` | 2.2 |
| `;req` used on a signature whose target message is a request | 2.5 step 2.5 |
| `;req` used but no originating request supplied | 2.4 |
| `;bs` combined with `;sf`, or with `;key` | 2.5 step 2.5, 2.1 |
| A component parameter the tool does not understand | 2.5 step 2.5 |
| A component parameter that does not apply to the component it is attached to: `;sf`, `;key`, `;bs` or `;tr` on a derived component, or `;name` on anything but `@query-param` | 2.5 step 2.5 |
| A named field absent from the message | 2.5 |
| A `;tr` component whose chunked body cannot be walked to its trailer section | 2.1.4 |
| A `;key` naming a Dictionary member that does not exist | 2.1.2 |
| A `@query-param` absent from the query, or occurring more than once | 2.2.8 |
| A `;sf` field whose Structured Field type is undeclared or unimplemented | 2.1.1, 2.5 |
| A component value containing a newline | 2 |
| Any non-ASCII character in the finished base | 2.5 step 4 |

### Structured Fields types the serialiser implements

For `;sf` and `;key`, exactly these, each with parameters:

**Integer**, **Decimal**, **String**, **Token**, **Byte Sequence**, **Boolean**, **Inner List**, **List**, **Dictionary**.

Anything else raises a visible error naming the unsupported type. The tool cannot know a field's type from the wire, so a component carrying `;sf` gets a type selector, and leaving it unset aborts the build rather than guessing.

### The `@query-param` encoder

Section 2.2.8 form-decodes the name and the value, then re-encodes with the urlencoded percent-encode set. Two obvious shortcuts are both wrong, in opposite directions, and the RFC's own printed vectors catch both. `URLSearchParams` turns a space into a plus sign and produces `bar=with+plus+whitespace`, where the RFC requires `with%20plus%20whitespace`. `encodeURIComponent` leaves `!`, `~`, `'`, `(` and `)` unescaped, and the urlencoded set escapes those.

What this page does instead: form-decode (every plus sign becomes a space, then percent-decode the result), then re-encode byte by byte, keeping literal only the 66 characters `[A-Za-z0-9]` plus `*`, `-`, `.` and `_`, and emitting every other byte as a percent sign and two uppercase hex digits. A space becomes `%20` and never a plus sign. All three Section 2.2.8 printed vectors ship as visible worked examples on the page and are recomputed by the self test, so the encoder is self-evidencing rather than merely asserted.

## Why this exists

RFC 9421 does not sign the bytes that went over the wire. It signs a string you have to reconstruct: the signature base. When verification fails, a boolean tells you nothing and the base tells you everything, because one wrong byte anywhere in it changes every byte of the MAC. The self test proves that on the page: it computes the MAC over the Appendix B.2.5 base, gets the value the RFC prints, then appends a single newline and gets a completely different value.

Single file, no build step, no network call, MIT licensed. Nothing to install and nothing watching you paste a signed production request into a box.

### Why two conforming stacks end up with different bases

A verifier does not choose `;bs` or `;sf`. Those parameters travel inside the `Signature-Input` inner list, and a conforming verifier reads them out of that header and applies them. Divergence comes from three other places.

1. **The verifier cannot serialize the type.** Section 2.1.1 states it directly: "If the application does not know the type of the field or does not know how to serialize the type of the field, the use of this flag will produce an error. As a consequence, the signer can only reliably sign fields using this flag when the verifier's system knows the type as well." That is why this page refuses to guess a type.
2. **An intermediary merged or split a multi-valued field.** Section 2.1.3 points at Section 7.5.6 for exactly this case. Without `;bs`, `Example-Header: value, with, lots` plus `Example-Header: of, commas` and the single merged `Example-Header: value, with, lots, of, commas` both collapse to the identical line `"example-header": value, with, lots, of, commas`, so the merge is invisible. With `;bs` the two-instance form gives `"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:` and the merged form gives `"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:`. Different base, failed verification, and no diagnostic anywhere in the stack. That contrast ships as a side-by-side worked example on the page.
3. **The signer applied `;sf` and an intermediary reserialised the field**, so signer and verifier parse different input and produce different strict serializations of the same nominal field.

### Why the crypto panel is HMAC-SHA-256 only

No asymmetric verification, no key import, no RSA, ECDSA or Ed25519 path. The reason is in the RFC. Its RSA-PSS and ECDSA examples each carry the note that the algorithm "is non-deterministic, meaning that a different signature value will be created every time the algorithm is run", so comparing a freshly computed value against the printed one is honest only for the deterministic `hmac-sha256` case in Appendix B.2.5. The base string is the deliverable. The MAC is the garnish. `crypto.subtle` is feature detected, and when it is absent the page degrades to base-only output with a one-line notice instead of throwing.

### The self test

One button, **Run self test**, running in your browser against the same code that builds your base. At the time this README was written the suite carried **91 checks plus 1 positive control**, and the page prints its own live count rather than trusting this sentence. Coverage: the Appendix B.2.1 to B.2.6 bases, the Section 2.5 Figure 1 base, the Section 2.4 `;req` response base, the Section 2.1 canonicalisation examples including the whitespace, obsolete-line-folding, repeated-field and empty-field cases, the Section 2.1.1 `;sf` reserialisation, the four Section 2.1.2 `;key` cases, both Section 2.1.3 `;bs` cases and both no-parameter collapses, the Section 2.1.4 trailer case, the derived components of Sections 2.2.1 to 2.2.9 including all four request-target forms, the Section 2.2.8 query parameter vectors, and the HMAC vector with its trailing-newline control.

It also covers the paths the RFC prints no vector for, because those are where a base goes wrong quietly: an absolute-form request target supplying its own scheme and its own default port, a present but empty query surviving into `@target-uri`, a `@query-param` value outside the Basic Multilingual Plane, a repeated Dictionary key keeping its original position, and a trailer sitting behind a multi-byte chunk. Every abort condition in the table above has a fixture behind it, one per condition.

The positive control is an assertion written to fail. If it ever reports PASS, the suite is not running and its results cannot be trusted. That is what makes a silently broken suite detectable, which matters here: during development a single reversed tuple in an inner list is enough to break a large fraction of the vectors while the page still renders a confident, wrong base.

## Privacy

Everything runs in your browser. There is no network call of any kind: no request for code, fonts, analytics or telemetry, and nothing you paste is transmitted anywhere. Save the file and it works offline from `file://`. The one browser API the page reaches for is `crypto.subtle`, for the optional HMAC, and it is feature detected. There is no server, no storage and no logging, so a signed production request pasted into the box goes nowhere.

## Run locally

```
git clone https://github.com/0xelitesystem/http-message-signature-base-builder.git
cd http-message-signature-base-builder
```

Open `index.html` in a browser. That is the whole thing. If you would rather serve it:

```
python -m http.server 8000
```

then open `http://localhost:8000/`.

## Build

No build. One self-contained `index.html` with inline CSS and inline JavaScript. No dependencies, no package manager, no bundler, no CDN, no web font.

## Independence and provenance

This is an independent tool. It is not affiliated with, endorsed by, or connected to the IETF, the RFC Editor, or any implementation of RFC 9421, and nothing here implies endorsement. Behaviour was reimplemented from the published specification at https://www.rfc-editor.org/rfc/rfc9421.txt and no code is reproduced here. The example messages, the expected signature bases and the shared secret are the specification's own published test material, with the RFC 8792 line wrapping removed.

## Third-party notices

**RFC 9421, HTTP Message Signatures** (IETF, Standards Track, February 2024).
https://www.rfc-editor.org/rfc/rfc9421

Copyright notice, copied verbatim from the RFC:

> Copyright (c) 2024 IETF Trust and the persons identified as the document authors. All rights reserved.
>
> This document is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info) in effect on the date of publication of this document. Please review these documents carefully, as they describe your rights and restrictions with respect to this document. Code Components extracted from this document must include Revised BSD License text as described in Section 4.e of the Trust Legal Provisions and are provided without warranty as described in the Revised BSD License.

What was taken: the test vectors printed in the RFC, used unchanged as expected values in this page's self test. That covers the complete signature bases of Appendix B.2.1 to B.2.6, the Section 2.5 Figure 1 base, the Section 2.4 response base, and the worked examples of Sections 2.1 to 2.2.9. They are reproduced byte for byte so the self test can prove this implementation matches the specification. No other text or code is taken from the RFC. The implementation itself is written from the specification's rules and is not copied from any other project.

## Related

- https://github.com/0xelitesystem/multi-provider-webhook-verifier
- https://github.com/0xelitesystem/http-header-explainer
- https://github.com/0xelitesystem/jwt-verify-in-browser

## License

MIT. Copyright (c) 2026 RBL Industries LLC.
