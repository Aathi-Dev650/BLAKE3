# CRYPTOLAB — BLAKE3

An interactive, client-side BLAKE3 laboratory. The educational engine exposes chunk outputs, seven compression rounds, G-function intermediate values, and the BLAKE3 left-balanced tree reduction. Each digest is cross-checked with `@noble/hashes` before it is shown.

## Run locally

```sh
npm install
npm run dev
```

Create a production build with `npm run build`.

## Engine checks

The engine checks every computed digest against the independent `@noble/hashes` implementation. It was also checked against the published empty-string and `abc` BLAKE3 digests, plus byte lengths around block and chunk boundaries and Unicode input.
