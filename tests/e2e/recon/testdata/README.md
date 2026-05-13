# Recon e2e fixtures

This directory holds inputs for the v26.5.0 recon end-to-end tests.

The JPEG fixture is generated on demand by `makeJPEGWithEXIF` in
`metadata_e2e_test.go` so we don't ship a binary blob the reader can't
inspect. The bytes are deterministic — every test run produces the
same file with a `Software=usulnet-e2e-test` EXIF tag in IFD0.

## Why generated, not committed

- Reviewers can audit the EXIF construction directly in Go source.
- A reviewer can re-derive the fixture without `exiftool` /
  `imagemagick` on their machine.
- Avoids the recurring problem of "what's actually in this 2 kB
  binary?" during a security review.

If a future test needs a real-world JPEG with EXIF (e.g., a camera
raw dump), drop it in this directory and reference it by relative
path from `metadata_e2e_test.go`.
