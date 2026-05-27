# Official Debian Archive Release Plan

This document tracks the long-term path for getting Saugra accepted into the
official Debian archive, and then into Ubuntu through the normal Debian-to-Ubuntu
sync flow where possible.

This is separate from the Saugra-owned signed APT repository described in
`docs/APT_REPOSITORY.md`. The Saugra APT repository is the near-term production
install channel. Official Debian archive inclusion is a slower distribution and
policy-compliance track.

## Target Outcome

The target outcome is:

```txt
Saugra upstream release -> Debian source package -> sponsor upload -> Debian archive -> Ubuntu sync
```

The package should install the same production-oriented runtime shape as the
Saugra-owned `.deb` package:

- `/usr/bin/saugra`
- systemd unit
- `/etc/saugra/saugra.yml` as operator-managed configuration
- bundled rule, standards, and intelligence data under Debian-approved paths
- durable event/log/state directories
- no automatic service start or enablement on install

## Important Difference From `cargo-deb`

The current `cargo-deb` package is useful for GitHub Releases and the Saugra APT
repository, but it is not sufficient by itself for official Debian archive
submission.

The official Debian path requires Debian source packaging. Builds must use
Debian-packaged dependencies and must not download crates or other source code
from the network during the package build.

## Debian Readiness Checklist

- [ ] Confirm every Cargo dependency is available in Debian as a packaged Rust
      crate, or identify missing crates that must be packaged first.
- [ ] Run `cargo-debstatus` or equivalent dependency checks on the repository.
- [ ] Decide whether Saugra should be maintained under the Debian Rust team,
      as an independently maintained application package, or both with Rust
      team coordination.
- [ ] Create Debian source packaging under `debian/`.
- [ ] Translate `Cargo.toml` dependencies into Debian `Build-Depends`.
- [ ] Build with `dh-cargo` or the current Debian Rust packaging tooling.
- [ ] Ensure the package build does not require network access.
- [ ] Add machine-readable `debian/copyright`.
- [ ] Add `debian/watch` for upstream release tracking if suitable.
- [ ] Add Debian changelog entries with Debian revision versions.
- [ ] Validate maintainer scripts against Debian Policy expectations.
- [ ] Confirm conffile handling preserves `/etc/saugra/saugra.yml`.
- [ ] Confirm systemd integration follows Debian maintainer-script helpers.
- [ ] Run `lintian` and resolve policy issues.
- [ ] Build in a clean environment with `sbuild` or `pbuilder`.
- [ ] File an ITP bug against Debian WNPP.
- [ ] Upload the package to mentors.debian.net.
- [ ] File an RFS sponsorship request and respond to sponsor review.
- [ ] Track NEW queue review if the package is uploaded.

## Dependency Audit

Rust applications in Debian generally need all build dependencies available as
Debian packages. Saugra currently depends on crates such as:

- `anyhow`
- `async-trait`
- `axum`
- `clap`
- `hyper`
- `hyper-util`
- `redis`
- `regex`
- `serde`
- `serde_json`
- `serde_yaml`
- `thiserror`
- `tokio`
- `tracing`
- `tracing-subscriber`
- `uuid`

Before opening an ITP, maintainers should generate a current dependency report
and split the results into:

- dependencies already packaged in Debian
- dependencies packaged but with incompatible versions/features
- dependencies missing from Debian
- dependencies that pull in additional missing transitive crates

Missing crates should be coordinated with the Debian Rust team rather than
vendored into the Saugra source package.

## Packaging Design Notes

The Debian source package should preserve Saugra's production behavior:

- monitor-first default guidance
- Redis-backed production rate limiting support
- durable local security event storage
- no silent blocking without structured security events
- no full sensitive request body logging by default
- operator-owned config during upgrades

Avoid maintaining two divergent installation behaviors. The Saugra-owned `.deb`
and official Debian package may use different packaging mechanics, but they
should install an equivalent operator workflow.

## Expected Submission Flow

1. Prepare a Debian source package locally.
2. Build and test it without network access.
3. Run `lintian`.
4. File an Intent to Package bug against WNPP.
5. Upload the source package to mentors.debian.net.
6. Request sponsorship through the Debian Mentors process.
7. Address sponsor feedback.
8. After sponsor upload, wait for NEW queue review if required.
9. Once accepted into Debian unstable, track testing migration.
10. Let Ubuntu sync from Debian where possible, or request Ubuntu sponsorship
    only if an Ubuntu-specific package is needed.

## References

- Debian Mentors: https://wiki.debian.org/DebianMentors
- Debian ITP process: https://wiki.debian.org/ITP
- Debian Rust packaging policy: https://wiki.debian.org/Teams/RustPackaging/Policy
- Debian Policy Manual, source packages: https://www.debian.org/doc/debian-policy/ch-source.html
- Ubuntu new package process: https://documentation.ubuntu.com/project/how-ubuntu-is-made/processes/new-packages/
