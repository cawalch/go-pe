# Release an experimental version

This guide describes maintainer actions. The first experimental release,
[v0.1.0](https://github.com/cawalch/go-pe/releases/tag/v0.1.0), was published on
2026-11-17 from commit `b7801b4fce05bc41a27ea7f4aa136bc87233b6b9`. Subsequent
releases are tracked in the [changelog](../CHANGELOG.md).

## Choose a version

Use semantic versions. The experimental MVP starts at `v0.1.0`. For future
release candidates, use a prerelease suffix such as `v0.2.0-rc.1`. Before v1.0.0, document breaking changes
in release notes and increase the minor version for them. Use patch versions
for compatible fixes. Consumers should pin a version and review updates.

The module path remains `github.com/cawalch/go-pe` for v0 and v1. A future v2
requires the `/v2` module-path suffix and a migration plan. Keep `go 1.26.0`
as the minimum until an intentional compatibility change requires otherwise.
CI tests the latest patch of that series and the current stable Go release.
Use current security patches when building applications.

## Prepare the release

1. Review the API, README example, parsing guide, security policy, and MIT license.
   Describe implemented features and limits, including offline Authenticode
   verification. Do not imply Windows trust equivalence.
2. Review the [validation inventory](validation.md), including corpus gaps and
   Authenticode assurance limits. Run the checks in [Contributing](../CONTRIBUTING.md#validate-a-change), including
   the comparison module and vulnerability checks. Review CI for the exact
   candidate commit on Linux, macOS, and Windows. Resolve failures before release.
3. Review dependency and security alerts. Follow the owner checklist below.
4. Write release notes with the version, commit, supported Go versions, features,
   known limitations, and any API changes. Remove the README's “no tagged release”
   notice only when a release exists, and change its installation command to the
   published version.

## Publish after approval

Publishing is a separate maintainer decision. From a clean checkout of the
reviewed commit, create and push an annotated tag. The following example assumes
the maintainer has approved `v0.1.0` and the current commit:

```sh
git tag -a v0.1.0 -m 'Experimental MVP v0.1.0'
git push origin v0.1.0
```

Go modules need a source tag, not a binary or GitHub Packages workflow. You can
also publish GitHub release notes for that tag. If immutable releases are enabled,
prepare a draft and finish its contents before publishing it. Tag rules protect
source-only tags that have no associated immutable GitHub release.

After publishing, request proxy discovery and confirm installation from a
separate temporary module with no local `replace` directive:

```sh
GOPROXY=https://proxy.golang.org go list -m github.com/cawalch/go-pe@v0.1.0
mkdir /tmp/go-pe-release-check
cd /tmp/go-pe-release-check
go mod init example.com/go-pe-release-check
go get github.com/cawalch/go-pe@v0.1.0
```

Check the versioned [package documentation](https://pkg.go.dev/github.com/cawalch/go-pe).
Never move or reuse a published tag. Publish a new version for corrections; use
a `retract` directive in a later version if a published version must be withdrawn.
See the official [Go publishing guide](https://go.dev/doc/modules/publishing).

## Repository settings for the owner

The following audit records read-only observations on 2026-11-17. These settings
are not configured by this cleanup and require an owner's decision:

| Setting | Observed state | Recommended action |
| --- | --- | --- |
| Main branch protection and repository rulesets | No main protection; no rulesets | Require pull requests and the successful CI checks from this PR; block force pushes and deletion. Choose review requirements appropriate for available maintainers. |
| Release tags | No rulesets | Protect `v*` tags from updates and deletion; restrict creation to release maintainers. Review and enable immutable GitHub releases before the first release. |
| Private vulnerability reporting | Disabled | Enable it, then update `SECURITY.md` with the private reporting link. Keep the verified email fallback. |
| CodeQL | Default setup not configured; no advanced workflow | Enable default setup for Go and GitHub Actions. Verify both analyses succeed. Do not also add an advanced CodeQL workflow; reassess advanced setup only if default coverage is insufficient. |
| Dependabot security updates | Disabled | Enable dependency graph, alerts, and security updates. Review findings in the comparison module as well as the root module. |
| Secret scanning and push protection | Enabled | Keep both enabled. |
| Actions token | Read-only; cannot approve pull requests | Keep these restrictions. Review fork-run approval requirements and restrict allowed actions to reviewed dependencies. |

See GitHub's guidance on [default CodeQL setup](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configure-code-scanning),
[private reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository),
[rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets),
and [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).
