# CHANGELOG


## v1.1.0 (2026-04-24)

### Bug Fixes

- Align dataset name on import
  ([`07e72b6`](https://github.com/celine-eu/celine-dashboards/commit/07e72b666a64c9d9b5b7ac2f7d2538207d2b66fd))

- Allow datasource access per role
  ([`0e67d9c`](https://github.com/celine-eu/celine-dashboards/commit/0e67d9c9a66d541561f4084290bfaff5f7d94aa8))

- Correct login / logout path handling
  ([`fbaed91`](https://github.com/celine-eu/celine-dashboards/commit/fbaed91f9594416de5a1e80186e5331b47f7fde3))

- Docker build, review permission mapping with organizations
  ([`62ae268`](https://github.com/celine-eu/celine-dashboards/commit/62ae268e078ecca3c1a8f39d97f74fa0ca44a47f))

- Replace dbstring during import
  ([`4acb19a`](https://github.com/celine-eu/celine-dashboards/commit/4acb19ac171c56df9da4eb73ad809926c963aabd))

- Use local url by default
  ([`1725612`](https://github.com/celine-eu/celine-dashboards/commit/172561271f492bb4f2be85c108e618185a272dfd))

### Chores

- Add AGENTS
  ([`5100702`](https://github.com/celine-eu/celine-dashboards/commit/51007026baa1900a56ebaadfa9765c9efaac532b))

- Bump version to 6.0.0-0.1.4
  ([`9a60e9f`](https://github.com/celine-eu/celine-dashboards/commit/9a60e9f1e1b1e0d4696bcd1d0165d8b1231481a7))

- Refactor, migrate to single package
  ([`24b114b`](https://github.com/celine-eu/celine-dashboards/commit/24b114b46b6d337cb3cfd094da8a369560004881))

- Release new versions
  ([`d62ed8a`](https://github.com/celine-eu/celine-dashboards/commit/d62ed8a126e84db132f8e01f573d1715381409da))

- Rm superset submodule
  ([`09e11f7`](https://github.com/celine-eu/celine-dashboards/commit/09e11f7c75ae7d377ba3ee07d9342d69f3c9a6bc))

### Continuous Integration

- Bump the actions group across 1 directory with 4 updates
  ([`e0e4333`](https://github.com/celine-eu/celine-dashboards/commit/e0e43332251ce5d167f87dfde0a1ed699c99f19d))

Bumps the actions group with 4 updates in the / directory:
  [actions/checkout](https://github.com/actions/checkout),
  [docker/setup-buildx-action](https://github.com/docker/setup-buildx-action),
  [docker/login-action](https://github.com/docker/login-action) and
  [dorny/paths-filter](https://github.com/dorny/paths-filter).

Updates `actions/checkout` from 4 to 6 - [Release
  notes](https://github.com/actions/checkout/releases) -
  [Changelog](https://github.com/actions/checkout/blob/main/CHANGELOG.md) -
  [Commits](https://github.com/actions/checkout/compare/v4...v6)

Updates `docker/setup-buildx-action` from 3 to 4 - [Release
  notes](https://github.com/docker/setup-buildx-action/releases) -
  [Commits](https://github.com/docker/setup-buildx-action/compare/v3...v4)

Updates `docker/login-action` from 3 to 4 - [Release
  notes](https://github.com/docker/login-action/releases) -
  [Commits](https://github.com/docker/login-action/compare/v3...v4)

Updates `dorny/paths-filter` from 3 to 4 - [Release
  notes](https://github.com/dorny/paths-filter/releases) -
  [Changelog](https://github.com/dorny/paths-filter/blob/master/CHANGELOG.md) -
  [Commits](https://github.com/dorny/paths-filter/compare/v3...v4)

--- updated-dependencies: - dependency-name: actions/checkout dependency-version: '6'

dependency-type: direct:production

update-type: version-update:semver-major

dependency-group: actions

- dependency-name: docker/setup-buildx-action dependency-version: '4'

- dependency-name: docker/login-action dependency-version: '4'

- dependency-name: dorny/paths-filter dependency-version: '4'

dependency-group: actions ...

Signed-off-by: dependabot[bot] <support@github.com>

### Features

- Add Alerts & Reports support (Playwright, SMTP, HTML sanitization)
  ([`6ff1b84`](https://github.com/celine-eu/celine-dashboards/commit/6ff1b84ed4cca4a6374a3ea34e5d739bdcfa590c))

- Add sync with org based permissions
  ([`c9ad804`](https://github.com/celine-eu/celine-dashboards/commit/c9ad80480cdfe0eac55664a8c64d58dad0faa3ae))

- Refactor packages, add superset CLI, review groups mapping
  ([`a074cf6`](https://github.com/celine-eu/celine-dashboards/commit/a074cf6d0a345cac594b2d782cfe71d7bf3e17f4))

- Separate jupyter vs superset packages due to incompatible runtimes. Review build
  ([`1fd32d5`](https://github.com/celine-eu/celine-dashboards/commit/1fd32d5771055c46b3f9e70e2893f550c2d3de12))

- **cli**: Add boostrap to sync datasets
  ([`b7dc461`](https://github.com/celine-eu/celine-dashboards/commit/b7dc4617fa1e54ca8098fefed26378ad86437819))


## v1.0.0 (2026-03-02)

### Bug Fixes

- Dockerfile
  ([`d51f3f2`](https://github.com/celine-eu/celine-dashboards/commit/d51f3f264f34b9954528afea7f2880fdc3ebe969))

- Missing default scopes
  ([`4713afb`](https://github.com/celine-eu/celine-dashboards/commit/4713afbcdd41d47af80329fedad9e5bbdeebfbfe))

### Chores

- Add dumpster
  ([`7bdab56`](https://github.com/celine-eu/celine-dashboards/commit/7bdab56fd0cd3813c88b5b1be3bbcb74251d75bf))

- Add update docs hook
  ([`53980b3`](https://github.com/celine-eu/celine-dashboards/commit/53980b39362dd67fcefc13afea844f755e6bf731))

- Remove superset image
  ([`e81071c`](https://github.com/celine-eu/celine-dashboards/commit/e81071c4932e58cbd31f7bfc65153b0fd1c14662))

- Run actions on selected tags/branches
  ([`8622dc7`](https://github.com/celine-eu/celine-dashboards/commit/8622dc76075a747d2377174e07ec45d65b2a4283))

- Upgrade taskfile with setup
  ([`dc4151c`](https://github.com/celine-eu/celine-dashboards/commit/dc4151c9ae6f801d84d33ae354b5abf64e79d7e4))

### Features

- Add jupyter
  ([`0c0bc99`](https://github.com/celine-eu/celine-dashboards/commit/0c0bc9928760be04e9ba6df7d13d8e8779ccc542))

- Add tests
  ([`1996ed6`](https://github.com/celine-eu/celine-dashboards/commit/1996ed6be1567ae7b9e879b923eb3a94d8fcec2a))


## v0.1.3 (2025-12-20)

### Bug Fixes

- Release
  ([`f2deeea`](https://github.com/celine-eu/celine-dashboards/commit/f2deeeab554d3b7c50230b6e07118e3d35cb86b6))


## v0.1.1 (2025-12-20)

### Bug Fixes

- Release
  ([`c75d0b0`](https://github.com/celine-eu/celine-dashboards/commit/c75d0b0d22ee53b8d4b356662256270324dd356d))

- Update action
  ([`739288d`](https://github.com/celine-eu/celine-dashboards/commit/739288d0861d093bf8997c507adb4125d5d86955))


## v0.1.0 (2025-12-20)

### Bug Fixes

- Correct remote user flow
  ([`2513a4e`](https://github.com/celine-eu/celine-dashboards/commit/2513a4e5c03cd29a056262313515809ad9cc2a95))

### Chores

- Add compose services
  ([`ec130ac`](https://github.com/celine-eu/celine-dashboards/commit/ec130ace6d1fb2d0a7513799301863eb1709831e))

- Migrate from processing repo
  ([`46e70bf`](https://github.com/celine-eu/celine-dashboards/commit/46e70bfd025ad60b6ac314c28c4dfee651b0328e))

### Features

- Add celine-superset module
  ([`5a3c9dd`](https://github.com/celine-eu/celine-dashboards/commit/5a3c9dd8d06e4ff2d503fa252eb583500a22d1a6))
