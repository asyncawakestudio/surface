# Changelog

## [0.3.0](https://github.com/asyncawakestudio/surface/compare/v0.2.1...v0.3.0) (2026-11-20)


### ⚠ BREAKING CHANGES

* read API keys from the environment only ([#27](https://github.com/asyncawakestudio/surface/issues/27))
* collect data only, leave analysis to downstream consumers ([#26](https://github.com/asyncawakestudio/surface/issues/26))
* serve MCP from the surface binary (surface mcp) ([#21](https://github.com/asyncawakestudio/surface/issues/21))

### Features

* collect data only, leave analysis to downstream consumers ([#26](https://github.com/asyncawakestudio/surface/issues/26)) ([c92249b](https://github.com/asyncawakestudio/surface/commit/c92249bda2639571c9077ebc81992fc352b181ec))
* discover cloud services and identity providers ([#19](https://github.com/asyncawakestudio/surface/issues/19)) ([2cd5c59](https://github.com/asyncawakestudio/surface/commit/2cd5c596b7d139282f7ed28ab74c3b70c72e7369))
* ProjectDiscovery-style terminal output ([#28](https://github.com/asyncawakestudio/surface/issues/28)) ([6da16cc](https://github.com/asyncawakestudio/surface/commit/6da16ccf3f25b4aa0aac1aee0935700f1265713b))
* serve MCP from the surface binary (surface mcp) ([#21](https://github.com/asyncawakestudio/surface/issues/21)) ([9f65c15](https://github.com/asyncawakestudio/surface/commit/9f65c15c401627355e84595df13de436d92a2001))


### Bug Fixes

* read API keys from the environment only ([#27](https://github.com/asyncawakestudio/surface/issues/27)) ([085007a](https://github.com/asyncawakestudio/surface/commit/085007a42a4d7f18f62eacfce2d21b4bdbdab99f))


### Chores

* **ci:** bump the minor version for features before 1.0 ([#25](https://github.com/asyncawakestudio/surface/issues/25)) ([ce98a63](https://github.com/asyncawakestudio/surface/commit/ce98a63cc7ec005c560cd80a8f453e12c364dece))
* **ci:** bump the patch version for features before 1.0 ([#22](https://github.com/asyncawakestudio/surface/issues/22)) ([e00718c](https://github.com/asyncawakestudio/surface/commit/e00718c2f9c49e350dc3f78ec9d1329a5d277fcb))
* **ci:** do not run tests in CD ([#17](https://github.com/asyncawakestudio/surface/issues/17)) ([7d8bf28](https://github.com/asyncawakestudio/surface/commit/7d8bf280b0cf03cc46453c7751e5f56d240d9cf1))
* **ci:** run tests on pull requests only ([#23](https://github.com/asyncawakestudio/surface/issues/23)) ([8449d3c](https://github.com/asyncawakestudio/surface/commit/8449d3c7c5e73d0470b86873e8cc6cae3c2aca49))
* **docs:** show release downloads ([#24](https://github.com/asyncawakestudio/surface/issues/24)) ([16a8ebe](https://github.com/asyncawakestudio/surface/commit/16a8ebeb00279e58e8594c4c8bcaee4320cb6000))
* strip debug info from local builds ([#20](https://github.com/asyncawakestudio/surface/issues/20)) ([c87c299](https://github.com/asyncawakestudio/surface/commit/c87c2997600ec1286835195b7fac2eb72c9b67eb))

## [0.2.1](https://github.com/asyncawakestudio/surface/compare/v0.2.0...v0.2.1) (2026-11-19)


### Bug Fixes

* drop go.mod replace so go install [@version](https://github.com/version) works ([#15](https://github.com/asyncawakestudio/surface/issues/15)) ([90054ec](https://github.com/asyncawakestudio/surface/commit/90054ec4b8fade97ebc0c29bf7964cba74d75b9e))

## [0.2.0](https://github.com/asyncawakestudio/surface/compare/v0.1.0...v0.2.0) (2026-11-19)


### Features

* brute-force subdomains using wordlist ([#12](https://github.com/asyncawakestudio/surface/issues/12)) ([77e62a3](https://github.com/asyncawakestudio/surface/commit/77e62a3d614d374e334d06f689af7d59e499fda6))
* check SPF, DMARC, CAA and zone transfers ([#10](https://github.com/asyncawakestudio/surface/issues/10)) ([601316d](https://github.com/asyncawakestudio/surface/commit/601316d06cf2d137c7cc8a0707c5ff84f68bb44b))
* check TLS versions, ciphers and certificates ([#13](https://github.com/asyncawakestudio/surface/issues/13)) ([c2065a3](https://github.com/asyncawakestudio/surface/commit/c2065a3a63febc725c8cd4d39fa55d260f2f1afc))
* detect subdomain takeovers ([#9](https://github.com/asyncawakestudio/surface/issues/9)) ([b13089d](https://github.com/asyncawakestudio/surface/commit/b13089d6937087b5199b245866217cf7bf39f61f))
* find public cloud storage buckets ([#14](https://github.com/asyncawakestudio/surface/issues/14)) ([d3207d9](https://github.com/asyncawakestudio/surface/commit/d3207d9c4153c823099b3271966aa86ddfb521b7))
* identify services on open ports ([#6](https://github.com/asyncawakestudio/surface/issues/6)) ([c681feb](https://github.com/asyncawakestudio/surface/commit/c681feb0c2741a9e2bba66aafa6628651e9d25dd))
* look up CVEs for detected services ([#7](https://github.com/asyncawakestudio/surface/issues/7)) ([62be8db](https://github.com/asyncawakestudio/surface/commit/62be8db2e2aaea602059f42856b9970fda5c8455))
* probe web services with httpx ([#8](https://github.com/asyncawakestudio/surface/issues/8)) ([454e63b](https://github.com/asyncawakestudio/surface/commit/454e63bb5a6e304ecff834617347df9fd14fca42))


### Bug Fixes

* **deps:** bump the go-modules group with 3 updates ([#4](https://github.com/asyncawakestudio/surface/issues/4)) ([38cc731](https://github.com/asyncawakestudio/surface/commit/38cc7316ca875d1acf4fe27f6ed8794835e7af96))


### Chores

* report subdomain takeovers as misconfigurations ([#11](https://github.com/asyncawakestudio/surface/issues/11)) ([4acc8d5](https://github.com/asyncawakestudio/surface/commit/4acc8d5d0b344cece4fe55a277b359dd98100d47))

## 0.1.0 (2026-10-19)


### Features

* attack surface discovery ([#1](https://github.com/asyncawakestudio/surface/issues/1)) ([f46c434](https://github.com/asyncawakestudio/surface/commit/f46c43444fed8825a90380793569d510d53c1f91))


### Bug Fixes

* **deps:** bump the go-modules group with 4 updates ([#3](https://github.com/asyncawakestudio/surface/issues/3)) ([9114744](https://github.com/asyncawakestudio/surface/commit/911474499800bea5aac48304efb641b808ea8ba6))


### Chores

* **ci:** update Release Please config ([a183ede](https://github.com/asyncawakestudio/surface/commit/a183ede0b48160c78a362f6e700cb5a59046b321))
* **docs:** add README ([ce0aa6d](https://github.com/asyncawakestudio/surface/commit/ce0aa6db0cbcca9b8eae1bd10ac27ba20ee9028f))
