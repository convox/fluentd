# convox/fluentd

Based on [fluent/fluentd-kubernetes-daemonset](https://github.com/fluent/fluentd-kubernetes-daemonset)

Modified to create a single image and add additional plugins

| Directory | fluentd | Image |
| --- | --- | --- |
| `1.13` | 1.7.4 (pinned in its Gemfile) | `convox/fluentd:1.13-all` |
| `1.19` | 1.19.3 | `convox/fluentd:1.19-all` |

To release, push a git tag (e.g. `1.19`) or run the `release` workflow with that tag. It builds the
directory matching the tag's major.minor and publishes `<tag>-amd64`, `<tag>-arm64` and the
multi-arch `<tag>-all`.
