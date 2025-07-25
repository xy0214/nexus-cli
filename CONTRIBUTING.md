# Contributing to the Nexus network

> **Note:** This guide is for contributors who want to modify or improve the CLI itself. If you're just looking to use the CLI, please see the [main README](README.md) for installation and usage instructions.

The Nexus network is contributor-friendly.
We welcome all contributions, no matter your experience with Rust or cryptography.

This document will help you get started. But first, **thank you for your interest in contributing!** We immensely appreciate quality contributions. This guide is intended to help you navigate the process.

The [Discord][discord] is always available for any concerns you may have that are not covered in this guide, or for any other questions or discussions you want to raise with the Nexus team or broader Nexus community.

## Development Setup

### Prerequisites

- **Rust and Cargo**: Latest stable version
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
  Verify installation:
  ```bash
  rustc --version
  cargo --version
  ```

- **Git**: For version control
  ```bash
  git --version
  ```

- **Protobuf Compiler**: Required if working with proto files
    - macOS: `brew install protobuf`
    - Ubuntu/Debian: `apt-get install protobuf-compiler`
    - Windows: Download from [protobuf releases](https://github.com/protocolbuffers/protobuf/releases)
      Verify installation:
  ```bash
  protoc --version
  ```

### Building from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/nexus-xyz/nexus-cli
   cd nexus-cli/clients/cli
   ```

2. Build the CLI:
   ```bash
   cargo build
   ```

3. Run the CLI:
   ```bash
   cargo run
   ```

### Code Quality Checks

Before submitting changes, please run the following checks locally:

```bash
# Format code
cargo fmt --check

# Run clippy lints
cargo clippy -- -D warnings

# Check for unused dependencies
cargo udeps

# Check for security vulnerabilities
cargo audit
```

These checks are the same ones that run in our CI pipeline. If they pass locally, your
changes are likely to pass CI as well.

### Proto Compilation

By default, the build process skips proto compilation to make it easier for contributors to work on the codebase without needing protobuf tooling. If you need to modify or regenerate the proto files, you can enable proto compilation by using the `build_proto` feature:

```bash
cargo build --features build_proto
```

### Code of Conduct

The Nexus network project adheres to the [Rust Code of Conduct][rust-coc]. This code of conduct describes the _minimum_ behavior
expected from all contributors.

If you encounter content or behavior that violates the Code of Conduct, you should report it. There are two ways to do so:

* **Contact the Nexus team**. You can reach out directly or via [Discord](https://discord.com/invite/nexus-xyz).
* **Use the GitHub "Report content" feature**. To report inappropriate content (such as comments, issues, or pull requests) directly on GitHub, click the "Report content" option (usually available via the three-dot menu next to the content) and follow the instructions. This helps ensure that violations are addressed promptly and appropriately.

### Ways to contribute

There are three main ways to contribute:

1. **By reporting an issue:** If you believe that you have uncovered a bug in this repository, report it by creating a new issue in the [GitHub][gh] issue tracker. See below for an extended discussion on how to make a bug report most helpful.
2. **By adding information:** Even if collaborators are already aware of your issue, you can always provide additional context, such as further evidence in the form of reproduction steps, screenshots, code snippets, or logging outputs.
3. **By resolving an issue:** Typically this is done in the form of either demonstrating that the issue reported is not a problem after all in a polite, thoughtfully explained, and evidence supported manner, or by opening a pull request that fixes the underlying problem and participating in its review and refinement.

**Anybody can participate in any stage of contribution**. We urge you to participate in all discussions around bugs, feature requests, existing code, and PRs.

## Reporting Issues

#### Asking for help

If you have reviewed this document and existing documentation and still have questions or are still having problems, but don't quite know enough to create a bug report, then
you can get help by **starting a discussion**.

You can do so on the [Discord][discord].

#### Submitting a bug report

If you believe that you have uncovered a bug, please describe it to the best of your ability, and provide whatever context and evidence you have. Don't worry if you cannot provide every detail, just give us what you can. Contributors will ask follow-up questions if something is unclear.

As a starting point, in a bug report we will pretty much always want:

- the platform you are on, ideally both the operating system (Windows, macOS, or Linux) and the machine architecture (_e.g.,_ if you're using an M-series Mac) if you know them;
- console logs from the CLI or web application showing errors and status messages;
- concrete and comprehensive steps to reproduce the bug.

Code snippets should be as minimal as possible. It is always better if you can reproduce the bug with a small snippet that focuses on your Nexus zkVM usage rather than on the surrounding code in your project. This will help collaborators verify, reproduce, and zero in on a fix.

See [this guide][mcve] on how to create a minimal, complete, and verifiable example.

#### Submitting a feature request

Please include as detailed an explanation as possible of the feature you would like, and add any additional context you think may be necessary or just helpful.

If you have examples of other tools with the feature you are requesting, please include references/links to them as well.

## Resolving Issues

Pull requests are the way concrete changes are made to the code, documentation, and dependencies of the Nexus network.

Before making a large change, it is usually a good idea to first open an issue describing the change to solicit feedback and guidance.
This will increase the likelihood of the PR getting merged. Striking up a discussion on the [Discord][discord] to let the community know
what you'll be working on can also be helpful for getting early feedback before diving in.

If you are working on a larger feature, we encourage you to open up a draft pull request and also check in with the [Discord][discord], to make sure that other
contributors are not duplicating work.

#### Discussion

You will probably get feedback or requests for changes to your pull request.
This is a regular and important part of the submission process, so don't be discouraged! Some reviewers may sign off on the pull
request right away, others may have more detailed comments or feedback. This is a necessary part of the process in order
to evaluate whether the changes are correct and necessary.

Remember to **always be aware of the person behind the code**. _How_ you communicate during reviews (of your code or others!) can have a significant impact on the success
of the pull request. We never want the cost of a change that makes the Nexus network better to be a valued contributor not
wanting to have anything to do with the project ever again. The goal is not just having good code. It's having a positive community that continues to turn good code into better code.

#### Abandoned or stale pull requests

If a pull request appears to be abandoned or stalled, it is polite to first check with the contributor to see if they
intend to continue the work before checking if they would mind if you took it over (especially if it just has minor revisions
remaining). When doing so, it is courteous to give the original contributor credit for the work they started, either by
preserving their name and e-mail address in the commit log, or by using the `Author: ` or `Co-authored-by: ` metadata
tag in the commits.

[rust-coc]: https://github.com/rust-lang/rust/blob/master/CODE_OF_CONDUCT.md

[gh]: https://github.com/nexus-xyz/nexus-cli

[discord]: https://discord.com/invite/nexus-xyz

[mcve]: https://stackoverflow.com/help/mcve

[reth-contributing]: https://github.com/paradigmxyz/reth/blob/main/CONTRIBUTING.md
