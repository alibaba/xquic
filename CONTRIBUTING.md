# Contributing to XQUIC

> [简体中文文档 CONTRIBUTING-zh-CN](./docs/docs-zh/CONTRIBUTING-zh.md)

Thank you for investing your time in contributing to our project! All types of contributions are encouraged and valued. As a contributor, here are the guidelines we would like you to follow:

- [Contributing to XQUIC](#contributing-to-xquic)
  - [Code of Conduct](#code-of-conduct)
  - [Submitting an Issue](#submitting-an-issue)
    - [Questions](#questions)
    - [Bugs](#bugs)
    - [Security Vulnerability](#security-vulnerability)
    - [New Features](#new-features)
  - [Submitting a Pull Request](#submitting-a-pull-request)
    - [Contributor License Agreement (CLA)](#contributor-license-agreement-cla)
    - [Contributing Documentation](#contributing-documentation)
    - [Contributing Code](#contributing-code)
      - [Initial Setup](#initial-setup)
      - [Working Branch](#working-branch)
      - [Commit Messages](#commit-messages)
      - [Tests](#tests)
      - [Rebase and Squash](#rebase-and-squash)
      - [Pull Request](#pull-request)
      - [Code Review](#code-review)
  - [Code Style](#code-style)
  - [All-contributors](#all-contributors)

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to keep our community approachable and respectable.

## Submitting an Issue

Please follow the [template](https://github.com/alibaba/xquic/issues/new) for reporting any issues.

### Questions

GitHub Discussions is an open forum for conversation among maintainers and the community. If you have a question about this project, how to use it, or just need clarification about something, please open a new Discussion topic in our [discussion forums](https://github.com/alibaba/xquic/discussions).

### Bugs

If you run into an error or bug with the project, you can help us by submitting a GitHub Issue.
Please try to create bug reports that are:
* _Reproducible_. Include steps to reproduce the problem.
* _Specific_. Include as much detail as possible: which version, what environment, etc.
* _Unique_. Do not duplicate existing opened issues.
* _Scoped to a Single Bug_. One bug per report.

### Security Vulnerability

Vulnerability information is extremely sensitive, please do not open a GitHub Issue.
If you have discovered potential security vulnerability in this project, please send an e-mail to xquic@alibaba-inc.com. You can review our [security policy](https://github.com/alibaba/xquic/security/policy) for more details.

### New Features

If the project doesn't do something you need or want it to do, you can submit an Github Issue to request a new feature. Please try and be clear about why existing features and alternatives would not work for you.

If you are suggesting a feature that you are intending to implement, please create an issue first to communicate your proposal so that the community can review and provide feedback. Getting early feedback will help ensure your implementation work is accepted by the community. This will also allow us to better coordinate our efforts and minimize duplicated effort.

## Submitting a Pull Request

### Contributor License Agreement (CLA)

Before we accept a non-trivial patch or pull request we will need you to sign the [Contributor License Agreement](https://cla-assistant.io/alibaba/xquic). Signing the contributor’s agreement does not grant anyone commit rights to the main repository, but it does mean that we can accept your contributions, and you will get an author credit if we do. Active contributors might be asked to join the core team, and given the ability to merge pull requests.

### Contributing Documentation

Documentation is an important part of our project. If you wish to help us improve, update or translate the documentation, please don’t hesitate! We welcome your participation to help make the documentation better.

Documentation undergoes the same review process as code. Feel free to submit a Pull Request even if you're just rewording a sentence to be more clear, or fixing a typo.

### Contributing Code

We use the "Fork and Pull" model to contribute to the XQUIC codebase.

A rough outline of an ideal contributors' workflow is as follows:

#### Initial Setup

For instructions regarding development environment setup, please visit the quickstart guide.

#### Working Branch

For each new feature, create a working branch from where to base the contribution. Mostly, it's the main branch.

```bash
git checkout -b {branch-name} main
```

_Branch name_:
* `dev/${feature_name}`: New feature
* `fix/${function_or_module_name}`: Bug fix
* `perf/${optimization_item}`: Performance optimization or other enhancement
* `doc/${documentation_name}`: Documentation

#### Commit Messages

Each commit message consists of a header, a body and a footer. The header has a special format that includes a type and a subject:

_Template_:

```bash
[<type>]: <subject>
<BLANK LINE>
<body>
<BLANK LINE>
<footer>
```

_Type_:
* `+`: Add a new feature / a new requirement
* `-`: Remove deprecated code or functionality
* `=`: Consistent with previous behaviour, generally representing code optimisation
* `~`: Changed behaviour, sometimes fixing bugs can also change existing behaviour

_Example_:

```bash
[~] Update CONTRIBUTING.md
```

#### Tests

Run the full test suite and ensure that all existing tests pass.

Write sufficient relevant tests for the code being added or changed, to verify that your contribution works as expected. 

#### Rebase and Squash

If any commits have been made to the upstream main branch, you should rebase your development branch so that merging it will be a simple fast-forward that won't require any conflict resolution work.

```bash
git checkout {branch-name} 
git rebase main
```

Now, it may be desirable to squash some of your smaller commits down into a small number of larger more cohesive commits. You can do this with an interactive rebase:

```bash
git rebase -i main
```

This will open up a text editor where you can specify which commits to squash.

#### Pull Request

Once you've validated that all continuous-integration checks have passed, go to the page for your fork on GitHub, select your development branch, and click the pull request button.

If your PR is connected to an open issue, add a line in your PR's description that says `Fixes: #123` , where `#123` is the number of the issue you're fixing.

#### Code Review

All code submissions will be rigorously reviewed and tested. Reviewers may have questions, check back on your PR to keep up with the conversation.

Before merging a PR, squash any fix review feedback, typo, merged, and rebased sorts of commits. The final commit message should be clear and concise.

## Code Style

We follow the [Nginx code style](http://nginx.org/en/docs/dev/development_guide.html#code_style), with the following points requiring special attention.

* maximum text width is 80 characters
* indentation is 4 spaces
* no tabs, no trailing spaces
* list elements on the same line are separated with spaces
* Macro names start from xqc_ or XQC_ (or more specific) prefix. Macro names for constants are uppercase. Parameterized macros and macros for initializers are lowercase.

* “//” comments are not used
* multi-line comments are formatted like this:

```C
/*
 * The red-black tree code is based on the algorithm described in
 * the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.
 */
 
/* find the server configuration for the address:port */
```

* All functions (even static ones) should have prototypes. Prototypes include argument names. Long prototypes are wrapped with a single indentation on continuation lines:
* The function name in a definition starts with a new line. The function body opening and closing braces are on separate lines. The body of a function is indented. 
* There is no space after the function name and opening parenthesis. Long function calls are wrapped such that continuation lines start from the position of the first function argument. If this is impossible, format the first continuation line such that it ends at position 79.

* Binary operators except “.” and “−>” should be separated from their operands by one space. Unary operators and subscripts are not separated from their operands by spaces:
* If an expression does not fit into single line, it is wrapped. The preferred point to break a line is a binary operator. The continuation line is lined up with the start of expression.

* The “if” keyword is separated from the condition by one space. Opening brace is located on the same line, or on a dedicated line if the condition takes several lines. Closing brace is located on a dedicated line, optionally followed by “else if / else”. Usually, there is an empty line before the “else if / else” part. Similar formatting rules are applied to “do” and “while” loops.
* The “switch” keyword is separated from the condition by one space. Opening brace is located on the same line. Closing brace is located on a dedicated line. The “case” keywords are lined up with “switch”.

## All-contributors

XQUIC participants: Taobao Technology Department, Damo Academy XG Lab, and other teams from Alibaba Group who provided help in deployment of this project.

In no particular order, thanks to these excellent individuals who contributed code to XQUIC or provided great help to the survival of this project.

* 左春伟(平兴)
* 胡军伟(苍茫)
* 施威(不达)
* 洪海(孤星)
* 李鼎(哲良)
* 杜叶飞(淮叶)
* 朱宇(黎叔)
* 罗凯(懿彬)
* 曾柯(毅丝)
* 徐盟欣(象谦)
* Bai Shi(白石)

This list will be continuously updated. Contributions are welcome!
