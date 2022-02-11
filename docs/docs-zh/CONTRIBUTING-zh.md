# 贡献指南

感谢你花费宝贵的时间为 XQUIC 做出贡献，我们欢迎所有类型的贡献。以下是我们的贡献指南：

- [贡献指南](#贡献指南)
  - [行为准则](#行为准则)
  - [提交 Issue](#提交-issue)
    - [问题](#问题)
    - [错误](#错误)
    - [安全漏洞](#安全漏洞)
    - [新特性](#新特性)
  - [提交 Pull Request](#提交-pull-request)
    - [贡献者许可协议 (CLA)](#贡献者许可协议-cla)
    - [贡献文档](#贡献文档)
    - [贡献代码](#贡献代码)
      - [环境配置](#环境配置)
      - [工作分支](#工作分支)
      - [提交信息](#提交信息)
      - [测试](#测试)
      - [变基和压缩](#变基和压缩)
      - [创建 Pull Request](#创建-pull-request)
      - [代码评审](#代码评审)
  - [编码风格](#编码风格)
  - [贡献者](#贡献者)

## 行为准则

请先阅读并遵守XQUIC社区的[行为准则](../../CODE_OF_CONDUCT.md)。

## 提交 Issue

请按照[相关模板](https://github.com/alibaba/xquic/issues/new)来报告问题。

### 问题

GitHub Discussions 是一个开放的论坛，供社区之间进行交流。如果你对XQUIC项目有任何疑问，或者有任何想与社区成员讨论的问题，欢迎移步[讨论区](https://github.com/alibaba/xquic/discussions)开启一个新的讨论话题。

### 错误

如果你在源码中发现了一个错误或Bug，你可以通过提交 Github Issue 来帮助我们，我们希望你提交的错误报告是：
* 可复现的：包括复现该问题的步骤；
* 具体的：包括尽可能多的细节：版本、环境等；
* 独特的：不要重复已有的问题；
* 每个错误报告只包含一个错误；

### 安全漏洞

漏洞信息是非常敏感的，请不要通过 GitHub Issue 来报告。如果你在这个项目中发现了潜在的安全漏洞，请发邮件到 xquic@alibaba-inc.com。你可以查看我们的[安全政策](https://github.com/alibaba/xquic/security/policy)以了解更多细节。

### 新特性

如果该项目没有你所希望的特性，你可以提交一个 Github Issue 来请求一个新特性。请尽量清楚地说明为什么现有的功能和替代方案对你不适用。

如果你想实现一个新特性，建议首先提交一个Github Issue 阐述你的建议，以便社区可以及时Review并提供反馈。尽早获得反馈将有助于确保你的实现被社区所接受，这也将使我们能够更好地协调我们的工作，并尽量减少重复的工作。

## 提交 Pull Request

### 贡献者许可协议 (CLA)

在我们接受你的贡献之前，我们需要你签署[贡献者许可协议](https://cla-assistant.io/alibaba/xquic)。签署贡献者协议并不授予任何人对代码仓库的提交权限，但是它意味着我们可以接受您的贡献，并且如果我们这样做，您将获得一个作者标注。活跃贡献者可能会被邀请加入核心团队，并有权限合并 Pull Request。

### 贡献文档

文档是我们项目的重要部分，如果你希望帮助我们改进、更新或翻译文档，请别犹豫！我们欢迎你的参与，帮助我们把文档做得更好。

文档的 Review 流程与代码相同，即使你只是改写一个句子使语义更清晰，或修正一个错字，都欢迎提交 Pull Request。

### 贡献代码

我们使用“Fork and Pull”模式对XQUIC代码库进行贡献。

理想的贡献流程如下：

#### 环境配置

有关开发环境设置的说明，请参见[快速入门指南](../../README.md)。

#### 工作分支

对于每个新功能，都要创建一个开发分支。大多数情况下，该开发分支基于主干分支。

```bash
git checkout -b {branch-name} main
```

_分支命名_:
* `dev/${feature_name}`: 新增功能
* `fix/${function_or_module_name}`: 问题修复
* `perf/${optimization_item}`: 性能优化
* `doc/${documentation_name}`: 文档修改

#### 提交信息

提交信息需要遵循以下格式：

_模板_:

```bash
[<类型>]: <说明>
<空行>
<内容>
<空行>
<脚注>
```

_类型_:
* `+`: 新增特性 / 新完成了一个需求
* `-`: 删除废弃的代码或者功能
* `=`: 和之前的行为保持一致，一般为代码优化
* `~`: 改动了行为，有时候修复bug也会改变既有行为

_举例_:

```bash
[~] Update CONTRIBUTING.md
```

#### 测试

请运行并确保所有现有的测试用例通过，并为你添加或修改的代码编写足够的测试，以验证你的改动是否符合预期。

#### 变基和压缩

如果上游的主干分支有任何提交，你应该 rebase 你的开发分支.

```bash
git checkout {branch-name} 
git rebase main
```

现在，我们可能需要将一些较小的 commit 压缩成少数较大的、有效的 commit ，来删除无效提交信息。你可以通过 interactive rebase 来实现。

```bash
git rebase -i main
```

这将打开一个文本编辑器，你可以指定要 squash 哪些提交。

#### 创建 Pull Request

一旦你验证了所有的 CI 都通过了，就去你的 fork 页面，选择你的开发分支，然后点击 Pull Request。
如果你的 PR 与一个 Issue 有关，在你的 PR 的描述中添加一行，写上 `Fixes: #123` ，其中 `#123` 是你要修复的问题的编号。

#### 代码评审

所有提交的代码都将被 Review 并测试。评审员可能会提出问题，请查看你的PR以保持对话。

在合并PR之前，要压缩无效的提交信息，包括反馈、错字、合并和Rebase。最后的提交信息应该是清晰简明的。

## 编码风格

我们遵循[Nginx编码风格](http://nginx.org/en/docs/dev/development_guide.html#code_style)，以下几点需要特别注意：

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

## 贡献者

XQUIC开发团队：大淘宝平台技术团队、达摩院XG实验室以及为项目提供帮助的阿里巴巴集团的其他团队。

在此，我们要感谢这些为XQUIC贡献代码或为这个项目提供帮助的杰出个人开发者（以下排名不分先后）：

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

名单持续更新，欢迎大家参与贡献！
