# Contributing

## Table of Contents

- [Things to Know](#things-to-know)
- [Developer Dependencies](#developer-dependencies)
- [Developing Process: The short version](#developing-process-the-short-version)
- [Developing Process: The long version](#developing-process-the-long-version)
- [Release overview (for the more regular contributors)](#release-overview--for-the-more-regular-contributors-)
- [Developer Notes](#developer-notes)
- [Code of Conduct](#code-of-conduct)

## Things to Know

Refer to [this](https://pesos.github.io/projects/about-rshark#learning-path-for-rshark) learning path to know the knowledge typically required to help contribute to Rshark

## Developer Dependencies

1. Install Rust using [`rustup`](https://www.rust-lang.org/tools/install).
2. [`cargo`](https://doc.rust-lang.org/cargo/guide/index.html) is a command line utility that is part of the Rust toolchain that can be used to install additional tools.
3. Install [`rustfmt`](https://github.com/rust-lang/rustfmt#quick-start) on the stable toolchain. `rustfmt` will be used to format code.

## Developing Process: The short version

1. Select an issue to work on, and inform the maintainers
2. Fork the project.
3. `git clone` the forked version of the project.
4. Work on the master branch for smaller patches and a separate branch for new features
5. After writing some code, run `cargo fmt` and `cargo test`.
6. If all tests are passing, pull changes from the original remote with a rebase, and push the changes to your remote repository.
7. Use the GitHub website to create a Pull Request and wait for the maintainers to review it.

## Developing Process: The long version

- Look for issues in the repository. Identify an issue you would like to work on.
- Once you have done that, leave a comment on the issue saying that you want to work on it. The maintainers will give you the go-ahead.
- Fork the repository. Your changes will be made on its `master` branch, or on the appropriate feature branch if applicable
- Clone the fork on your system. Add a remote to the original `pesos/rshark` repository called `upstream`
```
git clone https://github.com/<your-github-username>/rshark.git
git remote add upstream https://github.com/pesos/rshark.git
```
- Make your changes and commit them
```
git add <names of all the modified files>
git commit
```

- Make your commit descriptive. The above command will open your text editor. Write the commit message on the first line and a short description about your change. Save and quit the editor to commit your change.

- Before pushing your changes, make sure that the changes from upstream are included (use `--rebase` to make sure that your changes stay on top of the latest changes in the upstream repository)
```
git pull --rebase upstream master     # if you are working on a feature branch, use that branch name instead of master
```

- In the *extremely* small chance that you run into a conflict, just open the files having the conflict and remove the markers and edit the file to the one you want to push. After editing, run `git rebase --continue` and repeat till no conflict remains

- Verify that your program builds and passes all the tests, and your change actually works in general
- Push your changes to your fork
```
git push origin master      # if you are working on a feature branch, use that branch name instead of master
```
- Visit your forked repository and click on "Pull Request". The Pull Request must always be made to the `pesos/master` branch. Add the relevant description. At this point your name will be assigned to the original issue.
- The maintainers will review your code and see if it is okay to merge. It is quite normal for them to suggest you to make some changes in this review.
- if you are asked to make changes, all you need to do is:
```
# make your change
git add <files that you changed>
git commit
git push origin master      # if you are working on a feature branch, use that branch name instead of master
```
- The changes are immediately reflected in the pull request. Once the maintainers are satisfied, they will merge your contribution :)

As long as you follow the above instructions things should go well. You are always welcome to ask any questions about the process, or if you face any difficulties in the `#rshark-help` channel on the PES Open Source Slack.

## Release overview (for the more regular contributors)

- master branch for development. Small patches/enhancements go here.
- stable branch for tagged releases. This is the branch that will be shipped to users.
- Separate feature-x branches for adding new "big" features. These branches are merged with master, on completion.
- Once we are satisfied with a certain set of features and stability, we pull the changes from master to stable. A new release tag is made.
- If bugs were found on the stable release, we create a hotfix branch and fix the bug. The master branch must also pull the changes from hotfix. A new release tag is created (incrementing with a smaller number).

## Developer Notes

* To build the binary, run `cargo build`. This will place a binary in `target/debug` folder.
* Recommended way to run the binary would be `sudo ./target/debug/rshark`.
* Please run `cargo test` and `cargo fmt` before commiting any code.
* If you run into any problems, please feel free to ask the maintainers or other contributors.

## Code of Conduct

This project follows the [PES Open Source Code of Conduct](https://pesos.github.io/coc)
