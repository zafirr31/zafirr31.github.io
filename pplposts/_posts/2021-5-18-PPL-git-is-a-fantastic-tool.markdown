---
layout: post
title:  "Git is a fantastic tool"
description: ""
permalink: /ppl/git-is-a-fantastic-tool/
---

_Untuk bahasa Indonesia, silakan klik link [ini](#bahasa-indonesia)_

## English
![Error](https://blog.knoldus.com/wp-content/uploads/2020/05/cover-first-steps-git.png)<br>
_source: https://blog.knoldus.com/wp-content/uploads/2020/05/cover-first-steps-git.png_

Being a programmer, git is a tool I am very familiar with. Git is a version control tool, used by programmers to track changed to a codebase. Git is not only fast, but has many uses in controlling even the workflow of some projects. In the project my group and I are developing, we often use many git features to ease our development process.

### Git basics
Let's say we have a project, and we want to use git in this project. The first thing we need to do is:

```bash
$ git init
```

This initializes a .git folder, which is the magic folder that controls everything git related!

![Error](/assets/images/PPL/Git/1.png)

<br>

The basic flow of git is like so:

![Error](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQtdzF_jrEoXlHNV5fRpxKD8xY_3VZDbv9pVjMek7AdP5kKY2YTCYZ-Xe6jYHcLoLQodS8&usqp=CAU)<br>
_source: https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQtdzF_jrEoXlHNV5fRpxKD8xY_3VZDbv9pVjMek7AdP5kKY2YTCYZ-Xe6jYHcLoLQodS8&usqp=CAU_

Basically, when we have a new file we want to track, we _add_ the file. If we are sure this new file is ready, we _commit_ the file.

Let's look at an example:

![Error](/assets/images/PPL/Git/2.png)

![Error](/assets/images/PPL/Git/3.png)

These changes are now save in the .git folder. If we ever edit these files, and want to return to the versions before the edits, we can use git to do so!

### Gitlab
Gitlab is a git-repository manager that can be used by anyone, for **_free_**. It has allowed many programmers ease of control of their projects from a small project even to a big one. My group uses this when developing our project, how so is what I will explain next.

![Error](https://softwareasli.com/wp-content/uploads/2020/04/gitlab.jpeg)


### The git workflow of TBCare
We always like to keep the workflow steady, away from potential bugs, and always up to date. To do so, we implement a TDD system, as well as use gitlab pipelines to automate testing, building, and deployment phases of our project. 

### TDD
Test driven development is a programming style that encourages testing before implementation. This gives a clear image of how the code is supposed to run even before the code is written. This can preven bugs and more. In the context of git, whenever we commit new code, the commit message should clearly represent what the new code is doing.

In our project, the git commit's follow the TDD system. So whenever the testing code is ready, we commit the code with the prefix \[RED\]. When the implementation is ready and it passes the already written tests, we prefix the commit message with \[GREEN\]. After a correct implementation is created, we may want to refactor the code. In this case the commit message's prefix is not \[GREEN\] but instead \[REFACTOR\]. If we push something to the repository that has no correlation with implementation, we use the prefix \[CHORES\].

![Error](/assets/images/PPL/Git/4.png)

### Git branches
A git branch is can be viewed as a workspace in a codebase. Let's say we have two members working on a project. Instead of working in the same branch (workspace) at the same time, instead it's best if they work on their on branch, and then _merge_ the results afterwards. This can all be done with git, and we even implement it in our project!

Usually, for every task that the members of our team get, we create a new branch specific to that task. After we care done, we merge them (I will explain how that works after this).

![Error](/assets/images/PPL/Git/5.png)

### Code reviews and merge requests
When we are done individually with our tasks, we need to merge the changes into a single branch. In our project we call this branch "staging". However, merging is not dont instantly, but instead we create a merge request. A merge request is exactly what it's name implies, a request to merge changes. This merge request is useful, as every member can then see what we did, and give comments aswell as critiques. This is called a code review. For our project, the merge request can only be accepted after atleast 2 members have reviewed and approved of the changes we want to implement.

![Error](/assets/images/PPL/Git/6.png)

![Error](/assets/images/PPL/Git/7.png)

### Pipelines
Pipelines are used by my group to automate otherwise tedious tasks, such as testing and deployment. A pipeline is run on an individual branch everytime there is a change to that branch in the repository. So, a pipeline is run for every instace of `git push` and every merge request that is accepted. These pipelines are useful, because they allow us to make sure that the current state of code in the project is ready.

![Error](/assets/images/PPL/Git/8.png)

### Conclusion
Git is a powerful tool, but although for the basics maybe simple, using it to it's maximum potential can be very complex. As a programmer, knowing how to use it effectively is very useful, for now and for the future.