---
layout: post
title:  "Clean Code"
description: " "
permalink: /ppl/clean-code/
---

![Error](https://miro.medium.com/max/3200/1*H-MBSTjpf0-8DYxWoQ2KOw.png)<br>
_source: https://miro.medium.com/max/3200/1*H-MBSTjpf0-8DYxWoQ2KOw.png_

## English
As a programmer, creating clean code is a must. Clean code allows for easy to read, understand, and modifiable code. With the growing need for large scale software, creating clean code has never been more important. 

<br>

## What is clean code
Clean code refers to a book written by Robert C. Martin in 2008. Although the book mainly focuses on Java development, many programmers apply the principles shown in the book to other programming languages. In this blog post specifically, I will try to show how I applied 7 rules during my development time for TBCare.

<br>

## 1. Follow a consistant coding standard
Every programming language has a coding standard. For PHP, it's PSR-2. For python, it's PEP-8. For javascript, well many people have written their own. To make things easy, I follow the [google javascript coding standard](https://google.github.io/styleguide/jsguide.html)

Here's an example of code from the tbcare-mobile project:

```js
const signInWithGoogle = async () => {
  try {
    await GoogleSignin.signOut();
    await GoogleSignin.hasPlayServices();
    const userInfo = await GoogleSignin.signIn();
    const noGoogleUser = await checkIfTokenHasCorrespondingUser(userInfo.idToken);
    if(noGoogleUser)    {
      navigation.navigate('officer-signup-form-google-signin', {idToken: userInfo.idToken});
    }
  } catch (error) {
    ...
  }
};
```

The code follows the formatting guide by google, which states indentation should be 2, brackets should always be used in if statements, etc.

<br>

## 2. Name things properly
Naming conventions exist, and they should be upheld throughout the entire project. This means that if you use camelCase, stick to camelCase for all variables and functions. If you use snake_case, stick to snake_case for all variables and functions. Etc.

Besides naming conventions, make sure the names clearly indicate what they do, but are not too long. 

Take example the previous code. The function name is signInWithGoogle, which indicates well a function to sign in with google. The convention is consistant (camelCase), and the variables indicate what they represent.

<br>

## 3. Be expressive
Sometimes, writing code needs to be verbose. This allows the future readers to easily know what is going on. For example, the catch statement from the code above looks a little as such:

```js
if (error.code === statusCodes.SIGN_IN_CANCELLED) {
  // user cancelled the login flow
} else if (error.code === statusCodes.IN_PROGRESS) {
  // operation (e.g. sign in) is in progress already
} else if (error.code === statusCodes.PLAY_SERVICES_NOT_AVAILABLE) {
  // user does not have play services
} else {
}
```

The code between isn't important right now, what is important is the if statements, which use a object to represent the codes. The json object used to store those codes make the code more verbose, but easier to read.

Bad code would be like such

```js
if (error.code === 0) {
  // user cancelled the login flow
} else if (error.code === 1) {
  // operation (e.g. sign in) is in progress already
} else if (error.code === 2) {
  // user does not have play services
} else {
}
```

Although there are comments, knowing what the if statements do is still tough and requires more time.

<br>

## 4. Max indent should be 2, with exceptions
This rules is more suited for java development, so the rule I like to uphold is aslong as the code doesn't seem bloated, it is okay. React for instance, since it uses components it usually requires multiple indentations, sometimes up to 5 or 6. This is fine.

<br>

## 5. Avoid long methods
Methods (or functions) in principle should only do one thing. This means we should avoid code that has names like `doXAndY`. However, it is okay for a method to call another when what it does is generally long. The code above is still a good example

```js
const signInWithGoogle = async () => {
  try {
    await GoogleSignin.signOut();
    await GoogleSignin.hasPlayServices();
    const userInfo = await GoogleSignin.signIn();
    const noGoogleUser = await checkIfTokenHasCorrespondingUser(userInfo.idToken);
    if(noGoogleUser)    {
      navigation.navigate('officer-signup-form-google-signin', {idToken: userInfo.idToken});
    }
  } catch (error) {
    ...
  }
};
```

Here, the goal is a single thing, sign in with google. Although, there is another step to do which is to check if user already exists in the database or not. To do so, I call another method which does just that.

<br>

## 6. DRY (Dont repeat yourself)
If a function is required to be done in multiple areas, we can create functions in a single place and just call it over and over. This is useful if you find yourself copying the same blocks of code in many places.

For example, a "token" is used in the TBCare react-native app to save user sessions. Since we have two ways to login, there is a setToken method which we created and we just call it in multiple areas.

<br>

## 7. Avoid in-line comments
In general, the code should explain itself. Although, in some cases comments are required, excessive comments are not good. Robert C. Martin calls comments a code smell, and should be avoided.

<br>

## Conclusion
These rules should be kept as much as possible, although they should not be held as law. Rules have their exceptions, although minimally. Upholding these rules as much as possible will help us created better, cleaning code for the future. Happy coding!

<br>

## Sources
> [Sumet Chhetri](https://shhetri.github.io/clean-code/#/)