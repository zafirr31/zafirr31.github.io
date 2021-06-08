---
layout: post
title:  "Mocking your code in your tests"
description: "For better testing of your code"
permalink: /ppl/mocking-your-code-in-your-tests/
---

## English
Testing is a major part of software development. However, the process is not always as strightforward. Software, and code in general, can be very complex. Because of this, we often reuse code whenever possible to reduce the amount of coding actually required. This becomes problematic for testing though, since a single function could contain lots of other code!

To solve this, we often mock functions we <u>dont</u> want to test. Why the one's we dont want to test? Well the simple assumption is that if a function is called, that function should be tested with a different testcase. Remember, one of the main principles of testing is a single testcase should only test one thing!

<br>

### Mocking
But what is mocking? Mocking is the act of simulating the implementation of a some code, usually on the function or class level. Why do this? Well in some cases functions can be very complex, or they might require calling multiple other functions, or maybe their implementation requires accessing the internet, etc. All of these cases are not important to what we want to test in our testcase, so instead we mock the function. Basically we tell the testing software that whenever a certain function is called, do this instead of running the actualy implementation. This allows us to focus more on the code we actually want to test, instead of the functions that are called within it.

![Error](https://miro.medium.com/max/600/1*fCMBDvJQWR6KokIF-H7iwQ.png)<br>
_source: https://miro.medium.com/max/600/1*fCMBDvJQWR6KokIF-H7iwQ.png_

<br>

### Example
The last sprint in my TBCare project development cycle had me implement google sign in functionality into the TBCare mobile app. Luckily, the code for doing so has already been developed, and is public on [npm](https://www.npmjs.com/package/@react-native-community/google-signin)!

The code I will end up building (or have already written) is that similar to the examples given in the npm page.

```jsx
signIn = async () => {
  try {
    await GoogleSignin.hasPlayServices();
    const userInfo = await GoogleSignin.signIn();
    this.setState({ userInfo });
    // Do some things
    navigation.navigate("somewhere")
  } catch (error) {
    // Handle errors
  }
};
```

The functions that should be mocked are the ones from the GoogleSignin library, and the navigation. To do this I used jest mock functions.

Let's list what we want to test. We want to test when hasPlayServices and Signin are successful then navigate should be called once. To do this, we follow how hasPlayServices and Signin work. According to the [github page](https://github.com/react-native-google-signin/google-signin), hasPlayServices should return true if successful, and Signin should return userInfo (a JSON object with some data). Let's see how this can be done:

```jsx
  const mockHasPlayServices = jest.fn().mockImplementationOnce(() => new Promise(resolve => {
    resolve(true);
  }));
  
  const mockSignin = jest.fn().mockImplementationOnce(() => new Promise(resolve => {
    const data = {
      idToken: "1234",
      serverAuthCode: "4321",
      user: {
        email: "test@gmail.com",
        id: "1234",
        givenName: "test",
        familyName: "test",
        photo: "test.com", // url
        name: "test" // full name
      }
    }
    resolve(data);
  }));

  GoogleSignin.hasPlayServices = mockHasPlayServices
  GoogleSignin.signIn = mockSignin
```

Since they are async functions, we return a promise that just resolves to what we expect, true and the userInfo. Now that they're mocked, we can continue testing our code that would be at the `// Do some things` comment. At the end, navigation.navigate is called. This should shift the scene from one scene to the next, but we will just mock this too!

```jsx
const mockNavigation = jest.fn();
jest.mock('@react-navigation/native', () => {
  return {
    ...jest.requireActual('@react-navigation/native'),
    useNavigation: () => ({
      navigate: mockNavigation,
    }),
  };
});
```

This is the same as the GoogleSignin mock above, I just wanted to try new things :).

You may have noticed I didn't mock the implementation. This is intentional, when no mockImplementation is set, the function does well, nothing. This is fine, since in our test  we dont care what navigation does (it doesn't affect the try-catch or return anything).

Now I'll add a few expect calls to make sure everything had worked in the end.

```jsx
  await expect(mockHasPlayServices).toBeCalledTimes(1);
  await expect(mockSignin).toBeCalledTimes(1);
  await expect(mockNavigation).toBeCalledTimes(1);
```

And that's it. Now the rest of the testcase would be testing the actual code, but that's out of the scope of this blog post. Here's the resulting testcase:

```jsx
const mockNavigation = jest.fn();
jest.mock('@react-navigation/native', () => {
  return {
    ...jest.requireActual('@react-navigation/native'),
    useNavigation: () => ({
      navigate: mockNavigation,
    }),
  };
});

it('receives nothing when signin failed and fails to navigate to next scene', async () => {

  // Setup testcase code here

  const mockHasPlayServices = jest.fn().mockImplementationOnce(() => new Promise(resolve => {
    resolve(true);
  }));
  
  const mockSignin = jest.fn().mockImplementationOnce(() => { 
    throw new Error("signin error");
  });

  GoogleSignin.hasPlayServices = mockHasPlayServices
  GoogleSignin.signIn = mockSignin

  // Do some testing

  await expect(mockHasPlayServices).toBeCalledTimes(1);
  await expect(mockSignin).toBeCalledTimes(1);
  await expect(mockNavigation).toBeCalledTimes(1);
});
```

That's all for this blog post, happy coding!

### Sources
* [Jest](https://jestjs.io/docs/mock-functions)