---
layout: post
title:  "Developing a mobile app with react native"
description: "It's as simple as reactJS!"
permalink: /ppl/developing-a-mobile-app-with-react-native/
---

## English
It's not uncommon for people nowadays to own a smartphone. With the economy of many countries increasing steadily, and the cost of some smartphones becoming relatively cheap, the market for software developed for smartphones is also expanding. 

There are currently two large smartphone operating systems, Android and iOS. These operating systems have different setups, so developing an app may require setting up two projects. Instead, many mobile app programming languages and frameworks come with the option to build to both platforms, one such example is the framework React Native.

<br>

### React Native
![Error](https://miro.medium.com/max/1024/1*xDi2csEAWxu95IEkaNdFUQ.png)<br>
_source:https://miro.medium.com/max/1024/1*xDi2csEAWxu95IEkaNdFUQ.png_

React Native is a mobile app programming framework that allows programmers to code ReactJS-like code for mobile app development. If you do not know what ReactJS is, feel free to click [this link](https://reactjs.org/) to read more about it.

The basic principle is the same. In ReactJS, we code what is called "components". These components will interact with one another in a hierarchical structure, with one compoenent having "children" of other components. The ReactJS code that we write in React Native however, instead of being converted into JS6 code will be converted into the respective code for each operating system (java for android and C for iOS).

<br>

### Setup
There are multiple ways to setup a React Native project, you could use expo (run it in your browser), your smartphone, or an emulator. For this blog post, I will show how to set it up in an **<u>emulator</u>** for android development.

#### Step 1
The first step is to download android studio. Download the latest version [here](https://developer.android.com/studio)

#### Step 2
Next we need to install node version 12 or above, and jdk 8 or above. You acn do so using these bash commands:

```bash
sudo apt install nodejs
sudo apt-get install openjdk-8-jdk
java -version # Keep note of version
sudo update-alternatives --set java /usr/lib/jvm/jdk1.8.0_<version from above command>/bin/java
```

#### Step 3
Now open android studio and download an emulator. Below is how to do so

Click configure and select AVD Manager

![Error](/assets/images/PPL/React_Native/1.png)

Click the button "Create Virtual Device..."

![Error](/assets/images/PPL/React_Native/2.png)

Choose the desired hardware. This can be a phone, TV, tablet etc. For this example I will use a Pixel 4 emulator

![Error](/assets/images/PPL/React_Native/3.png)

Choose the system image. This is the version of Android you will develop in. The latest version is usually best, but since Android R is still quite new I will use android Q

![Error](/assets/images/PPL/React_Native/4.png)

Last configuration such as name, orientation, ram, can be setup here. I did not change any settings here.

![Error](/assets/images/PPL/React_Native/5.png)

The emulator should appear in the AVD manager now.

![Error](/assets/images/PPL/React_Native/6.png)

There may be some installing required if it is your first time, and they can be quite large in space (around 8 GB). Make sure you have enough storage space.

#### Step 4 (Optional)
To check whether or not the emulator works, run the emulator and then run the command 

```bash
adb devices
```

There should appear one device

![Error](/assets/images/PPL/React_Native/7.png)

<br>

### Running
For this example, I will be using the TBCare mobile app code that has already been developed. If you do not already have a react native project, you can initialize one with the command

```bash
npx react-native init <Project name>
```

Now in the project folder, run the command (make sure the emulator is running)

```bash
npx react-native run-android
```

Your project should be running in the emulator automatically.

![Error](/assets/images/PPL/React_Native/8.png)

The command prompt on the bottom left of that image is running metro. This is the javascript bundler that is used by react native to create the app in the emulator. This useful thing is, be default our app will run in debug mode. This means whatever we change in the source code will automatically update in the app!

<br>

### Development
To develop, we can just edit the code in the App.js file, just like a regular ReactJS project. Also like ReactJS, we can break down our code into components. However, there is one more point I would like to touch on, which is navigation

<br>

### Navigation
We can think of navigation like webpages for a website. Instead of lumping every piece of code into one page, we break down the code into make pages (in react native they are called screens). To define screens, we can use a NavigationContainer

(In App.js)
```
<NavigationContainer ref={navigatorRef} theme={navigationTheme}>
  <Stack.Navigator
    screenOptions={{
    // Empty header
    header: () => <></>,
    }}>
    // We will add our scenes here
  </Stack.Navigator>
</NavigationContainer>
```

We already have many scenes in our TBCare project, so I will show the work I did the last sprint, a Google Signin functionality. The Google Signin feature requested required a form to input the users phone number and address, so I created a new scene for that called OfficerSignupFormGoogleSignin. So, I added the following code to the navigation container


```
<NavigationContainer ref={navigatorRef} theme={navigationTheme}>
  <Stack.Navigator
    screenOptions={{
    // Empty header
    header: () => <></>,
    }}>
    .
    .
    .
    <Stack.Screen
      name="officer-signup-form-google-signin"
      component={OfficerSignupFormGoogleSignin}
     />
     .
     .
     .
  </Stack.Navigator>
</NavigationContainer>
```

Now I added a button to the login page like below

![Error](/assets/images/PPL/React_Native/9.png)

The code:

```
<Box
  mainAxis="center"
>
  <GoogleSigninButton
  style={{ width: 192, height: 48 }}
  size={GoogleSigninButton.Size.Wide}
  color={GoogleSigninButton.Color.Dark}
  onPress={() => signInWithGoogle()}
  />
</Box>
```

Now when the GoogleSigninButton button is pressed, signInWithGoogle is called, which does the following

```
const signInWithGoogle = async () => {
  try {
    await GoogleSignin.signOut();
    await GoogleSignin.hasPlayServices();
    const tempUserInfo = await GoogleSignin.signIn();
    setUserInfo(tempUserInfo);
    const noGoogleUser = await checkIfTokenHasCorrespondingUser(tempUserInfo.idToken);
    if(noGoogleUser)
      navigation.navigate('officer-signup-form-google-signin', {idToken: tempUserInfo.idToken});
  } catch (error) {
    if (error.code === statusCodes.SIGN_IN_CANCELLED) {
      // user cancelled the login flow
    } else if (error.code === statusCodes.IN_PROGRESS) {
      // operation (e.g. sign in) is in progress already
    } else if (error.code === statusCodes.PLAY_SERVICES_NOT_AVAILABLE) {
      setAlert({
        illustration: WonderingIllustration,
        message: "Play Service sedang tidak tersedia, coba lagi nanti",
      })
    } else {
      }
  }
};
```

The code basically logs in using google, google returns a token, and that token is then used in our app. Note the `navigation.navigate('officer-signup-form-google-signin', {idToken: tempUserInfo.idToken});`. If you see the code before, "officer-signup-form-google-signin" is the name of the screen. This will move the app to the screen with the form. Now we continue with writing the OfficerSignupFormGoogleSignin to continue development.

Result:

![Error](/assets/images/PPL/React_Native/9.png)

Shifts to

![Error](/assets/images/PPL/React_Native/10.png)

### Closing statements
Now that the basics are covered, go ahead try coding your own React Native App. Happy coding!

### Sources
* [React Native](https://reactnative.dev/)
* [Setup](https://reactnative.dev/docs/environment-setup)
* [React Navigation](https://reactnavigation.org/)