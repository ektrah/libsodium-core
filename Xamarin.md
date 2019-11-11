# Using Sodium.Core with Xamarin

## NuGet package

Install the [Sodium.Core](https://www.nuget.org/packages/Sodium.Core/) NuGet package in your Xamarin core project.

## Compile the native libraries

Installing the NuGet is not enough. You will have to compile the libsodium library for iOS and Android yourself, because they are not provided out of the box.

*The following instructions have been tested on Mac OS 10.14, using libsodium 1.0.18 and the [installation](https://download.libsodium.org/doc/installation) documentation.*

[Download the latest stable version](https://download.libsodium.org/libsodium/releases/) (for example `libsodium-1.0.18-stable.tar.gz`) and untar it:

```bash
tar xzf libsodium-1.0.18-stable.tar.gz
cd libsodium-stable
```

Then run the commands:

```bash
./configure
make && make check
sudo make install
```

Make sure everything went fine.

### Compile and install on iOS

First, make sure that you have the Xcode Command Line Tools properly installed and configured. Run:

```bash
xcode-select -p
```

It should return something of the form `/Applications/Xcode.app/Contents/Developer`.

If it doesn't, run

```bash
sudo xcode-select -s /Applications/Xcode.app
```

*note*: `/Applications/Xcode.app` is the path to your Xcode installation.

Then, run the command:

```bash
LIBSODIUM_FULL_BUILD=true dist-build/ios.sh
```

This will create the library in `libsodium-ios/lib/libsodium.a`.

In Visual Studio - in the Xamarin.iOS project - add this new file in your project. Make sure that the *Build Action* of the file is *None*. Right-click in the iOS project and do  "Add > Add Native Reference". Select the file you have just added.

### Compile and install on Android

First, make sure that you have installed the [Android NDK](https://developer.android.com/ndk/), and that you have the `ANDROID_NDK_HOME` environment variable. For example using:

```bash
export ANDROID_NDK_HOME=/Users/john/Library/Android/sdk/ndk/20.0.5594570
```

Then run the commands:

```bash
dist-build/android-x86.sh
dist-build/android-x86_64.sh
dist-build/android-armv7-a.sh
dist-build/android-armv8-a.sh
```

This will create 4 new folders that each contain the *libsodium.so* file. Beware of using the **.so** file and not the **.a** file like you did for iOS.

In you Xamarin.Android project create a new folder `Resources/lib/`. Inside, create 4 new folders called `x86`, `x86_64`, `armeabi-v7a` and `arm64-v8a`. Inside those folders add the *libsodium.so* files following the mapping:

| libsodium folder           | Xamarin.Android folder |
| -------------------------- | ---------------------- |
| libsodium-android-i686     | x86                    |
| libsodium-android-westmere | x86_64                 |
| libsodium-android-armv7-a  | armeabi-v7a            |
| libsodium-android-armv8-a  | arm64-v8a              |

Change the *Build Action* of the files to *AndroidNativeLibrary*.

## Usage

You can now use libsodium inside your Xamarin code, by including the package `Sodium`. For example:

```csharp
var version = Sodium.SodiumCore.SodiumVersionString();
Console.WriteLine($"Libsodium version: {version}");
```
