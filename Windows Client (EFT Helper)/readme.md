# Introduction

The feature shops have been asking for - support to integrate EFTSuite with a live ten-print scanner is finally here! This allows you to scan your customers' prints with ease.


### Initial Considerations

1. You MUST install the IB drivers *and* copy down the EXE and associated DLLs for this app to function.
2. The app will initialize the scanner.
3. When launched, the app will automatically run `GetDeviceCount` and will display `Devices Found`. You should expect to see this number read at least `1` if your scanner is plugged in.

### Menu

Now we'll go through the menu:

`a) Verify device is initialized`

This returns a boolean (`True` or `False`). If `True`, the app sees your scanner and has initialized it for use. If `False`, make sure the scanner is plugged in, drivers are installed, and you run `B`

`b) Re-initialize device`

Open the connection to the device. Re-run `A` to verify that the device is initialized after runnign this option

`c) Test capture (L_SLAP -> disk)`

This will run a test capture to make sure that the reader can capture your print. It will only capture the left slap and will save it to the same directory that you are running this app from.

`d) Start web listener`

The web listener exposes a websocket (`ws`) on `TCP/8888`. The OEFT2 web app uses this to establish a handshake with the scanner and passes the print to the app via a Base64-encoded image. The Web Listener stays running and `WS` exposed until your quit this app.

`e) Exit`

Quit the app and gracefully closes connection to the scanner.

### Troubleshooting

**The Helper app can't see my IB scanner**
1. Currently, the only official supported scanner is the Integrated Biometrics Kojak. No other scanners are *officially* supported, though other IB products like the Five-O may work. Please let me know what you try!
2. Make sure the drivers are installed (found in the /Windows Client (OEFT Helper)/Drivers/ folder of this repo)
3. Plug your device in and then launch the Helper app
4. Reboot your computer

**The web app doesn't see the Helper app**
1. Did you start the web listener?
2. Expose `TCP/8888` on Windows Firewall to your docker subnets (shouldn't be needed)
3. Restart the docker container and check the console output in the web app for more info

**What version of the SDK is running?**
A: This is displayed at the top of the helper app on first launch (eg: SDK Version: Product=4.2.1.0)

**What OS versions are supported?**
A: Windows 10 and Windows 11 only at this time
