# mhypbase

- This project focuses on improving the experience of private servers, not official servers.
- This project is not a protocol emulation of the original `mhypbase.dll`, users should **NOT** use it to connect to official servers.
- This project renames `Astrolabe.dll` and `MiHoYoMTRSDK.dll` in `*_Data/Plugins` folder to BAK files. If you want to connect to the official server, you should rename them back, manually.

The latest GitHub Action build artifact: [[file]](https://nightly.link/Jx2f/mhypbase/workflows/msbuild/main/mhypbase-latest.zip)

## Features

- [x] _Disable BSoD drivers_ to prevent Windows from crashing.
- [x] _Disable log uploads_ to prevent crash log upload.
- [x] _Custom channel config_ to allow users to connect to a certain dispatch server, and remove watermark.
- [x] _Encrypt account password_ with the public key, which can be decrypted by the server private key.
- [x] _Verify the signature of the dispatched data_ with the public key to avoid the client error 4214.
- [x] _Filter out the RCE packets_ to prevent the client from being fully controlled by the server.
- [ ] ......
