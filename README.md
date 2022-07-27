# Hot Droppers

"Hot Droppers" contain three droppers developed for the Sektor7 Malware Development Essentials course as the final project. They are:

- **Stealthy Dropper**
    - Storing AES-encrypted payload in .rsrc
    - Bypassing Windows Defender with AES
	- All strings are obfuscated
    - No blinking command prompt window when launched
- **Image Dropper**
- **AES **Dropper**

# Where this name "Hot Dropper" comes from?

Drop it like it's hot.

# Usage

In each folder, there is a file named `compile.bat`. It is used to compile `implant.cpp`:

```powershell
.\compile.bat
```

Double click `implant.exe` to trigger the payload.
