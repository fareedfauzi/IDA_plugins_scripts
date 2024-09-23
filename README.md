# IDA_plugins_scripts
Collection of my IDA plugins/scripts

## funccall_highlighter.py
An IDA Pro plugin that highlights function calls within the Hex-Rays pseudocode view, enabling better readability for function pointer and function call identification.

### Prerequisites
- IDA Pro 7.x or later with the Hex-Rays decompiler plugin installed.
- Python 3.x compatible with IDA Pro.

### Installation
- Copy `funccall_highlighter.py` into `C:\path\to\IDA Pro\plugins\`. For example `C:\Program Files\IDA Pro 8.3\plugins\`

### Usage
Via right-click menu:

![image](https://github.com/user-attachments/assets/6443cb02-d958-47b7-bfbb-8f7c18094f3c)

Via hotkey:
- `Ctrl + Alt + H`: Enable function call highlighting.
- `Ctrl + Alt + D`: Disable function call highlighting.

Before and after:

![ida64_a98qM7lfUH](https://github.com/user-attachments/assets/f13c2511-c698-4fed-8fcc-6e4d86f0100a)
