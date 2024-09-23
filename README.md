# IDA_plugins_scripts
Collection of my IDA plugins/scripts

## highlight_hexray_func_calls.py
- The plugin scans for function calls and highlights them within the Hex-Rays pseudocode.
- Please ensure the Hex-Rays decompiler is installed and activated.
- Copy the script (`highlight_func_calls.py`) to your IDA plugins directory. The location may vary depending on your system, typically in Windows: `C:\Program Files\IDA\plugins`.
- Open your file/samples in IDA Pro -> Open hexray decompiler of interested function -> Run the script/plugin.
- The plugin will be available in the plugin menu or you can activate it manually using the provided hotkey by press **Ctrl-Shift-H** to activates the plugin.

Before:

![image](https://github.com/user-attachments/assets/84cd2cf6-bc72-492a-bacd-955a7cba18c6)

After:

![image](https://github.com/user-attachments/assets/fe2dee33-4869-48d8-96b3-0c8622189ce3)


