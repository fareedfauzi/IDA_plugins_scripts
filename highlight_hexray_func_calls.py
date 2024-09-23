import ida_hexrays
import ida_kernwin as kw
import ida_lines as il
import ida_idaapi
import re

HIGHLIGHT_COLOR = 0x99FFFF

class highlight_hooks_t(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self.func_call_pattern = re.compile(
            r"\b[a-zA-Z_]+\d*[a-zA-Z_]*\d*\s*\([^)]*\)\s*(?:;|\)|\s*\{)|"  # Handles multiple underscores in function names
            r"\b[\w_]+\s*\((?:[^)]|\n)*\)\s*(?:;|\)|\s*\{)|"  # Standard function calls, multiline args
            r"\(\*\([^)]*\)\)\s*\([^)]*\)|"  # Pointer function calls
            r"(?<!BYTE)(?<!WORD)\b[\w_]+\s*\(\s*(?:[^=<>]|\n)*\)\s*(?:;|\)|\s*\{)",  # Avoid BYTE and WORD
            re.IGNORECASE | re.DOTALL
        )



    def _apply_highlight(self, vu, pc):
        if pc:
            for sl in pc:
                line = sl.line
                clean_line = il.tag_remove(line).strip()
                if self.func_call_pattern.search(clean_line):
                    sl.bgcolor = HIGHLIGHT_COLOR
        return

    def text_ready(self, vu):
        pc = vu.cfunc.get_pseudocode()
        if pc:
            self._apply_highlight(vu, pc)
        return 0

class highlight_func_calls_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Highlight function calls in Hex-Rays pseudocode"
    help = "Highlights function pointer and strict function calls based on naming conventions"
    wanted_name = "Highlight Function Calls"
    wanted_hotkey = "Ctrl-Shift-H"

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            kw.msg("Hex-Rays not available.\n")
            return ida_idaapi.PLUGIN_SKIP

        self.hooks = highlight_hooks_t()
        self.hooks.hook()

        vu = ida_hexrays.get_widget_vdui(kw.get_current_viewer())
        if vu is None:
            kw.msg("No active Hex-Rays decompiler view detected. Please open a decompiler view.\n")
        else:
            vu.refresh_ctext()

        kw.msg("Highlight Function Calls plugin: START.\n")
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        if self.hooks:
            self.hooks.unhook()
        kw.msg("Highlight Function Calls plugin: DONE\n")

    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return highlight_func_calls_t()
