import ida_hexrays
import ida_kernwin as kw
import ida_lines as il
import ida_idaapi
import re

HIGHLIGHT_COLOR = 0x99FFFF
plugin_enabled = False

class highlight_hooks_t(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self.func_call_pattern = re.compile(
        r"\b[\w_]+\s*\(\s*[^()]*?\s*\)\s*(?:;|\)|\{)|"        # Function calls
        r"\(\*\([^)]*\)\)\s*\([^)]*\)|"                       # Pointer dereference calls
        r"(?<!BYTE)(?<!WORD)\b[\w_]+\s*\([^=<>]*?\)\s*(?:;|\)|\{)",  # Skip WORD/BYTE
        re.IGNORECASE | re.DOTALL
)


    def _apply_highlight(self, vu, pc):
        # Optimization: Limit to a reasonable number of lines to avoid performance issues
        if pc and plugin_enabled and len(pc) < 2000: 
            for sl in pc:
                line = sl.line
                clean_line = il.tag_remove(line).strip()
                if self.func_call_pattern.search(clean_line):
                    sl.bgcolor = HIGHLIGHT_COLOR
        return

    def text_ready(self, vu):
        if plugin_enabled:
            pc = vu.cfunc.get_pseudocode()
            if pc:
                self._apply_highlight(vu, pc)
        return 0

class highlight_func_calls_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Highlight function calls in Hex-Rays pseudocode"
    help = "Highlights function pointer and function calls based on naming conventions"
    wanted_name = "Highlight Function Calls"
    wanted_hotkey = "Ctrl-Shift-H"

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            kw.msg("Hex-Rays not available.\n")
            return ida_idaapi.PLUGIN_SKIP

        self.hooks = highlight_hooks_t()
        self.hooks.hook()

        kw.msg("Highlight Function Calls plugin: Loaded but inactive.\n")
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        if self.hooks:
            self.hooks.unhook()
        kw.msg("Highlight Function Calls plugin: Unloaded.\n")

    def run(self, arg):
        toggle_plugin_for_current_view()

def toggle_plugin_for_current_view():
    global plugin_enabled
    plugin_enabled = not plugin_enabled

    vu = ida_hexrays.get_widget_vdui(kw.get_current_viewer())
    if vu is None:
        kw.msg("No active Hex-Rays decompiler view detected.\n")
        return

    if plugin_enabled:
        kw.msg("Highlight Function Calls plugin: ENABLED for the current view.\n")
        vu.refresh_ctext()  # Refresh the pseudocode to apply highlighting
    else:
        kw.msg("Highlight Function Calls plugin: DISABLED.\n")
        vu.refresh_ctext()  # Refresh the pseudocode to remove highlighting

def PLUGIN_ENTRY():
    return highlight_func_calls_t()
