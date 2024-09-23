import idaapi
import ida_hexrays
import ida_kernwin
import ida_lines
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
        if pc and plugin_enabled and len(pc) < 2000:  # Limiting to 2000 lines
            for sl in pc:
                line = sl.line
                clean_line = ida_lines.tag_remove(line).strip()
                if self.func_call_pattern.search(clean_line):
                    sl.bgcolor = HIGHLIGHT_COLOR
        return

    def text_ready(self, vu):
        if plugin_enabled:
            pc = vu.cfunc.get_pseudocode()
            if pc:
                self._apply_highlight(vu, pc)
        return 0

class highlight_func_calls_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Highlight function calls in Hex-Rays pseudocode"
    help = "Highlights function pointer and function calls based on naming conventions"
    wanted_name = "Highlight Function Calls"
    wanted_hotkey = ""

    enable_action_name = "highlight_func_calls:enable"
    disable_action_name = "highlight_func_calls:disable"

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            ida_kernwin.msg("Hex-Rays not available.\n")
            return idaapi.PLUGIN_SKIP

        # Register Enable and Disable actions for right-click menu
        enable_action = idaapi.action_desc_t(
            self.enable_action_name,
            "Enable Highlighting",
            toggle_highlight_on_handler(),
            "Ctrl+Alt+H",
            "Enable function call highlighting",
            201
        )
        disable_action = idaapi.action_desc_t(
            self.disable_action_name,
            "Disable Highlighting",
            toggle_highlight_off_handler(),
            "Ctrl+Alt+D",
            "Disable function call highlighting",
            201
        )

        idaapi.register_action(enable_action)
        idaapi.register_action(disable_action)

        # Hook the right-click context menu
        self.menu_hooks = ContextMenuHooks()
        self.menu_hooks.hook()

        self.hooks = highlight_hooks_t()
        self.hooks.hook()

        ida_kernwin.msg("Highlight Function Calls (funccall_highlighter.py) plugin: Loaded.\n")
        return idaapi.PLUGIN_KEEP

    def term(self):
        if self.hooks:
            self.hooks.unhook()

        idaapi.unregister_action(self.enable_action_name)
        idaapi.unregister_action(self.disable_action_name)

        if self.menu_hooks:
            self.menu_hooks.unhook()

        ida_kernwin.msg("Highlight Function Calls (funccall_highlighter.py) plugin: Unloaded.\n")

    def run(self, arg):
        pass

class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, highlight_func_calls_t.enable_action_name, "Function CALL highlight/")
            idaapi.attach_action_to_popup(form, popup, highlight_func_calls_t.disable_action_name, "Function CALL highlight/")

class toggle_highlight_on_handler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        enable_highlighting()
        return 1

    def update(self, ctx):
        if idaapi.get_widget_type(ctx.widget) == idaapi.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class toggle_highlight_off_handler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        disable_highlighting()
        return 1

    def update(self, ctx):
        if idaapi.get_widget_type(ctx.widget) == idaapi.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

def enable_highlighting():
    global plugin_enabled
    plugin_enabled = True
    vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
    if vu:
        ida_kernwin.msg("Highlighting Enabled\n")
        vu.refresh_ctext()

def disable_highlighting():
    global plugin_enabled
    plugin_enabled = False
    vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
    if vu:
        ida_kernwin.msg("Highlighting Disabled\n")
        vu.refresh_ctext()

def PLUGIN_ENTRY():
    return highlight_func_calls_t()
