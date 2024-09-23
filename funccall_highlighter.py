import idaapi
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_idaapi
import ida_segment
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

# Hook for highlighting function calls in Graph and Linear views
class GraphLinearHighlightHooks(idaapi.IDB_Hooks):
    def __init__(self):
        idaapi.IDB_Hooks.__init__(self)

    def _highlight_disassembly_calls(self, ea):
        disasm_line = ida_lines.generate_disasm_line(ea, 0)
        if "call" in disasm_line:
            # Highlight the line if it contains a function call
            idaapi.set_item_color(ea, HIGHLIGHT_COLOR)

    def _remove_highlight(self, ea):
        idaapi.set_item_color(ea, 0xFFFFFFFF)
    def refresh_view(self):
        seg = ida_segment.getseg(idaapi.get_screen_ea())
        if not seg:
            return

        start = seg.start_ea
        end = seg.end_ea
        if plugin_enabled:
            for ea in range(start, end):
                if idaapi.is_code(idaapi.get_full_flags(ea)):
                    self._highlight_disassembly_calls(ea)
        else:
            for ea in range(start, end):
                if idaapi.is_code(idaapi.get_full_flags(ea)):
                    self._remove_highlight(ea)

class highlight_func_calls_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Highlight function calls in Hex-Rays pseudocode, Graph View, and Linear View"
    help = "Highlights function pointer and function calls based on naming conventions"
    wanted_name = "Highlight Function Calls"
    wanted_hotkey = ""

    enable_action_name = "highlight_func_calls:enable"
    disable_action_name = "highlight_func_calls:disable"
    enable_disasm_action_name = "highlight_disasm_calls:enable"
    disable_disasm_action_name = "highlight_disasm_calls:disable"

    def init(self):
        # Check if Hex-Rays is available
        hexrays_available = ida_hexrays.init_hexrays_plugin()
        
        if hexrays_available:
            # Register Enable/Disable actions for right-click menu in pseudocode
            enable_action = idaapi.action_desc_t(
                self.enable_action_name,
                "Enable Highlighting (Pseudocode)",
                toggle_highlight_on_handler(),
                "Ctrl+Alt+H",
                "Enable function call highlighting",
                201
            )
            disable_action = idaapi.action_desc_t(
                self.disable_action_name,
                "Disable Highlighting (Pseudocode)",
                toggle_highlight_off_handler(),
                "Ctrl+Alt+D",
                "Disable function call highlighting",
                201
            )
            idaapi.register_action(enable_action)
            idaapi.register_action(disable_action)

            # Hook the pseudocode highlighting if Hex-Rays is available
            self.hooks = highlight_hooks_t()
            self.hooks.hook()

        else:
            ida_kernwin.msg("Hex-Rays not available. Pseudocode highlighting disabled.\n")

        # Register Enable/Disable actions for right-click menu in disassembly views (Graph/Linear)
        enable_disasm_action = idaapi.action_desc_t(
            self.enable_disasm_action_name,
            "Enable Highlighting (Graph/Linear)",
            toggle_disasm_highlight_on_handler(),
            "Ctrl+Alt+G",
            "Enable function call highlighting in Graph/Linear view",
            201
        )
        disable_disasm_action = idaapi.action_desc_t(
            self.disable_disasm_action_name,
            "Disable Highlighting (Graph/Linear)",
            toggle_disasm_highlight_off_handler(),
            "Ctrl+Alt+L",
            "Disable function call highlighting in Graph/Linear view",
            201
        )

        idaapi.register_action(enable_disasm_action)
        idaapi.register_action(disable_disasm_action)

        # Hook the right-click context menu for both views
        self.menu_hooks = ContextMenuHooks()
        self.menu_hooks.hook()

        # Hook for Graph/Linear view highlighting
        self.graph_linear_hooks = GraphLinearHighlightHooks()

        ida_kernwin.msg("Highlight Function Calls plugin: Loaded.\n")
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        if hasattr(self, 'hooks') and self.hooks:
            self.hooks.unhook()

        idaapi.unregister_action(self.enable_action_name)
        idaapi.unregister_action(self.disable_action_name)
        idaapi.unregister_action(self.enable_disasm_action_name)
        idaapi.unregister_action(self.disable_disasm_action_name)

        if self.menu_hooks:
            self.menu_hooks.unhook()

        ida_kernwin.msg("Highlight Function Calls plugin: Unloaded.\n")


    def run(self, arg):
        pass

class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, highlight_func_calls_t.enable_action_name, "Function CALL highlighter/")
            idaapi.attach_action_to_popup(form, popup, highlight_func_calls_t.disable_action_name, "Function CALL highlighter/")
        # Add actions to the context menu of Graph and Linear views
        elif idaapi.get_widget_type(form) in [idaapi.BWN_DISASMS, idaapi.BWN_DISASM]:
            idaapi.attach_action_to_popup(form, popup, highlight_func_calls_t.enable_disasm_action_name, "Function CALL highlighter/")
            idaapi.attach_action_to_popup(form, popup, highlight_func_calls_t.disable_disasm_action_name, "Function CALL highlighter/")

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

class toggle_disasm_highlight_on_handler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        enable_disasm_highlighting()
        return 1

    def update(self, ctx):
        if idaapi.get_widget_type(ctx.widget) in [idaapi.BWN_DISASMS, idaapi.BWN_DISASM]:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class toggle_disasm_highlight_off_handler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        disable_disasm_highlighting()
        return 1

    def update(self, ctx):
        if idaapi.get_widget_type(ctx.widget) in [idaapi.BWN_DISASMS, idaapi.BWN_DISASM]:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

def enable_highlighting():
    global plugin_enabled
    plugin_enabled = True
    vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
    if vu:
        ida_kernwin.msg("Highlighting Enabled (Pseudocode)\n")
        vu.refresh_ctext()

def disable_highlighting():
    global plugin_enabled
    plugin_enabled = False
    vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
    if vu:
        ida_kernwin.msg("Highlighting Disabled (Pseudocode)\n")
        vu.refresh_ctext()

def enable_disasm_highlighting():
    global plugin_enabled
    plugin_enabled = True
    ida_kernwin.msg("Highlighting Enabled (Graph/Linear View)\n")
    GraphLinearHighlightHooks().refresh_view()

def disable_disasm_highlighting():
    global plugin_enabled
    plugin_enabled = False
    ida_kernwin.msg("Highlighting Disabled (Graph/Linear View)\n")
    GraphLinearHighlightHooks().refresh_view()

def PLUGIN_ENTRY():
    return highlight_func_calls_t()
