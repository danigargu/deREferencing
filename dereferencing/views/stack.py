#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# deREferencing - by @danigargu
#

import idc
import idaapi
import ida_bytes

from dereferencing import dbg, config, actions

from dereferencing.constants import *
from dereferencing.views import CustViewer
from dereferencing.actions import ActionHandler

# -----------------------------------------------------------------------
class StackViewer(CustViewer):
    def __init__(self, parent=None):
        super(StackViewer, self).__init__()
        self.parent = parent
        self.base_expr = None
        self.hook = None
        self.menu_actions = []
        dbg.initialize()

    def jump_to(self):
        current = self.base_expr if self.base_expr is not None else ""
        b = idaapi.ask_str(current, 0, "Sync with")
        if b and len(b) > 0:
            try:
                self.base_expr = b
                self.reload_info()
            except:
                idaapi.warning("Invalid expression")
        else:
            self.base_addr = None

    def set_stack_entries(self):
        value = idaapi.ask_long(config.n_stack_entries, "Set the number of stack entries to show")
        if value is not None:
            if value <= 0:
                idaapi.warning("Negative values are not allowed")
                return False
            config.n_stack_entries = value
            self.reload_info()
            return True
        return False

    def modify_value(self):
        ea = self.get_current_expr_ea()
        if not ea or not idaapi.is_loaded(ea):
            return
        stack_val = 0
        if idaapi.inf_is_64bit():
            stack_val = ida_bytes.get_qword(ea)
        else:
            stack_val = ida_bytes.get_dword(ea)
        b = idaapi.ask_str("0x%X" % stack_val, 0, "Modify value")
        if b is not None:
            try:
                value = int(idaapi.str2ea(b))
                if idaapi.inf_is_64bit():
                    idc.patch_qword(ea, value)
                else:
                    idc.patch_dword(ea, value)
                self.reload_info()
            except:
                idaapi.warning("Invalid expression")
                
    def can_edit_line(self):
        return True

    def register_actions(self):
        self.menu_actions.extend([
            actions.MenuAction("-"),
            actions.MenuAction("s_jump_disassembly", self.jump_in_disassembly, "Jump in disassembly",  None, "J",         124),
            actions.MenuAction("s_jump_new_window",  self.jump_in_new_window,  "Jump in a new window", None, "Ctrl-J",    125),
            actions.MenuAction("s_jump_hex",         self.jump_in_hex,         "Jump in hex",          None, "X",         89),
            actions.MenuAction("s_jump_to",          self.jump_to,             "Sync with expr",       shortcut="G", icon=124),
            actions.MenuAction("s_modify_value",     self.modify_value,        "Modify value",         None, "E",         104),
            actions.MenuAction("s_stack_entries",    self.set_stack_entries,   "Stack entries"),
            actions.MenuAction("-"),
        ])
        actions.register_menu_actions(self)

    def unregister_actions(self):
        actions.unregister_menu_actions(self)

    def Create(self, title):
        if not idaapi.simplecustviewer_t.Create(self, title):
            return False

        self.register_actions()
        self.hook = dbg.DbgHooks(self.reload_info)
        self.hook.hook()

        if not self.reload_info():
            return False
        return True

    def OnKeydown(self, vkey, shift):
        if vkey == ord('U'):
            self.reload_info()
        elif vkey == 27: # ESC
            pass
        else:
            return False
        return True

    def add_line(self, s=None):
        if not s:
            s = ""
        self.AddLine(s)

    def OnCursorPosChanged(self):
        pass

    def parse_value(self, value):
        reduced = False
        chain = self.get_ptr_chain(value)

        result = ""
        result += self.colorize_value(chain[0])

        vals = chain[1:]
        if len(vals) > config.max_deref_levels:
            vals = vals[:config.max_deref_levels]
            reduced = True

        result += ''.join([self.as_ptr(value) for value in vals])
        if reduced:
            result += self.as_arrow_string("[...]")

        result += self.get_value_info(chain[-1], stack_view=True)
        if chain.limit_exceeded:
            result += self.as_arrow_string("[...]")

        return result

    def reload_info(self):
        if not dbg.is_process_suspended():
            return False

        base_addr = None
        if self.base_expr is None:
            base_addr = idc.get_reg_value(dbg.registers.stack)
        else:
            base_addr = idaapi.str2ea(self.base_expr)
            if base_addr == idc.BADADDR:
                idaapi.warning("Invalid base expr: %s" % self.base_expr)
                return False

            if not idaapi.is_loaded(base_addr):
                idaapi.warning("Memory address is not loaded: $#x" % base_addr)
                return False

        self.ClearLines()
        dbg.set_thread_info()

        try:
            segm_end = idc.get_segm_end(base_addr)
            n_entries = config.n_stack_entries or ((segm_end-base_addr) // dbg.ptr_size)

            for i in range(n_entries):
                offset = i * dbg.ptr_size
                ptr = base_addr + offset

                if not idaapi.is_loaded(ptr):
                    break

                value = dbg.get_ptr(ptr)
                self.add_line("%02d:%04X  %s" % (i, offset, self.parse_value(ptr)))

        except Exception as e:
            idaapi.warning(str(e))
            return False
        return True

    def OnDblClick(self, shift):
        symbol = self.get_current_word()
        if symbol is not None:
            ea = self.resolve_expr(symbol)
            if ea and idaapi.is_loaded(ea):
                idaapi.jumpto(ea)
                return True
        return False

    def set_window_position(self):
        stack_view = idaapi.find_widget("Stack view")
        if stack_view:
            idaapi.set_dock_pos(STACK_WIDGET_TITLE, "Stack view", idaapi.DP_INSIDE)
            #idaapi.close_widget(stack_view, 0)
        else:
            idaapi.set_dock_pos(STACK_WIDGET_TITLE, REGS_WIDGET_TITLE, idaapi.DP_BOTTOM)

    def OnClose(self):
        self.unregister_actions()
        if self.hook:
            self.hook.unhook()

# -----------------------------------------------------------------------

