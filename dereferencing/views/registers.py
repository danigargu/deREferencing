#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# deREferencing - by @danigargu
#

import idc
import idaapi

import collections

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtCore import Qt

from dereferencing import dbg, config, win2_errors, actions
from dereferencing.views import CustViewer
from dereferencing.constants import *

# -----------------------------------------------------------------------
class RegistersViewer(CustViewer):
    def __init__(self, parent):
        super(RegistersViewer, self).__init__()
        self.parent     = parent
        self.title      = None
        self.last_error = None
        self.actions    = None
        self.menu_actions = []

    def add_leyend(self):
        self.add_line()
        self.add_line(self.as_stack('STACK') + ' | ' +
            self.as_heap('HEAP') + ' | ' +
            self.as_code('CODE') + ' | ' +
            self.as_data('DATA') + ' | ' +
            self.as_rodata('RODATA') + ' | ' +
            self.as_rwx('RWX') + ' | ' +
            self.as_value('VALUE')
        )

    def add_line(self, s=None, highlight=False):
        if not s:
            s = ""
        bgcolor = config.highlight_color if highlight and config.highlight_changes else None
        self.AddLine(s, bgcolor=bgcolor)

    def last_error_str(self):
        result = None
        changed = False
        last_error = dbg.get_last_error()

        if last_error is not None:
            if last_error != self.last_error:
                result = '*'
                changed = True
            else:
                result = ' '

            result += 'GLE %s' % self.as_value(dbg.format_ptr(last_error))
            error_name = win2_errors.error_code_to_name(last_error)
            if error_name:
                result += ' (%s)' % (error_name)

            self.last_error = last_error
        return result, changed

    def reload_info(self):
        if not dbg.is_process_suspended():
            return False

        self.ClearLines()
        dbg.set_thread_info()

        for reg in dbg.registers:
            line, changed = self.colorize_register(reg)
            self.add_line(line, changed)

        if dbg.is_pefile:
            self.add_line(*self.last_error_str())

        if config.show_leyend:
            self.add_leyend()
        return True

    def get_reg_label(self, reg, val):
        changed = False
        if self.reg_vals[reg] != val:
            regname = "*%s" % reg
            self.reg_vals[reg] = val
            changed = True
        else:
            regname = " %s" % reg
        regname = regname.ljust(dbg.registers.max_len+2)
        return regname, changed

    def colorize_register(self, reg):
        result = ''
        reduced = False

        reg_val = idc.get_reg_value(reg)
        label, changed = self.get_reg_label(reg, reg_val)
        chain = self.get_ptr_chain(reg_val)

        result += label + self.colorize_value(chain[0])

        if reg == dbg.registers.flagsr:
            return result, changed

        elif reg != dbg.registers.pc:
            vals = chain[1:]
            if len(vals) > config.max_deref_levels:
                vals = vals[:config.max_deref_levels]
                reduced = True

            result += ''.join([self.as_ptr(value) for value in vals])
            if reduced:
                result += self.as_arrow_string("[...]")

        result += self.get_value_info(chain[-1])
        if chain.limit_exceeded:
            result += self.as_arrow_string("[...]")

        return result, changed

    def modify_value(self):
        reg = self.get_selected_reg()
        if not reg:
            return

        reg_val = idc.get_reg_value(reg)
        b = idc.AskStr("0x%X" % reg_val, "Modify register value")
        if b is not None:
            try:
                value = int(idaapi.str2ea(b))
                idc.SetRegValue(value, reg)
                self.reload_info()

                if reg == dbg.registers.flags:
                    self.reload_flags_view()
            except:
                idaapi.warning("Invalid expression")

    def reload_flags_view(self):
        if self.self.parent.flags_view:
            self.parent.flags_view.reload_info()

    def get_selected_reg(self):
        reg = None
        lineno = self.GetLineNo()
        if lineno > len(dbg.registers)-1:
            return reg

        line = self.GetLine(lineno)
        if line and len(line) > 0:
            line_str = idaapi.tag_remove(line[0])
            reg = line_str[1:dbg.registers.max_len+2].strip()
        return reg

    def toggle_value(self):
        reg = self.get_selected_reg()
        if not reg:
            return

        val = dbg.to_uint(~self.reg_vals[reg])
        idc.SetRegValue(val, reg)
        self.reload_info()

    def inc_reg(self):
        reg = self.get_selected_reg()
        if not reg:
            return

        val = dbg.to_uint(self.reg_vals[reg]+1)
        idc.SetRegValue(val, reg)
        self.reload_info()

    def dec_reg(self):
        reg = self.get_selected_reg()
        if not reg:
            return

        val = dbg.to_uint(self.reg_vals[reg]-1)
        idc.SetRegValue(val, reg)
        self.reload_info()

    def zero_reg(self):
        reg = self.get_selected_reg()
        if not reg:
            return

        idc.SetRegValue(0, reg)
        self.reload_info()

    def set_deref_levels(self):
        value = idc.AskLong(config.max_deref_levels, "Set current dereferencing levels to show")
        if value is not None:
            if value < 0:
                idaapi.warning("Negative values are not allowed")
                return False

            if value > config.deref_limit:
                idaapi.warning("Value should not exceed the dereferencing limit: %d" % config.deref_limit)
                return False

            config.max_deref_levels = value
            self.reload_info()
            return True
        return False

    def set_show_area_name(self):
        config.show_area_name = (not config.show_area_name)
        self.reload_info()

    def set_show_leyend(self):
        config.show_leyend = (not config.show_leyend)
        self.reload_info()

    def register_actions(self): 
        self.menu_actions.extend([
            actions.MenuAction("-"),
            actions.MenuAction("jump_disassembly", self.jump_in_disassembly, "Jump in disassembly",  None, "J",         124),
            actions.MenuAction("jump_new_window",  self.jump_in_new_window,  "Jump in a new window", None, "Ctrl-J",    125),
            actions.MenuAction("jump_hex",         self.jump_in_hex,         "Jump in hex",          None, "X",         89),
            actions.MenuAction("modify_value",     self.modify_value,        "Modify value",         None, "E",         104),
            actions.MenuAction("toggle_value",     self.toggle_value,        "Toggle value",         None, "Alt-Space", 58),
            actions.MenuAction("inc_value",        self.inc_reg,             "Increment value",      None, "+",         50),
            actions.MenuAction("dec_value",        self.dec_reg,             "Decrement value",      None, "-",         51),
            actions.MenuAction("zero_value",       self.zero_reg,            "Zero value",           None, "0",         123),
            actions.MenuAction("-"),
            actions.MenuAction("show_leyend",      self.set_show_leyend,     "Show leyend",          None, None,  checkable=config.show_leyend),
            actions.MenuAction("show_area_name",   self.set_show_area_name,  "Show area name",       None, None,  checkable=config.show_area_name),
            actions.MenuAction("deref_levels",     self.set_deref_levels,    "Dereferencing levels", None, None,  always_enabled=True),
            actions.MenuAction("-"),
        ])
        actions.register_menu_actions(self)

    def unregister_actions(self):
        actions.unregister_menu_actions(self)

    def can_edit_line(self):
        lineno = self.GetLineNo()
        if lineno > len(dbg.registers)-1:
            return False
        return True

    def Create(self, title):
        self.title = title

        if not idaapi.simplecustviewer_t.Create(self, title):
            return False

        self.reg_vals  = dict([(i, None) for i in dbg.registers])
        self.register_actions()

        return True

    def OnKeydown(self, vkey, shift):
        if vkey == ord('U'):
            self.reload_info()
        elif vkey == 27: # ESC
            pass
        else:
            return False
        return True

    def OnDblClick(self, shift):
        symbol = self.get_current_word()
        if symbol is not None:
            if symbol.isupper() and symbol.replace("*","") in dbg.registers:
                self.modify_value()
                return True
            else:
                ea = self.resolve_expr(symbol)
                if ea and idaapi.is_loaded(ea):
                    idaapi.jumpto(ea)
                    return True
        return False

    def OnHint(self, lineno):
        #return (4, "OnHint, line=%s" % lineno)
        return False

    def OnClose(self):
        self.unregister_actions()

# -----------------------------------------------------------------------
class FlagsView(idaapi.simplecustviewer_t):
    def __init__(self, parent):
        super(FlagsView, self).__init__()
        self.parent = parent
        self.menu_actions = []

    def Create(self, title):
        if not idaapi.simplecustviewer_t.Create(self, title):
            return False

        self.flag_vals  = dict([(i,None) for i in dbg.registers.flags])
        self.register_actions()

        return True

    def reload_info(self):
        if not dbg.is_process_suspended():
            return False

        self.ClearLines()
        for flag in dbg.registers.flags:
            try:
                value = idc.get_reg_value(flag)
                result = None

                if self.flag_vals[flag] != value:
                    result = self.as_changed(str(value))
                    self.flag_vals[flag] = value
                else:
                    result = str(value)
                self.add_line('%-4s %s' % (flag, result))
            except:
                pass

        return True

    def as_changed(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_CREFTAIL)

    def add_line(self, s=None):
        if not s:
            s = ""
        self.AddLine(s)

    def switch_value(self):
        lineno = self.GetLineNo()
        if lineno > len(dbg.registers.flags):
            return

        line = self.GetLine(lineno)
        line = idaapi.tag_remove(line[0])
        flag = line[:4].strip()
        new_val = not self.flag_vals[flag]

        rc = idc.SetRegValue(int(new_val), flag)
        if not rc:
            idaapi.warning("Unable to update the register value")
            return

        self.parent.reload_view()

    def can_edit_line(self):
        lineno = self.GetLineNo()
        if lineno > len(dbg.registers.flags):
            return False
        return True

    def register_actions(self):
        self.menu_actions.extend([
            actions.MenuAction("-"),
            actions.MenuAction("switch_value", self.switch_value, "Switch value",  None, "S", 104),
            actions.MenuAction("-")
        ])
        actions.register_menu_actions(self)

    def unregister_actions(self):
        actions.unregister_menu_actions(self)

    def OnClose(self):
        self.unregister_actions()

# -----------------------------------------------------------------------
class RegsFlagsViewer(idaapi.PluginForm):
    def __init__(self):
        super(RegsFlagsViewer, self).__init__()
        self.hook = None
        self.flags_view = None
        dbg.initialize()

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

        self.hook = dbg.DbgHooks(self.reload_view)
        self.hook.hook()

    def reload_view(self):
        self.regs_view.reload_info()

        if self.flags_view:
            self.flags_view.reload_info()

    def PopulateForm(self):
        hbox = QtWidgets.QHBoxLayout()
        splitter = QtWidgets.QSplitter()

        hbox.setContentsMargins(0, 0, 0, 0)

        self.regs_view = RegistersViewer(self)
        self.regs_view.Create("%s-Registers" % PLUGIN_NAME)

        show_flags = (dbg.registers.flags is not None)
        flagsview_widget = None

        if show_flags:
            self.flags_view = FlagsView(self)
            self.flags_view.Create("%s-Flags" % PLUGIN_NAME)
            flagsview_widget = self.FormToPyQtWidget(self.flags_view.GetWidget())

        regsview_widget = self.FormToPyQtWidget(self.regs_view.GetWidget())

        """
        # attempt to remove the status bar

        self.status_bar = regsview_widget.findChild(QtWidgets.QStatusBar)
        showMessage = self.status_bar.showMessage

        for widget in self.status_bar.findChildren(QtWidgets.QLabel):
            self.status_bar.removeWidget(widget)
        """

        splitter.setHandleWidth(1)
        splitter.addWidget(regsview_widget)

        if flagsview_widget:
            flagsview_widget.setFixedWidth(70)
            splitter.addWidget(flagsview_widget)

        hbox.addWidget(splitter)
        self.parent.setLayout(hbox)

        self.reload_view()

    def set_window_position(self):
        ref_widgets = [
            ("Modules",       idaapi.DP_TOP),
            ("Threads",       idaapi.DP_TOP),
            ("IDA View-EIP",  idaapi.DP_RIGHT),
            ("Stack view",    idaapi.DP_TOP)
        ]
        plug_window_name = "Registers - %s" % PLUGIN_NAME
        regs_widget = idaapi.find_widget("General registers")

        if regs_widget:
            idaapi.set_dock_pos(REGS_WIDGET_TITLE, "General registers", idaapi.DP_INSIDE)
            idaapi.close_widget(regs_widget, 0)
        else:
            found = False
            for wname, pos in ref_widgets:
                if idaapi.find_widget(wname):
                    idaapi.set_dock_pos(REGS_WIDGET_TITLE, wname, pos)
                    found = True
                    break
            if not found:
                idaapi.set_dock_pos(REGS_WIDGET_TITLE, None, idaapi.DP_FLOATING)

    def OnClose(self, form):
        if self.hook:
            self.hook.unhook()

# -----------------------------------------------------------------------

