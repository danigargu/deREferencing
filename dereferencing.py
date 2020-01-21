#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# deREferencing - by @danigargu
#

import re
import os

import idc
import idaapi

from dereferencing.constants import *
from dereferencing.views import *
from dereferencing import dbg

# -----------------------------------------------------------------------
# Debugging setup for VSCode

debug = False
if debug:
    try:
        # https://github.com/Microsoft/ptvsd
        import ptvsd
        ptvsd.enable_attach(address=('0.0.0.0', 5678))
        #ptvsd.wait_for_attach()
    except Exception as e:
        print("ERROR: ptvsd already in use")

# -----------------------------------------------------------------------
class StartHandler(idaapi.action_handler_t):
    def __init__(self, widget_title):
        idaapi.action_handler_t.__init__(self)
        self.widget_title = widget_title

    def activate(self, ctx):
        if self.widget_title == REGS_WIDGET_TITLE:
            if idaapi.find_widget(self.widget_title) is None:
                w = RegsFlagsViewer()
                w.Show(REGS_WIDGET_TITLE)
                w.set_window_position()

        elif self.widget_title == STACK_WIDGET_TITLE:
            if idaapi.find_widget(self.widget_title) is None:
                w = StackViewer()
                w.Create(STACK_WIDGET_TITLE)
                w.Show()
                w.set_window_position()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------
class DbgHook(idaapi.DBG_Hooks):
    def dbg_bpt(self, tid, ea):
        Registers = StartHandler(REGS_WIDGET_TITLE)
        Registers.activate(None)
        Stack = StartHandler(STACK_WIDGET_TITLE)
        Stack.activate(None)
        idaapi.activate_widget(idaapi.find_widget("IDA View-EIP"), True)
        return 0

# -----------------------------------------------------------------------
def register_munu_actions():
    act_registers = '%s:registers' % PLUGIN_NAME
    act1 = idaapi.action_desc_t(
        act_registers,
        REGS_WIDGET_TITLE,
        StartHandler(REGS_WIDGET_TITLE),
        'Alt-Shift-D',
        'Start plugin',
        122
    )
    idaapi.register_action(act1)
    idaapi.attach_action_to_menu(DBG_MENU_PATH, act_registers, idaapi.SETMENU_APP)

    act_stack = '%s:stack' % PLUGIN_NAME
    act2 = idaapi.action_desc_t(act_stack,
        STACK_WIDGET_TITLE,
        StartHandler(STACK_WIDGET_TITLE),
        'Alt-Shift-E',
        'Start plugin',
        122
    )
    idaapi.register_action(act2)
    idaapi.attach_action_to_menu(DBG_MENU_PATH, act_stack, idaapi.SETMENU_APP)

def detach_menu_actions():
    idaapi.detach_action_from_menu(DBG_MENU_PATH, '%s:registers' % PLUGIN_NAME)
    idaapi.detach_action_from_menu(DBG_MENU_PATH, '%s:stack' % PLUGIN_NAME)

# -----------------------------------------------------------------------
def register_desktop_hooks():
    global h
    h = populate_desktop_hooks_t()
    h.hook()

# -----------------------------------------------------------------------
def register_dbg_hook():
    global dbg_hook
    try:
        if dbg_hook:
            dbg_hook.unhook()
    except:
        pass
    dbg_hook = DbgHook()
    dbg_hook.hook()

# -----------------------------------------------------------------------
class populate_desktop_hooks_t(idaapi.UI_Hooks):
    def create_desktop_widget(self, title, cfg):
        if title == REGS_WIDGET_TITLE:
            w = RegsFlagsViewer()
            w.Show(REGS_WIDGET_TITLE, options=idaapi.PluginForm.WOPN_CREATE_ONLY)
            return w.GetWidget()

        elif title == STACK_WIDGET_TITLE:
            w = StackViewer()
            w.Create(STACK_WIDGET_TITLE)
            return w.GetWidget()

# -----------------------------------------------------------------------
class deREferencing_plugin_t(idaapi.plugin_t):
    comment = ""
    help = PLUGIN_NAME
    flags = idaapi.PLUGIN_KEEP|idaapi.PLUGIN_HIDE
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        if not dbg.supported_cpu():
            return idaapi.PLUGIN_SKIP

        register_dbg_hook()
        register_munu_actions()
        register_desktop_hooks()

        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        pass

    def term(self):
        detach_menu_actions()
        
# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return deREferencing_plugin_t()

# -----------------------------------------------------------------------
