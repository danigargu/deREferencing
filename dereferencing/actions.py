#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# deREferencing - by @danigargu
#

import idaapi

from dereferencing.constants import *

# -----------------------------------------------------------------------
class MenuAction(object):
    def __init__(self, name, handler=None, title=None, tooltip=None, shortcut=None, \
        icon=-1, checkable=None, always_enabled=False):
        self.name = name
        self.handler = handler
        self.title = title
        self.tooltip = tooltip
        self.shortcut = shortcut
        self.icon = icon
        self.checkable = checkable
        self.always_enabled = always_enabled

# -----------------------------------------------------------------------
class ActionHandler(idaapi.action_handler_t):
    def __init__(self, tform, action):
        self.tform = tform
        self.action = action

    def activate(self, ctx):
        self.action.handler()

    def update(self, ctx):
        if ctx.widget_title == self.tform.title:
            if self.action.always_enabled:
                return idaapi.AST_ENABLE

            if self.action.checkable is not None:
                return idaapi.AST_ENABLE

            if self.tform.can_edit_line():
                return idaapi.AST_ENABLE

        return idaapi.AST_DISABLE

# -----------------------------------------------------------------------
def register_menu_actions(form):
    widget = form.GetWidget()
    for action in form.menu_actions:
        act_name = action.name
        if act_name != '-':
            act_name = "%s:%s" % (PLUGIN_NAME, action.name)
            idaapi.register_action(
                idaapi.action_desc_t(
                    act_name, 
                    action.title,
                    ActionHandler(form, action), 
                    action.shortcut, 
                    action.tooltip, 
                    action.icon
                )
            )
        if action.checkable is not None:
            idaapi.update_action_checkable(act_name, True)
            idaapi.update_action_checked(act_name, action.checkable)

        idaapi.attach_action_to_popup(widget, None, act_name)

# -----------------------------------------------------------------------
def unregister_menu_actions(form):
    for action in form.menu_actions:
        if action.name == "-":
            continue

        act_name = "%s:%s" % (PLUGIN_NAME, action.name)
        idaapi.unregister_action(act_name)

# -----------------------------------------------------------------------


