#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# deREferencing - by @danigargu
#

import re
import string

import idc
import ida_bytes
import ida_nalt
import idaapi
import idautils

from dereferencing import dbg
from dereferencing import config

# -----------------------------------------------------------------------
T_STACK  = 0
T_HEAP   = 1
T_CODE   = 2
T_DATA   = 3
T_RODATA = 4
T_RWX    = 5
T_VALUE  = 6

# -----------------------------------------------------------------------
def get_value_type(ea):
    addr_type = T_VALUE

    if not idaapi.is_loaded(ea):
        return addr_type

    segm_name = idc.get_segm_name(ea)
    segm = idaapi.getseg(ea)
    flags = idc.get_full_flags(ea)
    is_code = idc.is_code(flags)

    if "stack" in segm_name.lower() or \
    (dbg.stack_segm and dbg.stack_segm.start_ea == segm.start_ea):
        addr_type = T_STACK

    elif "heap" in segm_name.lower():
        addr_type = T_HEAP

    elif segm != None:
        if not is_code and segm.perm & idaapi.SEGPERM_READ and \
        segm.perm & idaapi.SEGPERM_WRITE and \
        segm.perm & idaapi.SEGPERM_EXEC:
            addr_type = T_RWX

        elif is_code or \
        (segm.perm & idaapi.SEGPERM_READ and segm.perm & idaapi.SEGPERM_EXEC):
            addr_type = T_CODE

        elif segm.perm & idaapi.SEGPERM_READ and \
        segm.perm & idaapi.SEGPERM_WRITE:
            addr_type = T_DATA

        elif segm.perm & idaapi.SEGPERM_READ:
            addr_type = T_RODATA

    return addr_type

# -----------------------------------------------------------------------
def get_chain(value, limit=config.deref_limit):
    count = 0
    stop = False
    result = [value]

    if not idaapi.is_loaded(value):
        return result, False

    next_val = dbg.get_ptr(value)
    while not stop and count < limit:
        if result.count(next_val) >= 2 or not idaapi.is_loaded(next_val):
            stop = True
            continue

        result.append(next_val)
        next_val = dbg.get_ptr(next_val)
        count += 1

    exceeded = not stop
    return result, exceeded

# -----------------------------------------------------------------------
class Chain(object):
    def __init__(self, ptr):
        self.ptr = ptr
        self.values = []
        self.limit_exceeded = False
        self.parse_chain()

    def parse_chain(self, limit=config.deref_limit):
        chain, exceeded = get_chain(self.ptr)
        if exceeded:
            self.limit_exceeded = True

        for i, v in enumerate(chain):
            cv = ChainValue(i, v, get_value_type(v))
            self.values.append(cv)

    def __getitem__(self, i):
        return self.values[i]

    def __len__(self):
        return len(self.values)

# -----------------------------------------------------------------------
class ChainValue(object):
    def __init__(self, level, val, type):
        self.level = level
        self.value = val
        self.type = type

    def __str__(self):
        return "[%d]=%d" % (self.level, self.val)

# -----------------------------------------------------------------------
class Colorizer(object):
    def __init__(self):
        self.colours = {
            T_STACK:  self.as_stack,
            T_HEAP:   self.as_heap,
            T_CODE:   self.as_code,
            T_DATA:   self.as_data,
            T_RODATA: self.as_rodata,
            T_RWX:    self.as_rwx,
            T_VALUE:  self.as_value
        }
        self.arrow = config.arrow_symbol

    def as_stack(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_SEGNAME)

    def as_heap(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_VOIDOP)

    def as_code(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_CREFTAIL)

    def as_data(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_IMPNAME)

    def as_rodata(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_NUMBER)

    def as_rwx(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_MACRO)

    def as_value(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_SYMBOL)

    def as_comment(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_AUTOCMT)

    def get_ptr_chain(self, value):
        return Chain(value)

    def colorize_value(self, v):
        ptr_str = dbg.format_ptr(v.value)
        return self.colours[v.type](ptr_str)

    def as_ptr(self, value):
        c = self.colorize_value(value)
        return self.as_arrow_string(c)

    def as_arrow_string(self, string):
        return " %s %s" % (self.arrow, string)

    def as_closed_string(self, v, t):
        return ' (%s)' % self.colours[t](v)

    def as_mem_string(self, string):
        value = self.strip_str(string)
        max_string_len = config.max_string_len
        if len(value) > max_string_len:
            value = value[:max_string_len]
            return ' %s ("%s"...)' % (self.arrow, value)
        return ' %s ("%s")' % (self.arrow, value)

    def is_code(self, ea):
        flags = idc.get_full_flags(ea)
        return idc.is_code(flags)

    def is_ascii(self, s):
        return all(ord(c) < 127 and ord(c) >= 32 for c in s)

    def is_printable(self, s):
        return all(c in string.printable for c in s)

    def strip_disas_spaces(self, d):
        return re.sub(' +', ' ', d)

    def strip_str(self, d, rep='*'):
        return repr(d).replace("'","")

    def get_disasm(self, ea):
        d = idc.GetDisasm(ea)[:config.max_string_len]
        return self.strip_disas_spaces(d)

    def get_string(self, ea):
        res = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C_16)
        if res and len(res) == 1:
            res = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C_16)
        return res

    def get_printable(self, val):
        packed = dbg.pack(val).replace('\x00', '')
        if len(packed) > 0 and self.is_ascii(packed):
            return self.as_comment(' /* %s */' % repr(packed))
        return ''

    def get_area_name(self, ea, val_type):
        name = None
        if val_type == T_CODE:
            fcn_name = idc.get_func_off_str(ea)
            if fcn_name:
                name = fcn_name
            else:
                symbol_name = idaapi.get_name(ea)
                if symbol_name:
                    name = symbol_name
        else:
            symbol_name = idaapi.get_name(ea)
            if symbol_name:
                name = symbol_name

        seg_name = idc.get_segm_name(ea)
        if seg_name is not None:
            if name:
                name = "%s ! %s" % (seg_name, name)
            else:
                name = seg_name
        return name

    def get_ptr_value(self, v):
        ptr_val = dbg.get_ptr(v.value)
        cval = ChainValue(v.level + 1, ptr_val, T_VALUE)
        return self.as_ptr(cval) + self.get_printable(cval.value)

    def as_area_name(self, v):
        area_name = self.get_area_name(v.value, v.type)
        if area_name is not None:
            area_name = self.as_closed_string(area_name, v.type)
        return area_name

    def as_disasm(self, ptr):
        disasm = self.get_disasm(ptr)
        return self.as_arrow_string(disasm)

    def str_or_value(self, v):
        string = self.get_string(v.value)
        if string and len(string) >= config.min_string_len and self.is_printable(string):
            return self.as_mem_string(string)
        return self.get_ptr_value(v)

    def get_value_info(self, v, stack_view=False):
        result = ""
        ptr = v.value
        val_type = v.type
        level = v.level

        if not idaapi.is_loaded(ptr):
            result += self.get_printable(ptr)
            return result

        area_name = ""
        if config.show_area_name:
            area_name = self.as_area_name(v)

        if val_type == T_CODE:
            result += area_name
            if self.is_code(ptr):
                result += self.as_disasm(ptr)
        else:
            if val_type not in (T_STACK, T_HEAP):
                result += area_name

            if stack_view:
                if level == 0:
                    result += self.get_ptr_value(v)
                else:
                    result += self.str_or_value(v)
            else:
                result += self.str_or_value(v)

        return result

# -----------------------------------------------------------------------

