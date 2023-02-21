#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# deREferencing - by @danigargu
#

import sys
import struct

import idaapi
import idc

from dereferencing import regs

initialized = False
ptr_size = None
get_ptr = None
cpu_name = None
is_be = False
endian = None
filetype = None
mem_fmt = None
pack_fmt = None
registers = None
flags = None
thread_id = None
stack_segm = None
is_pefile = False

m = sys.modules[__name__]

# -----------------------------------------------------------------------
class DbgHooks(idaapi.DBG_Hooks):
    def __init__(self, callback):
        super(DbgHooks, self).__init__()
        self.callback = callback

    def hook(self, *args):
        super(DbgHooks, self).hook(*args)

    def unhook(self, *args):
        super(DbgHooks, self).unhook(*args)

    def notify(self):
        idaapi.refresh_debugger_memory()
        self.callback()

    def dbg_suspend_process(self):
        self.notify()

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        self.notify()

# -----------------------------------------------------------------------
def get_ptrsize():
    info = idaapi.get_inf_structure()
    ptr_size = None
    if info.is_64bit():
        ptr_size = 8
    elif info.is_32bit():
        ptr_size = 4
    return ptr_size

# -----------------------------------------------------------------------
def supported_cpu():
    info = idaapi.get_inf_structure()
    cpuname = info.procname.lower()
    if cpuname == "metapc" or cpuname.startswith("arm") or cpuname.startswith("mips"):
        return True
    return False

# -----------------------------------------------------------------------
def get_thread_tib(tid):
    tib_segm_name = "TIB[%08X]" % tid
    tib_segm = idaapi.get_segm_by_name(tib_segm_name)
    tib = None

    if not tib_segm:
        return tib

    ea  = tib_segm.start_ea
    tid_offset = m.ptr_size * 9
    while ea < tib_segm.end_ea:
        thread_id = m.get_ptr(ea+tid_offset)
        if thread_id == tid:
            tib = ea
            break
        ea += 0x1000
    return tib

# -----------------------------------------------------------------------
def get_stack_segment():
    thread_id = idaapi.get_current_thread()
    tib_ea = get_thread_tib(thread_id)
    if tib_ea:
        offset = m.ptr_size * 2
        stack_limit = m.get_ptr(tib_ea + offset)
        return idaapi.getseg(stack_limit)
    return None

# -----------------------------------------------------------------------
def get_last_error():
    thread_id = idaapi.get_current_thread()
    tib_ea = get_thread_tib(thread_id)
    if tib_ea:
        offset = m.ptr_size * 13
        return m.get_ptr(tib_ea + offset)
    return None

# -----------------------------------------------------------------------
def format_ptr(x):
    return m.mem_fmt % x

# -----------------------------------------------------------------------
def pack(val):
    return struct.pack(m.pack_fmt, val)

# -----------------------------------------------------------------------
def to_uint(val):
    if m.ptr_size == 4:
        return val & 0xFFFFFFFF
    return val & 0xFFFFFFFFFFFFFFFF

# -----------------------------------------------------------------------
def is_process_suspended():
    return (idaapi.get_process_state() == -1)

# -----------------------------------------------------------------------
def NtCurrentTeb():
    return idaapi.Appcall.proto("ntdll_NtCurrentTeb", "DWORD __stdcall NtCurrentTeb(void);")()

# -----------------------------------------------------------------------
def GetLastError():
    return idaapi.Appcall.proto("kernel32_GetLastError", "DWORD __stdcall GetLastError();")()

# -----------------------------------------------------------------------
def GetLastErrorEx():
    tib_ea = get_thread_tib(idaapi.get_current_thread())
    if tib_ea:
        return idc.get_wide_dword(tib_ea+0x34)
    return None

# -----------------------------------------------------------------------
def set_thread_info():
    if m.is_pefile:
        current_thread_id = idaapi.get_current_thread()
        if m.thread_id != current_thread_id:
            m.thread_id  = current_thread_id
            m.stack_segm = get_stack_segment()
    elif m.filetype == idaapi.f_ELF:
        pass

# -----------------------------------------------------------------------
def initialize():
    if m.initialized:
        return
        
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        m.ptr_size = 8
        m.get_ptr = idc.get_qword
        m.mem_fmt = "%016X"
        m.pack_fmt = "<Q"
    elif info.is_32bit():
        m.ptr_size = 4
        m.get_ptr = idc.get_wide_dword
        m.mem_fmt = "%08X"
        m.pack_fmt = "<L"

    m.cpu_name = info.procname.lower()
    m.is_be = idaapi.cvar.inf.is_be()
    m.filetype = info.filetype
    m.is_pefile = (m.filetype == idaapi.f_PE)
    m.thread_id = idaapi.get_current_thread()

    if m.cpu_name == "metapc":
        m.registers = {
            4: regs.x86,
            8: regs.x64
        }[m.ptr_size]

    elif m.cpu_name.startswith("arm"):
        m.registers = {
            4: regs.arm,
            8: regs.aarch64
        }[m.ptr_size]
    elif m.cpu_name.startswith("mips"):
        m.registers = regs.mips

    m.initialized = True

# -----------------------------------------------------------------------

