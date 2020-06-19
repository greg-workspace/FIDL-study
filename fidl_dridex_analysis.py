import FIDL.decompiler_utils as du
from FIDL.compiler_consts import *
import pefile
from binascii import crc32
import ida_typeinf

get_func_start = lambda ea: idc.GetFunctionAttr(ea, idc.FUNCATTR_START)
ulong = lambda val: (val & 0xFFFFFFFFL)
module_list = ['NTDLL.DLL','KERNEL32.DLL','USER32.DLL' ,'ADVAPI32.DLL', 'WININET.DLL', 'SHLWAPI.DLL', 'SHELL32.DLL', 'IPHLPAPI.DLL']
#module_list = ['ADVAPI32.DLL']

dict_hash_str = {}


get_proc_name = lambda name: name.split('.')[1] if '.' in name else name

def add_hash_enum(m_hash, c_hash, name, enum_name = 'crc32_hash'):
        enum_hashes = GetEnum(enum_name)
        if enum_hashes == 0xFFFFFFFF:
                enum_hashes = AddEnum(0, enum_name, idaapi.hexflag())
       
        if '.' in name:
                module_name, proc_name = name.split('.')
                AddConstEx(enum_hashes, '_' + module_name + '_HS_', m_hash, -1)
                AddConstEx(enum_hashes, '_' + proc_name + '_HS_', c_hash, -1)
        else:
                AddConstEx(enum_hashes, '_' + name + '_HS_', c_hash, -1)
                           
def type_for_name(name):
        ret = ida_typeinf.get_named_type(None, name, 0)
        if not ret:
                return None
        type_str = ret[1]
        field_str = ret[2]
        t = ida_typeinf.tinfo_t()
        t.deserialize(None, type_str, field_str)
        funct_type = str(t)
        
        funct_type = funct_type.replace("__stdcall","(__stdcall*)")
        #print 'procdure type:', typeinfo
        return funct_type                                                


def prepare_hashes(system32_pth='c:\\windows\\system32\\'):
        for m in module_list:
                dict_hash_str[ulong(crc32(m))] = m
                pe = pefile.PE(system32_pth+m) 
                pe.parse_data_directories(directories=[1])
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                                dict_hash_str[ulong(crc32(exp.name))] = exp.name 
                                                                                        
def resolve_api_frm_hash(module_hash, proc_hash, xor_key = 0x65C54023L):
        try:
                module_name = None
                if module_hash:
                        module_name = dict_hash_str[module_hash ^ xor_key]
                        module_name = module_name.split('.')[0]
                proc_name = dict_hash_str[proc_hash ^ xor_key]
                if module_name:
                        return module_name + '.' + proc_name
                else:
                        return proc_name
        except KeyError:
                return None


def get_var_name(ins, c):
        if (du.is_var(ins)):
                 real_var = du.ref2var(ref=ins, c=c) # real_var: lvar_t
                 my_var = du.my_var_t(real_var) # my_var: my_var_t
                 return my_var.name
        else:
                return None
                                                  
def resolve_api(addr=0x409334, dbg_file='debug.txt' ):
        func_list = []
        
        for xref in XrefsTo(addr, ida_xref.XREF_ALL):
                func_ea = get_func_start(xref.frm)
                if func_ea == 0:
                        print 'xref outside of defined function %x' % xref.frm
                elif func_ea != 0xFFFFFFFFL:
                        func_list.append(func_ea)
                        
        func_list = set(func_list)
        fp = open(dbg_file, 'w+')
        for f in func_list:
                c = du.controlFlowinator(ea=f)
                
                fptr_var_dict = {}
                for co in c.calls:
                        try:
                                if co.call_ea == addr and co.args[1].type == 'number':
                                        
                                        module_hash = ulong(co.args[0].val) if co.args[0].type == 'number' else 0
                                        proc_hash = ulong(co.args[1].val)
                                        res = resolve_api_frm_hash(module_hash, proc_hash)
                                        
                                        if res:
                                                # du.create_comment(c=c, ea=co.ea, comment='%x -> %s' % (co.ea,res))
                                                # du.display_node(c=c, node=co.node) 
                                                add_hash_enum(module_hash, proc_hash, res)
                                                
                                                
                                                dbg_msg = 'function start ea: %X; caller ea: %X => %s; expr type: %s; ' % (f, co.ea, res, expr_ctype[co.node.op])
                                                
                                                if du.is_asg(co.node):
                                                        #cf = du.my_decompile(co.ea)
                                                        #ret_tinfo = du.get_return_type(cf) 
                                                        #if not ret_tinfo.is_funcptr():
                                                        #        print '[!] Converting to func pointer'
                                                        #        ret_tinfo.create_ptr(ret_tinfo)
                                                        prototype = type_for_name(get_proc_name(res))
                                                        dbg_msg += 'prototype: %s;' %  prototype
                                                        lhs = co.node.x # lhs: cexpr_t
                                                        ret_varname = get_var_name(lhs, c)
                                                        fptr_var_dict[ret_varname] = get_proc_name(res)
                                                        
                                                        if (ret_varname):
                                                                dbg_msg += 'var name = %s;' % ret_varname
                                                        elif (du.is_global_var(lhs)):
                                                                dbg_msg += 'global addr = %s;' % du.value_of_global(lhs)
                                                fp.write(dbg_msg + '\n')
                                                
                                
                                if co.ea != 0xffffffffL and co.call_ea == 0xffffffffL: # it means function ptr such as call v1(...)
                                        callee_var = get_var_name(co.expr.x,c)
                                        proc_name = fptr_var_dict.get(callee_var)
                                        if proc_name:
                                                proto = type_for_name(proc_name)
                                                if proto:
                                                        print '{}[?] ea = {:x}; var name = {}; proc name = {}; '.format(' '*80, co.ea, callee_var, proc_name)
                                                        ti = idaapi.tinfo_t()
                                                        idaapi.parse_decl2(None,proto+';',ti,0)
                                                        idaapi.apply_callee_tinfo(co.ea, ti)
                                                        idaapi.set_op_tinfo(co.ea, 0, ti)
                                                        MakeComm(co.ea, proc_name)
                                                        du.create_comment(c=c, ea=co.ea, comment='%x -> %s' % (co.ea,proc_name))
                                                
                                                
                        except Exception as e:
                                print '{}[-] EA {:x} Exception: {}'.format(' '*160, co.ea, e)
                                fp.write('\n')
                                fp.write('ERROR caller ea: %X \n' % co.ea)
                        
                        
        fp.close()
       
print '-'*80
prepare_hashes()
resolve_api()
print '='*80