from pylibelf import *
from pylibelf.types import *
from pylibelf.iterators import *
from pylibelf.constants import *
from pylibelf.util import *
from pylibelf.util.syms import *
from pylibelf.macros import *
import pylibelf.util
import pylibelf
import os

class BaseElfNode(object):
  def __init__(self, elf, pt, obj, typ = None, addFields = []):
    assert(pt == None or isinstance(pt, BaseElfNode))
    self._elf = elf
    self._pt = pt
    self._obj = obj
    self._typ = typ

    self._fields = []
    if self._typ != None:
      self._fields += map(lambda x: x[0], self._typ._fields_)
    self._fields += addFields
    

  def _select(self, name):  return select(self._elf, name)

  def __getattr__(self, name):
    try:
      inner = self._obj.contents
    except AttributeError:
      raise Exception("Can't access %s in %s - not a pointer" % \
        (name, str(self._obj)))
      
    return getattr(inner, name)

  def _getelf(self):
    p = self
    while not isinstance(p, Elf):
      p = p._pt

    return p

  def _class(self):
    return pylibelf.util._class(self._elf)

  def __dir__(self):
    return self._fields

class ElfEhdr(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj,
      Elf64_Ehdr if is64(elf) else Elf32_Ehdr, [])

class ElfShdr(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj,
      Elf64_Shdr if is64(elf) else Elf32_Shdr, ['name'])

  def __getattr__(self, name):
    if (name == "name"):
      return elf_strptr(self._elf, self._pt._pt.ehdr.e_shstrndx, self._obj.contents.sh_name)
    else:
      return BaseElfNode.__getattr__(self, name)

class ElfSym(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj,
      Elf64_Sym if is64(elf) else Elf32_Sym, ['name', 'section', 'defined', \
        'contents'])


  def __getattr__(self, name):
    if (name == "name"):
      return elf_strptr(self._elf, self._pt.shdr.sh_link, self._obj.contents.st_name)
    elif (name == "section"):
      return self._pt
    elif (name == "defined"):
      return self.st_shndx != SHN_UNDEF
    elif (name == "contents"):
      (c, lelfRels, lelfRelas) = derefSymbolFull(self._elf, self._obj.contents)
      rels = [ ElfRel(self._elf,
        ElfScn(self._elf, self._pt._pt, elf_getscn(self._elf, scnInd)), r)
          for (r, scnInd) in lelfRels ]
      relas = [ ElfRela(self._elf,
        ElfScn(self._elf, self._pt._pt, elf_getscn(self._elf, scnInd)), r)
          for (r, scnInd) in lelfRels ]
      return (c, rels, relas)
    else:
      return BaseElfNode.__getattr__(self, name)

class ElfRela(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj, \
      Elf64_Rela if is64(elf) else Elf32_Rela, ['sym'])

  def __getattr__(self, name):
    if (name == "sym"):
      elfO = self._getelf()
      scn = elfO.section(self._pt.shdr.sh_link)
      symInd = ELF64_R_SYM(self.r_info) if is64(self._elf) else \
        ELF32_R_SYM(self.r_info)
      return ElfSym(self._elf, scn, scn.sym(symInd)._obj)
    else:
      return BaseElfNode.__getattr__(self, name)

class ElfRel(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj, \
      Elf64_Rel if is64(elf) else Elf32_Rel, ['sym'])

  def __getattr__(self, name):
    if (name == "sym"):
      elfO = self._getelf()
      scn = elfO.section(self._pt.shdr.sh_link)
      symInd = ELF64_R_SYM(self.r_info) if is64(self._elf) else \
        ELF32_R_SYM(self.r_info)
      return ElfSym(self._elf, scn, scn.sym(symInd)._obj)
    else:
      return BaseElfNode.__getattr__(self, name)

class ElfData(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj, Elf_Data, [])

class ElfArhdr(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj, Elf_Arhdr, [])

class ElfScn(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj, Elf_Scn,\
      ['index', 'shdr', 'link_scn', 'info_scn', 'syms', 'relas', 'sym', 'data'])
  def __getattr__(self, name):
    if (name == "index"):
      return elf_ndxscn(self._obj)
    elif (name == "shdr"):
      return ElfShdr(self._elf, self, select(self._elf, 'getshdr')(self._obj))
    elif (name == "link_scn"):
      return ElfScn(self._elf, self._pt, elf_getscn(self._elf, \
        self.shdr.sh_link))
    elif (name == "info_scn"):
      return ElfScn(self._elf, self._pt, elf_getscn(self._elf, \
        self.shdr.sh_info))
    elif (name == "syms" and self.shdr.sh_type in [SHT_SYMTAB, SHT_DYNSYM]):
      symT = Elf32_Sym if (is32(self._elf)) else Elf64_Sym
      return reduce(lambda a,c: a+c, \
        map(lambda d: map(lambda sym:  ElfSym(self._elf, self, pointer(sym)), \
          list(arr_iter(d, symT))), list(data(self._obj))))
    elif (name == "relas" and self.shdr.sh_type == SHT_RELA):
      relaT = Elf32_Rela if (is32(self._elf)) else Elf64_Rela
      return reduce(lambda a,c: a+c, \
        map(lambda d: map(lambda rela:  ElfRela(self._elf, self, pointer(rela)),\
          list(arr_iter(d, relaT))), list(data(self._obj))))
    else:
      return BaseElfNode.__getattr__(self, name)

  def sym(self, ind):
    shtype = self.shdr.sh_type 
    if shtype not in [SHT_SYMTAB, SHT_DYNSYM]:
      raise Exception("Section %s does not contain symbols" % (self.shdr.name,))

    return self.syms[ind]

  def data(self):
    d = None
    while True:
      d = elf_getdata(self._obj, d)
      if not bool(d): break
      yield ElfData(self._elf, self, d)

class Elf(BaseElfNode):
  def __init__(self, elf, pt=None, claz = None):
    if type(elf) == str:
      self.fd = os.open(elf, os.O_RDONLY)
      elf = elf_begin(self.fd, ELF_C_READ, None)
    elif isinstance(elf, ElfP):
      self.fd = None
    else:
      raise Exception("Invalid input to Elf.__init__(): %s" % (str(elf), ))

    if claz != None:
      self._class = claz
    else:
      self._class = pylibelf.util._class(elf)

    BaseElfNode.__init__(self, elf, pt, elf, pylibelf.types.Elf, \
      ['ehdr', 'shstrndx', 'arhdr', 'sections', 'section', 'syms', 'findSym'])

  def __del__(self):
    elf_end(self._elf)
    if self.fd != None:
      os.close(self.fd)

  def __getattr__(self, name):
    if (name == "ehdr"):
      return ElfEhdr(self._elf, self, self._select("getehdr")(self._elf))
    elif (name == "shstrndx"):
      return self.ehdr.e_shstrndx
    elif (name == "arhdr"):
      return ElfArhdr(self._elf, self, elf_getarhdr(self._elf))
    else:
      return BaseElfNode.__getattr__(self, name)

  def sections(self, **kwargs):
    for s in sections(self._elf, **kwargs):
      yield ElfScn(self._elf, self, s)

  def section(self, ind):
    return ElfScn(self._elf, self, elf_getscn(self._elf, ind))

  def syms(self):
    for scn in self.sections():
      if scn.shdr.sh_type != SHT_SYMTAB:
        continue

      for sym in syms(self._elf, scn._obj):
        yield ElfSym(self._elf, scn, pointer(sym[1]))

  def findSym(self, name):
    for s in self.syms():
      if s.name == name:
        return s
    return None

class Ar:
  def __init__(self, fname, claz):
    self._fname = fname
    self._class = claz

  def elfs(self):
    self.fd = os.open(self._fname, os.O_RDONLY)
    ar = elf_begin(self.fd, ELF_C_READ, None)
    while True:
      e = elf_begin(self.fd, ELF_C_READ, ar)
      if (not bool(e)): break
      yield Elf(e, None, self._class)

    elf_end(ar)
    os.close(self.fd)

__all__ = [ 'BaseElfNode', 'ElfEhdr', 'ElfShdr', 'ElfSym', 'ElfRela', \
  'ElfData', 'ElfArhdr', 'ElfScn', 'Elf', 'Ar' ]
