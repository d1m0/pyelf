from pylibelf import *
from pylibelf.types import *
from pylibelf.iterators import *
from pylibelf.constants import *
from pylibelf.util import *
from pylibelf.util.syms import *
from pylibelf.macros import *
from bisect import bisect_left
import pylibelf.util
import pylibelf
import types
import os

def _inrange(x, a,b):
  return x>=a and x < b


class BaseElfNode(object):
  _globCache = {}

  def __init__(self, elf, pt, obj, typ = None, addFields = []):
    assert(pt == None or isinstance(pt, BaseElfNode))
    self._elf = elf
    self._pt = pt
    self._obj = obj
    self._ptr = cast(self._obj, c_void_p).value
    self._elf_ptr = cast(self._elf, c_void_p).value
    self._typ = typ
    self._cache = {}


    if self._elf_ptr not in self._globCache:
      self._globCache[self._elf_ptr] = {}

    self._fields = []
    if self._typ != None:
      self._fields += map(lambda x: x[0], self._typ._fields_)
    self._fields += addFields

  def _select(self, name):  return select(self._elf, name)

  def __getattr__(self, name):
    cache = self._globCache[self._elf_ptr]
    key = (self._ptr, name)

    if (key in cache):
      return cache[key]

    res = self._getattr_impl(name)

    if (isinstance(res, types.GeneratorType)):
      cache[key] = list(res)
    else:
      cache[key] = res
    return res

  def _getattr_impl(self, name):
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

  def to_dict(self):
    """ Convert the object into a dictionary.
        Used to remedy the "not enough memory" problem
    """
    return dict([(name, getattr(name)) for name in self._fields])


class ElfEhdr(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj,
      Elf64_Ehdr if is64(elf) else Elf32_Ehdr, [])

class ElfShdr(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj,
      Elf64_Shdr if is64(elf) else Elf32_Shdr, ['name'])

  def _getattr_impl(self, name):
    if (name == "name"):
      return elf_strptr(self._elf, self._pt._pt.ehdr.e_shstrndx, self._obj.contents.sh_name)
    else:
      return BaseElfNode._getattr_impl(self, name)

class ElfSym(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj,
      Elf64_Sym if is64(elf) else Elf32_Sym, ['name', 'section', 'defined', \
        'contents'])

  def _getattr_impl(self, name):
    if (name == "name"):
      return elf_strptr(self._elf, self._pt.shdr.sh_link, self._obj.contents.st_name)
    elif (name == "section"):
      return self._pt
    elif (name == "defined"):
      return self.st_shndx != SHN_UNDEF
    elif (name == "contents"):
      targetSec = self._pt._pt.section(self.st_shndx)
      relas = []

      for relaScn in targetSec.relaScns:
        # [self.st_value ...
        start = bisect_left(relaScn.relas, self.st_value)
        #  ... self.st_value + self.st_size)
        end = bisect_left(relaScn.relas, self.st_value + self.st_size)
        relas.extend(relaScn.relas[start:end])

      # Testing only
      #for r in relas:
      #  assert(r.r_offset >= self.st_value and r.r_offset < self.st_value + self.st_size)

      #TODO: rels = []
      rels = []
      mem = derefSymbol(self._elf, self._obj.contents)
      return (mem, rels, relas)
    else:
      return BaseElfNode._getattr_impl(self, name)

class ElfRela(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj, \
      Elf64_Rela if is64(elf) else Elf32_Rela, ['sym'])

  def _getattr_impl(self, name):
    if (name == "sym"):
      elfO = self._getelf()
      scn = elfO.section(self._pt.shdr.sh_link)
      symInd = ELF64_R_SYM(self.r_info) if is64(self._elf) else \
        ELF32_R_SYM(self.r_info)
      return ElfSym(self._elf, scn, scn.sym(symInd)._obj)
    else:
      return BaseElfNode._getattr_impl(self, name)

  def __cmp__(self, other):
    if type(other) == long or type(other) == int:
      return self.r_offset.__cmp__(other)
    raise Exception("NYI")

class ElfRel(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj, \
      Elf64_Rel if is64(elf) else Elf32_Rel, ['sym'])

  def _getattr_impl(self, name):
    if (name == "sym"):
      elfO = self._getelf()
      scn = elfO.section(self._pt.shdr.sh_link)
      symInd = ELF64_R_SYM(self.r_info) if is64(self._elf) else \
        ELF32_R_SYM(self.r_info)
      return ElfSym(self._elf, scn, scn.sym(symInd)._obj)
    else:
      return BaseElfNode._getattr_impl(self, name)

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

  def _getattr_impl(self, name):
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
    elif (name == "relaScns"):
      return [s for s in self._pt.sections if s.shdr.sh_info == self.index\
        and s.shdr.sh_type == SHT_RELA]
      return None
    else:
      return BaseElfNode._getattr_impl(self, name)

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
  def __init__(self, elf, pt=None, claz = None, fp=None):
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

    self._symsMap = dict([
      (sym.name, sym) for sym in self.syms()
    ])

    if fp != None:
      fp.write("[ELF] __init__ > _globCache: %s\n" % (BaseElfNode._globCache[self._elf_ptr]))
      fp.flush()

    self._secMap = dict([
      (elf_ndxscn(s._obj), s) for s in self.sections
    ])

  def __del__(self):
    fd = self.fd
    elf = self._elf
    elf_ptr = self._elf_ptr
    # Past this point can't access atributes on ourselves
    del self._globCache[elf_ptr]
    elf_end(elf)
    if fd != None:
      os.close(fd)

  def _getattr_impl(self, name):
    if (name == "ehdr"):
      return ElfEhdr(self._elf, self, self._select("getehdr")(self._elf))
    elif (name == "shstrndx"):
      return self.ehdr.e_shstrndx
    elif (name == "arhdr"):
      return ElfArhdr(self._elf, self, elf_getarhdr(self._elf))
    elif (name == "sections"):
      return [ ElfScn(self._elf, self, pointer(s)) for s in
        sections(self._elf) ]
    else:
      return BaseElfNode._getattr_impl(self, name)

  def section(self, ind):
    return self._secMap[ind]

  def syms(self):
    for scn in self.sections:
      if scn.shdr.sh_type != SHT_SYMTAB:
        continue

      for sym in syms(self._elf, scn._obj.contents):
        yield ElfSym(self._elf, scn, pointer(sym[1]))

  def findSym(self, name):
    try:
      return self._symsMap[name]
    except:
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
      r =  Elf(e, None, self._class)
      yield r

    elf_end(ar)
    os.close(self.fd)

__all__ = [ 'BaseElfNode', 'ElfEhdr', 'ElfShdr', 'ElfSym', 'ElfRela', \
  'ElfData', 'ElfArhdr', 'ElfScn', 'Elf', 'Ar' ]
