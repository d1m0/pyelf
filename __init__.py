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

def _overlap(a, b, c, d):
  return a <= d and c <= b

class Bunch:
  def __setitem__(self, k, v):  self.__dict__[k] = v
  def __getitem__(self, k):  return self.__dict__[k]

class BaseElfNode(object):
  @staticmethod
  def extract(obj):
    return BaseElfNode._extract(obj, {})

  @staticmethod
  def _extract(obj, m):
    """ Given a BaseElfNode object extract a static snapshot of the current
        object and its children that does not refer to the parent or any pylibelf
        objects
    """
    if isinstance(obj, BaseElfNode):
      if obj in m:
        return m[obj]

      res = Bunch()
      m[obj] = res

      for attr in dir(obj):
        if (isinstance(obj, ElfSym) and attr == 'contents' and not obj.defined):
          v = None
        elif (isinstance(obj, ElfScn) and (attr == 'info_scn' or attr == 'link_scn' or attr == 'index')):
          try:
            v = getattr(obj, attr)
          except ElfError: # This section doesn't have a info_scn or a link_scn
            v = None
        else:
          v = getattr(obj, attr)

        if hasattr(v, "__call__"):
          # This is a function - ignore
          continue

        try:
            res[attr] = BaseElfNode._extract(v, m)
        except AttributeError:  pass

      return res
    elif type(obj) == list:
      return map(lambda x:  BaseElfNode._extract(x, m), obj)
    elif type(obj) == tuple:
      return tuple(map(lambda x:  BaseElfNode._extract(x, m), obj))
    elif type(obj) == dict:
      return dict([(BaseElfNode.extract(k, m), BaseElfNode.extract(v, m)) for (k,v) in obj.items()])
    elif type(obj) in [int, str, long, bool, types.NoneType]:
      return obj
    else:
      print type(obj), obj
      return None

  def __init__(self, elf, pt, obj, typ = None, addFields = []):
    assert(pt == None or isinstance(pt, BaseElfNode))
    self._elf = elf
    self._pt = pt
    self._obj = obj
    self._ptr = cast(self._obj, c_void_p).value
    self._typ = typ

    # All object's memoization cache points to the root elf file's memoization cache
    if (isinstance(self, Elf)):
      self._cache = {}
    else:
      while (not isinstance(pt, Elf)):  pt = pt._pt
      self._cache = pt._cache

    self._fields = []
    if self._typ != None:
      self._fields += map(lambda x: x[0], self._typ._fields_)
    self._fields += addFields

  def _select(self, name):  return select(self._elf, name)

  def __getattr__(self, name):
    cache = self._cache
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
      if (self._obj != None):
        inner = self._obj.contents
      else:
        return 0
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

  def _getattr_impl(self, name):
    if (name == "name"):
      return elf_strptr(self._elf, self._pt._pt.ehdr.e_shstrndx, self._obj.contents.sh_name)
    else:
      return BaseElfNode._getattr_impl(self, name)

class ElfSym(BaseElfNode):
  def __init__(self, elf, pt, obj):
    BaseElfNode.__init__(self, elf, pt, obj,
      Elf64_Sym if is64(elf) else Elf32_Sym, ['name', 'section', 'defined', \
        'contents', 'type', 'binding', 'targetScn'])

  def _getattr_impl(self, name):
    if (name == "name"):
      return elf_strptr(self._elf, self._pt.shdr.sh_link, self._obj.contents.st_name)
    elif (name == "section"):
      return self._pt
    elif (name == "defined"):
      return self.st_shndx != SHN_UNDEF
    elif (name == "type"):
      if is64(self._elf):
        return ELF64_ST_TYPE(self.st_info)
      else:
        return ELF32_ST_TYPE(self.st_info)
    elif (name == "binding"):
      if is64(self._elf):
        return ELF64_ST_BIND(self.st_info)
      else:
        return ELF32_ST_BIND(self.st_info)
    elif (name == "targetScn"):
      return self._pt._pt.section(self.st_shndx)
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

      #TODO: rels
      rels = []
      mem = targetSec.memInRange(self.st_value, self.st_size)
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
      ['index', 'shdr', 'link_scn', 'info_scn', 'syms', 'relas', 'relaScns', 'sym', 'data', 'memInRange',
        'relasInRange', 'strAtAddr'])

  def _getattr_impl(self, name):
    if (name == "index"):
      return elf_ndxscn(self._obj)
    elif (name == "shdr"):
      return ElfShdr(self._elf, self, select(self._elf, 'getshdr')(self._obj))
    elif (name == "link_scn" and self.shdr.sh_link != SHN_UNDEF):
      return ElfScn(self._elf, self._pt, elf_getscn(self._elf, \
        self.shdr.sh_link))
    elif (name == "info_scn" and (self.shdr.sh_type == SHT_REL or \
      self.shdr.sh_type == SHT_RELA)):
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
    elif (name == "name"):
      return self.shdr.name
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

  def memInRange(self, start, size):
    r = ''
    off = 0
    base = self.shdr.sh_addr
    end = start + size

    for d in self.data():
      if start >= end:  break;
      off = base + d.d_off
      if start >= off and start < off + d.d_size:
        c = cast(d.d_buf, POINTER(c_char))
        l = min(off + d.d_size, end) - start
        r += c[start- off : start - off + l]
        start += l

    return r

  def relasInRange(self, start, size):
    relas = []

    for relaScn in self.relaScns:
      # [self.st_value ...
      start = bisect_left(relaScn.relas, start)
      #  ... self.st_value + self.st_size)
      end = bisect_left(relaScn.relas, start + size)
      relas.extend(relaScn.relas[start:end])

    return relas

  def strAtAddr(self, ptr):
    r = ''
    off = 0
    base = self.shdr.sh_addr
    start = ptr - base

    for d in self.data():
      off = d.d_off
      c = cast(d.d_buf, POINTER(c_char))

      while (start >= off and start < off + d.d_size):

        if c[start] == '\x00':
          break

        r += c[start]
        start += 1

    return r

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

    self._symsMap = dict([
      (sym.name, sym) for sym in self.syms()
    ])

    self._secMap = dict([
      (elf_ndxscn(s._obj), s) for s in self.sections
    ])


    nullScn = ElfScn(self._elf, self, None)
    self._secMap[0] = nullScn

  def finalize(self):
    elf_end(self._elf)
    if self.fd != None:
      os.close(self.fd)

  def _getattr_impl(self, name):
    if (name == "ehdr"):
      return ElfEhdr(self._elf, self, self._select("getehdr")(self._elf))
    elif (name == "shstrndx"):
      return self.ehdr.e_shstrndx
    elif (name == "arhdr"):
      arhdr = elf_getarhdr(self._elf)
      if (bool(arhdr)):
        return ElfArhdr(self._elf, self, arhdr)
      else:
        raise AttributeError("Elf file doesn't have an arhdr")
    elif (name == "sections"):
      return [ ElfScn(self._elf, self, pointer(s)) for s in
        sections(self._elf) ]
    elif (name == "relasMap"):
      return dict([(s.index, s.relas) \
                  for s in self.sections if s.shdr.sh_type == SHT_RELA])
    else:
      return BaseElfNode._getattr_impl(self, name)

  def section(self, ind):
    return self._secMap[ind]

  def syms(self):
    for scn in self.sections:
      if scn.shdr.sh_type != SHT_SYMTAB and scn.shdr.sh_type != SHT_DYNSYM:
        continue

      for sym in syms(self._elf, scn._obj.contents):
        yield ElfSym(self._elf, scn, pointer(sym[1]))

  def findSym(self, name):
    try:
      return self._symsMap[name]
    except:
      return None

  def deref(self, addr, size):
    r = None
    for s in self.sections:
      # TODO(dbounov): Hack, due to .tbss overlapping other sections. Figure out correct way to deal with this.
      if s.shdr.name == ".tbss":
        continue

      if _overlap(addr, addr+size - 1, s.shdr.sh_addr, s.shdr.sh_addr + s.shdr.sh_size - 1):
        assert r == None # Currently support address ranges in a single section only
        r = (s.memInRange(addr, size), [], s.relasInRange(addr, size) )

    return r

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
