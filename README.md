pyelf
=====

Higher level interface to libelf (build on top of pylibelf). Currently its read only. Brief example of using it:

```
from pyelf import *

# This is how you open an elf file:

e = Elf('/bin/ls')

# You can look at the fields/functions defined by any
# object with dir. E.g. this:

print dir(e)

# Will print:
# ['arhdr', 'ehdr', 'section', 'sections', 'shstrndx', 'syms'] 
# You can iterate through sections:

for s in e.sections():
  print s

# And you can access both the underlying pylibelf attributes for each object, as well as some convenience attributes that pyelf adds. For example, you can get the section using the sh_name field of the section header:

for s in e.sections():
  print s.shdr.sh_name

# All the fields present in pylibelf (which have the same name as the structure members in elf.h) are present. pyelf also adds some more convenient fields. For example you can access the string name of a section:

for s in e.sections():
  print s.shdr.name

# Furthermore you can iterate through data in a sections, symbols, relocations etc..

# Also you can go through archives
ar = Ar("/usr/lib/libelf.a", 64)

for elf in ar.elfs():
  print elf.arhdr.ar_name, elf.arhdr.ar_size
```
