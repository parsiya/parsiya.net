---
categories:
- Memfetch
- Kali
comments: true
date: 2014-11-18T23:21:01Z
title: Building memfetch on Kali + Comments
---

I've used Disqus to add comments. At the moment, guests can comment and comments do not need to be approved (unless they have links). Hopefully there won't be much spam to sink the ocassional comment that I think will be posted.

Note: I just wanted to make it work in a hurry. There are probably better ways of doing this.

I stumbled upon the very useful tool [memfetch](http://lcamtuf.coredump.cx/soft/memfetch.tgz) by the talented *lcamtuf*. The utility is quite old (from 2003 if I recall correctly) and I could not build it using the provided makefile.

<!--more-->

{% codeblock lang:bash >}}
$ make
gcc -Wall -O9    memfetch.c   -o memfetch
memfetch.c:30:22: fatal error: asm/page.h: No such file or directory
compilation terminated.
make: *** [memfetch] Error 1
{% endcodeblock >}}

Seems like the location of header files have moved since then. [This stackoverflow answer](http://stackoverflow.com/a/19310710) mentions removing ``asm/page.h`` and adding ``linux/types.h``. Let's see what happens now:

{% codeblock lang:bash >}}
$ make
gcc -Wall -O9    memfetch.c   -o memfetch
memfetch.c: In function ‘main’:
memfetch.c:284:25: error: ‘PAGE_SIZE’ undeclared (first use in this function)
memfetch.c:284:25: note: each undeclared identifier is reported only once for each function it appears in
make: *** [memfetch] Error 1
{% endcodeblock >}}

The ``page.h`` file is located at ``/usr/src/linux-headers-3.12-kali1-common/include/asm-generic/page.h`` on Kali linux. This is where ``PAGE_SIZE`` is defined. Just adding it to ``memfetch.c`` along with changing ``#include <asm/page.h>`` to ``#include <linux/types.h>`` will do the trick.

{% codeblock >}}
// #include <asm/page.h>
#include <linux/types.h>

// Copied from asm-generic/page.h
/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT	12
#ifdef __ASSEMBLY__
#define PAGE_SIZE	(1 << PAGE_SHIFT)
#else
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#endif
#define PAGE_MASK	(~(PAGE_SIZE-1))
{% endcodeblock >}}

If there is a better way to make this work, please let me know.
