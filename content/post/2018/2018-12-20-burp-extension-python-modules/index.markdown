---
title: "Python Utility Modules for Burp Extensions"
date: 2018-12-19T22:48:10-05:00
draft: false
toc: true
comments: true
twitterImage: 01-extender-options.png
categories:
- Burp
- Burp extension
tags:
- Python
---

We can create and load Python/Java utility modules in Burp and then use them in extensions. It's a somewhat unknown/unused capability in Burp's Python/Java extensions.

**Note:** Alternatively, the modules can be placed in the same path as the extension and loaded/used the same way. For example, instead of putting the Burp Exceptions file in the modules folder, store it in the extension directory.

<!--more-->

# Loading Modules
If you use Burp, you have seen this screen. This is where we set the Jython jar file. Everyone ignores that second input field here (under `Python Environment`). Any Python module in this path will be loaded with Burp. Then the extension can use any function/object inside them.

The same capability exists for Java but not for Ruby. In this blog post I will discuss how I use these modules in my Python extensions.

{{< imgcap title="Extender options" src="01-extender-options.png" >}}

# Burp Exceptions Extension
Before starting to develop any Python extension, please make sure to use:

* https://github.com/securityMB/burp-exceptions

The instructions to set it up are easy and straightforward. You need to load a module and then add a few lines to your extension. Be sure to remove them before you release your code.

Let's say we have referenced a non-existent field or variable in the extension (`self.nothing`). This is the meaningless error message in we will see Burp:

{{< imgcap title="Burp's error message" src="02-burp-error.png" >}}

This is the error message from the extension (appears in the `Output` tab):

{{< imgcap title="Meaningful error message" src="03-python-error.png" >}}

It actually tells us where the problem is. **SO YEAH, USE THE DAMN EXTENSION.**

# Using Modules
I couldn't find any usage documentation or tutorials about modules. Burp documentation mentions the field but that's about it. If you have setup [Burp Exceptions][burp-exceptions], you have probably figured out how they are imported. Modules are imported by their file name. If our file is named `mylibrary.py`, it's can be imported in the extension like this:

``` python
from mylibrary import *
# or a single function
from mylibrary import myFunction
```

Now we can use any function inside `mylibrary.py` (or just `myFunction` in the second case) in our extension.

## Drawback
The end user needs to setup the modules path and copy extra files there. I am also not sure how modules work when extensions are installed from Burp App store.

My solution (yours could be different) is using modules for development/personal/work extensions and then copying the needed functions (or all of them) from the modules to the actual extension for release.

## What's Inside the Module?
Anything and everything. Anything you want and think is useful. I have turned it into a utility library. Things like base64 encoding/decoding, encryption (more on that in the next blog post) and functions that use the Burp's [IExtensionHelpers][iextensionhelpers] methods. It has very helpful methods.

## Using IExtensionHelpers in Modules
The only way to get an object to use these methods is through the [IBurpExtenderCallbacks.getHelpers()][gethelpers] method. As a result, I pass an instance of it manually as a function parameter to each helper function that uses it.

Let's look at a minimal example based on the `custom editor tab` example at https://github.com/PortSwigger/example-custom-editor-tab/blob/master/python/CustomEditorTab.py.

We will see a complete example in the next blog post. The `callbacks` object is available inside the [registerExtenderCallbacks][register-extender-callbacks]


``` python
class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
```

Here we are saving the `helper` object as field. This saves it to the `extender` object that is passed to `__init__` of the tab object. Here we are assigning `extender` to the `_extender`. What I usually do is, add `helpers` directly to a field.

``` python
class Base64InputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable

        # adding helpers as a direct field.
        self.helpers = extender._helpers
        
        # create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
```

Now we can use `self.helpers` inside the extension and use its methods like this:

``` python
self.helpers.analyzeRequest(content)
self.helpers.base64Encode(someBytes)
```

Base64 is an exception because Jython already has a base64 module, so it can be written without the need for `helpers`. You could also write your own implementation of `IExtensionHelpers` methods but why re-implement when it's already been done.

Note: You cannot use anything that is not in the Jython standard library. For example, `pycrypto` for encryption/decryption is not available inside Burp extensions. We will discuss a couple of workarounds in the next blog post.

I also pass it directly as a parameter to helper functions inside my Python module:

``` python
# inside mylibrary.py

# getInfo processes the request/response and returns info
def getInfo(content, isRequest, helpers):
    if isRequest:
        return helpers.analyzeRequest(content)
    else:
        return helpers.analyzeResponse(content)

# getBody returns the body of a request/response
def getBody(content, isRequest, helpers):
    info = getInfo(content, isRequest, helpers)
    return content[info.getBodyOffset():]
```

Now instead of manually doing it, we can just call a function and get the body of what we have.

``` python
# inside the extension
# import the module
from mylibrary import getInfo, getBody

# later inside one of the tab functions
def setMessage(self, content, isRequest):
    if content is None:
        # clear our display
        self._txtInput.setText(None)
        self._txtInput.setEditable(False)
    
    else:
        # get the body of the message
        body = getBody(content, isRequest, self.helpers)
```

# Conclusion
We learned about Burp modules in Python and Java. In the next blog post, I will use this as a building block to show what I learned from creating a Burp extension to decrypt some custom protocol.

<!-- Links -->
[burp-exceptions]: https://github.com/securityMB/burp-exceptions
[iextensionhelpers]: https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html
[gethelpers]: https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html#getHelpers()
[register-extender-callbacks]: https://portswigger.net/burp/extender/api/burp/IBurpExtender.html#registerExtenderCallbacks