---
title: "Swing in Python Burp Extensions - Part 3 - Tips and Tricks"
date: 2019-11-26T00:24:37-08:00
draft: false
toc: true
comments: true
twitterImage: # populate this
categories:
- Burp
- Burp extension
tags:
- Python
---

In the two previous parts, we learned about Jython Swing. Those blogs take a lot
of time to write. I think each of them took around 10 hours. I do not want to
spend that kind of time but I still want to document what I have learned.

In this blog I will write tips and tricks with a small code snippet instead of
creating a complete extension.

Did I tell you I release [Bug Diaries](https://github.com/parsiya/bug-diaries),
it's a Python Burp extension that aims to bring Burp issues to the community
version. It's pretty neat.

* [Swing in Python Burp Extensions - Part 1]({{< relref "/post/2019-11-04-gui-python-burp-extension-1/index.markdown" >}} "Swing in Python Burp Extensions - Part 1")
* [Swing in Python Burp Extensions - Part 2 - NetBeans and TableModels]({{< relref "/post/2019-11-11-gui-python-burp-extension-2/index.markdown" >}} "Swing in Python Burp Extensions - Part 2 - NetBeans and TableModels") 

<!--more-->

# See Error Messages in Spawned Frames/Dialogs
When creating new JFrames or JDialogs, you might not get the crash or error
message in Burp. I am not sure why (probably has something to do with either
Swing threads [swing is not thread safe] or because stdout/stderr is not
defined).

For example, I would create a new dialog/frame and spawning it would not do
anything or print any error messages to console. It was pretty hard to figure
out what had gone wrong.

For example, in Java:

```java
public void display() {
    try {
        this.frm.setVisible(true);
    } catch (Exception e) {
        MainDiary.printOutput(e.toString());
    }
}
```

Solution: Put the `.setVisible(True)` statement (or other statements) in
`try/except` (Python) and `try/catch` blocks.

# Save and Load Extension Configuration
You can save extension specific configuration items in Burp and later load them
for reuse. You can use it to persist extension options between Burp sessions. We
can use two `IBurpExtenderCallbacks` methods:

* [loadExtensionSetting][loadextension-doc]
* [saveExtensionSetting][saveextension-doc]

For example, to save the last used directory:

```python

try:
    # get the last used directory from extension settings.
    # it might not exist so we are doing it in a try block.
    lastDir = callbacks.loadExtensionSetting("lastuseddir")
catch:
    pass

# open a dialog at "lastDir".
openFileDialog(lastDir)

# assume newDir is the directory the last opened file.

# save the last used directory
callbacks.saveExtensionSetting("lastuseddir", newDir)
```

# Create a Context Menu

## Step 1: BurpExtener should inherit IContextMenuFactory
[IContextMenuFactory][icontextmenufactory-doc] is the interface to create a
context menu.

```python
class BurpExtender(IBurpExtender, IContextMenuFactory):
```

## Step 2: Register the Context Menu
Use [registerContextMenuFactory][registercontextmenufactory-doc] inside
`registerExtenderCallbacks`.

```python
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        # ...

        callbacks.registerContextMenuFactory(self)
```

## Step 3: Implement the IContextMenuFactory Interface
Create the `createMenuItems` method inside the `BurpExtender` class. It is
called when the context menu is selected in Burp.

```python
class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        # ...

        callbacks.registerContextMenuFactory(self)
    
    def createMenuItems(self, invocation):
        # do something
```

## Step 4: Create The Menu Items
Inside `createMenuItems`, make one or more menu items of type
[JMenuItem][jmenuitem-doc]. Add them to a [java.util.ArrayList][arraylist-doc].
Return the ArrayList.

```python
def createMenuItems(self, invocation):
    from javax.swing import JMenuItem
    menuItem1 = JMenuItem("Label for menu item 1")
    menuItem2 = JMenuItem("Label for menu item 2")
    # add action listeners to menuitems (see below)
    
    from java.util import ArrayList
    menuArray = ArrayList()
    menuArray.add(menuItem1)
    menuArray.add(menuItem2)

    return menuArray
```

## Step 5: Configure Item Click ActionListeners
These are the actions that are executed after clicking each menu item. It can be
done in two ways:

**Method 1**: Directly assign a method to the `actionPerformed` field of
JMenuItem. The method takes one parameter which is an `event` of type
[ActionEvent][actionevent-doc].

This has the disadvantage of not having direct access to the `invocation` (more
on it later), but it's simple and quick.

* Note 1: Directly assigning to `actionPerformed` is not possible in Java.
* Note 2: This can be done with other Swing elements in Jython. For example, a
  button's action can be assigned:
    * `btn1 = JButton("Button Label", actionPerformed=buttonAction)`

        ```python
        class BurpExtender(IBurpExtender, IContextMenuFactory):
            def registerExtenderCallbacks(self, callbacks):
                # ...

            def actionMenu1(self, event):
                # do something when menu item 1 is clicked
                jitem = event.getSource()
            
            def createMenuItems(self, invocation):
                from javax.swing import JMenuItem
                menuItem1 = JMenuItem("Label for menu item 1",
                    actionPerformed=actionMenu1)
                menuItem2 = JMenuItem("Label for menu item 2")
                # add action listeners to menuitems (see below)
                
                from java.util import ArrayList
                menuArray = ArrayList()
                menuArray.add(menuItem1)
                menuArray.add(menuItem2)

                return menuArray
        ```

The most useful method inside the function is `event.getSource()`.
[getSource][getsource-doc] returns the Swing element that was the source of the
event. In this case, we get the menu item that was clicked.

**Method 2**: Create a class that inherits
[java.awt.event.ActionListener][actionlistener-doc]. Inside the class we put the
action inside an `actionPerformed` method similar to the above.

Then we add this class with `addActionListener` to the menu item.

This method has the advantage of being able to get the `invocation` through a
constructor. See this example:

```python
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    # ...

    def createMenuItems(self, invocation):
        """Called when a context menu is invoked in Burp."""
        from javax.swing import JMenuItem
        menuItem1 = JMenuItem("Label for menu item 1")
        menuItem2 = JMenuItem("Label for menu item 2")

        # create an instance of the custom ActionListener and pass the
        # invocation as a parameter to the constructor
        contextMenuListener = ContextMenuListener(invocation)
        # add the instance as an actionlistener
        customMenuItem.addActionListener(contextMenuListener)

        from java.util import ArrayList
        menuArray = ArrayList()
        menuArray.add(menuItem1)
        menuArray.add(menuItem2)
        return menuArray

    # this class is defined before BurpExtender but showing it before helps

class ContextMenuListener(ActionListener):
    """ActionListener for the Burp context menu."""
    def __init__(self, invocation):
        # storing the invocation
        self.invocation = invocation

    def actionPerformed(self, event):
        """Invoked when the context menu item is selected."""
        # now we can use both the event and the invocation
```

## Step 6: Invocation
The invocation is of type [IContextMenuInvocation][icontextmenuinvocation-doc]
and contains a lot of useful methods for figuring out what was clicked and
getting information.

* `getInvocationContext` returns a `byte` that can be used to figure out the
  menu item was clicked in which Burp context. For example,
  `CONTEXT_PROXY_HISTORY` is `6`. See all of them at
  [burp.IContextMenuInvocation enums][context-enums].
* `getSelectedMessages()` is useful for getting the message(s) that were
  selected when the item was clicked. This useful when the extension wants to do
  something with the message(s). For example, sending them to a different tab.
    * Note: This method returns an *array* of [IHttpRequestResponse][ihttprequestresponse-doc].
        ```python
        def actionPerformed(self, event):
            """Invoked when the context menu item is selected."""
            # now we can use both the event and the invocation
            requestResponses = self.invocation.getSelectedMessages()
            for reqResp in requestResponses:
                request = reqResp.getRequest()
                # note: not every message has a response
                response = reqResp.getResponse()
                # https://portswigger.net/burp/extender/api/burp/IHttpService.html#getHost()
                host = reqResp.getHttpService().getHost()
                # do somethings with these
        ```
* `getToolFlag()` returns the tool flag. For example, `TOOL_PROXY` is `4`.
    * See all of them at [burp.IBurpExtenderCallbacks enums][toolflag-enums].

# JTextArea Sizing
[JTextArea][jtextarea-doc] by default does not have word wrap and can take over
all of the GUI if it gets too big.

```python
textArea = JTextArea("some initial text")
# set to readonly
textArea.editable = False
# textArea.setEditable(false) in Java

# enable linewrap
textArea.setLineWrap(True)
# set linewrap to word
textArea.setWrapStyleWord(True)
```

To enable scrollbars and have a fixed size textarea, put it in a
[JScrollPane][jscrollpane-doc].

```python
js = JScrollPane(textArea)
```

# "GroupLayout can only be used with one container at a time" Error
When spawning a new JFrame or JPanel, I would get an error. Before putting the
error in a `try/catch` block, it would not spawn. After that I would get this
error "GroupLayout can only be used with one container at a time."

When using classes that had inherited JFrames or JPanels, it would work but when
I would assign it to a field. And this would mostly happen in Java.

Solution: `GroupLayout` should be assigned to the frame or panel's "content
pane." Content pane is the layer that holds all the objects together.

```java
// Inside the class
private JFrame frm;

// Inside initializeComponent() [which is called by the constructor]
frm = new JFrame();

// Later when assigning the GroupLayout
GroupLayout layout = new GroupLayout(this.frm.getContentPane());
this.frm.getContentPane().setLayout(layout);
```

The following code compiles but will result in the "GroupLayout can only be used ..." error.

```java
GroupLayout layout = new GroupLayout(this.frm);
this.frm.setLayout(layout);
```

# IMessageEditor

* Create it:
    * `callbacks.createMessageEditor([controller], [editable True/False])`
* Add it to the form with `getComponent()`:
    * `jTabbedPane1.addTab("Request", panelRequest.getComponent());`
* Set the message
    * `self.panelRequest.setMessage([message in a byte array], [True if request, False if response])`
* docs:
    * https://portswigger.net/burp/extender/api/burp/IMessageEditor.html

## Context Menu in IMessageEditor
To make this happen, you need to create an
[IMessageEditorController][imessageeditorcontroller-doc] and assign it to the
`IMessageEditor` during creation.

```python
class MyController(IMessageEditorController):
    # needs to implement three methods
    def getHttpService():
        # ...
    def getRequest():
        # ...
    def getResponse():
        # ...

# ...
# creating the IMessageEditor in gui
callbacks.createMessageEditor(MyController, [editable True/False])
```

Now you can the context menu in your IMessageEditors. E.g., `Send to Repeater`.

Creating this interface is straightforward in simple extensions. For a good
example, see the `Custom Logger` extension from Portswigger:

* https://github.com/PortSwigger/custom-logger/blob/master/python/CustomLogger.py#L121

In this case, the extension implements this interface. The extension stores the
selected `IHttpRequestResponse` in the log and returns its fields in these
methods.

```python
class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    # ...

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    # inside registerExtenderCallbacks
    def	registerExtenderCallbacks(self, callbacks):
        # ...
        # https://github.com/PortSwigger/custom-logger/blob/master/python/CustomLogger.py#L45
        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
```

# Select the Current Text When Control is Selected
When tabbing between controls that have text (e.g., JTextField, JTextArea), we
want the current selection. This allows us to replace the default text with new
items without having to select it manually. This is done with setting the
selection start index to `0`.

* In Python:
    * `textField1.setSelectionStart(0)`
    * `textField.selectionstart = 0`
* In Java:
    * `textField1.setSelectionStart(0)`

# Print to Console
Normal print statements do the job in the main thread. `print` in Python and
`System.out.println` in Java. But when I was printing in other Swing components
(e.g., a spawned JFrame), it did not work.
[callbacks.getStdout()][callbacks-getstdout-doc] returns a
`java.io.OutputStream` which is a pain to print too.

Instead use [callbacks.printOutput][callbacks-printoutput-doc] and
[callbacks.printError][callbacks-printerror-doc]. Create functions like this and
use them using `callbacks`.

```java
/**
* Prints the String s to standard output.
* @param s The String to be printed.
*/
public static void printOutput(String s) {
    callbacks.printOutput(s);
}

/**
* Prints the String s to standard error.
* @param s The String to be printed.
*/
public static void printError(String s) {
    callbacks.printError(s);
}
```

# Equivalent of Jython toString() is \__repr()\_\_ in Python
When creating a class, you might want to create a `toString()` method. The
equivalent of it in Python is not `__str()__` but instead `__repr()__`.

Source: https://stackoverflow.com/a/6950800

# Adding Objects to a JComboBox
It's done with [JComboBox.addItem()][jcombobox-additem-doc]. To decide what is
displayed in the combobox for each item, the class needs to have `toString()`
method in Java and `__repr()__` in Python

For example, if we want to add objects from the `Issue` class to the combobox
and display the issue name.

```python
class Issue():
    # fields
    self.name
    self.host

    def __repr__(self):
        return self.name

# later they are added to the combobox
cBox = JComboBox()
for issue in issues:
    cBox.addItem(issue)
```

# Assign Fields to a Python Object
Python stores an object field in a dictionary. Let's say you have a dictionary
of items and you want to assign them as fields of an object:

```python
d = {"name": "name1", "path": "example.net"}

obj1 = SomeClass()
obj1.__dict__.update(d)
```

`update` keeps any existing attributes that are not in the new dictionary. To
overwrite those, assign it like this `obj1.__dict__ = d`

# Converting an Object with Object Fields to JSON
`json.dump(s)` do not work on objects that have other objects as fields. It
works if the object only has primitive types.

```python
class Obj1():
    # field
    self.name # string
    self.host # string

    def toJSON():
        return json.dumps(self.__dict, indent=2)
```

But if `Obj1` has another class as a field. We get an error that the field is
not serializable. We add a `customJSON` method to `Obj1` and other classes that
are fields. This method returns the fields as a dictionary.

```python
class Obj():
    # field
    self.name # string
    self.host # string
    self.child # type Obj2

    def customJSON(self):
        return dict(
            name = self.name,
            host = self.host,
            child = self.child
        )

class Obj2():
    # fields
    self.name # string
    # ...

    def customJSON(self):
        return dict(
            name = self.name
            # ...
        )
```

Next, we create an encoder of type `json.JSONEncoder`.

```python
class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj,'customJSON'):
            return obj.customJSON()
        else:
            return json.JSONEncoder.default(self, obj)
```

This encoder checks if the class has a method called `customJSON`, if so, it
will use it to return a dictionary. Otherwise, it will use the normal encoder.

We can convert an array of `Obj` to JSON:

```python
def objsToJSON(self):
    from ComplexEncoder import ComplexEncoder
    return json.dumps([obj.customJSON() for obj in objects],
                            cls=ComplexEncoder, indent=2)
```

<!-- Links -->
[loadextension-doc]: https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html#loadExtensionSetting(java.lang.String)
[saveextension-doc]: https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html#saveExtensionSetting(java.lang.String,%20java.lang.String)
[icontextmenufactory-doc]: https://portswigger.net/burp/extender/api/burp/IContextMenuFactory.html
[registercontextmenufactory-doc]: https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html#registerContextMenuFactory(burp.IContextMenuFactory)
[jmenuitem-doc]: https://docs.oracle.com/javase/8/docs/api/javax/swing/JMenuItem.html
[arraylist-doc]: https://docs.oracle.com/javase/8/docs/api/java/util/ArrayList.html
[actionevent-doc]: https://docs.oracle.com/javase/8/docs/api/java/awt/event/ActionEvent.html
[actionlistener-doc]: https://docs.oracle.com/javase/8/docs/api/java/awt/event/ActionListener.html
[getsource-doc]: https://docs.oracle.com/javase/8/docs/api/java/util/EventObject.html#getSource--
[icontextmenuinvocation-doc]: https://portswigger.net/burp/extender/api/burp/IContextMenuInvocation.html
[context-enums]: https://portswigger.net/burp/extender/api/constant-values.html#burp.IContextMenuInvocation.CONTEXT_INTRUDER_ATTACK_RESULTS
[ihttprequestresponse-doc]: https://portswigger.net/burp/extender/api/burp/IHttpRequestResponse.html
[toolflag-enums]: https://portswigger.net/burp/extender/api/constant-values.html#burp.IBurpExtenderCallbacks.TOOL_COMPARER
[jtextarea-doc]: https://docs.oracle.com/javase/8/docs/api/javax/swing/JTextArea.html
[jscrollpane-doc]: https://docs.oracle.com/javase/8/docs/api/javax/swing/JScrollPane.html
[imessageeditorcontroller-doc]: https://portswigger.net/burp/extender/api/burp/IMessageEditorController.html
[callbacks-getstdout-doc]: https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html#getStdout()
[callbacks-printoutput-doc]: https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html#printOutput(java.lang.String)
[callbacks-printerror-doc]: https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html#printError(java.lang.String)
[jcombobox-additem-doc]: https://docs.oracle.com/javase/8/docs/api/javax/swing/JComboBox.html#addItem-E-
