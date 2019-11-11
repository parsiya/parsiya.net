---
title: "Swing in Python Burp Extensions - Part 2 - NetBeans and TableModels"
date: 2019-11-11T12:00:53-08:00
draft: false
toc: true
comments: true
twitterImage: 00-swjfo-bd1.jpg
categories:
- Burp
- Burp extension
tags:
- Python
---

In [part 1]({{< relref "/post/2019-11-04-gui-python-burp-extension-1" >}} "Swing
in Python Burp Extensions - Part 1") we discussed handcrafting Swing GUI items
in a form. In this part, we will design a GUI using
[NetBeans](https://netbeans.org/) and then convert it to Jython. Then use it in
a Burp tab. Next, we will create a custom table model based on objects to handle
our issues.

Code is at:

* https://github.com/parsiya/Parsia-Code/tree/master/jython-swing-2

<!--more-->

{{< imgcap title="BD-1, design this GUI for me" src="00-swjfo-bd1.jpg" >}}

[Image credit: Electronic Arts - Star Wars Jedi: Fallen Order](https://www.ea.com/games/starwars/jedi-fallen-order/media).

Open NetBeans and follow any tutorial to design a form. In this case, I am going
to design something that looks like an issue tab.

# Designing in NetBeans

1. Open NetBeans.
2. `File > Open Project` and point to the `jython-swing-2\01-SampleGUI` directory.
3. If the form is not opened, select it from the sidebar at
   `Source Packages > sample > SampleJFrame.java`.
4. Click on the `Design` tab to view the form.

{{< imgcap title="Opening the form" src="01-open-form.png" >}}

This is not a GUI design tutorial. You can use any tutorial on the web but Swing
GUI design in NetBeans is pretty much the same as any other IDE (e.g., Visual
C#). It's mostly drag and drop.

{{< imgcap title="GUI in NetBeans" src="02-form-netbeans.png" >}}

After you are satisfied with your design, click on the `Source` tab beside
`Design`. You will see a Java file that has the generated code for the GUI. This
must be converted to Jython. The important part is the section after
`@SuppressWarnings` which is already folded in the editor with the label
`Generated Code`. `initComponents` sets up the GUI. Copy the contents of the
function into a separate file in your favorite editor and get converting.

For extensions in Java, the following guide by
[Paul Ritchie][paul-ritchie-twitter] A.K.A. [Corner Pirate][paul-ritchie-github]
on the Secarma Labs blog from October 2017 discusses designing Burp extension
GUIs in NetBeans and then hooking them up in Burp. I have not tried
it so I don't know if it works, but it's a good idea:

* https://blog.secarma.com/labs/using-netbeans-gui-designer-to-make-pretty-burp-extenders

# Converting to a JFrame
This is a simple process in this context. Because of our knowledge from part 1,
we understand some of these words. This is good, because if something goes
wrong, we can troubleshoot.

The conversion process was simple:

1. Remove `new `.
2. Remove `;`.
3. Search for `javax.swing.` and import everything.
4. Then remove `javax.swing.`.
5. Add everything to the constructor of a new class.

The result is in `02-JFrame`. If we add `extension.py` to Burp, we will get a
detached JFrame.

{{< imgcap title="JFrame" src="03-frame.png" >}}

Inside `getUiComponent` we create an instance of the frame, display it and
return it.

{{< codecaption title="02-JFrame/extension.py/getUiComponent" lang="python" >}}
def getUiComponent(self):
    from NBFrame import NBFrame
    frm = NBFrame()
    frm.pack()
    frm.show()
    return frm
{{< /codecaption >}}

`NBFrame` (stands for NetBeans frame) is a [JFrame][jframe-doc]. Some items have
been commented out. I will discuss the important parts.

```python
from javax.swing import (JScrollPane, JTable, JPanel, JTextField, JLabel,
     JTabbedPane, JComboBox, table, BorderFactory, GroupLayout, LayoutStyle,
     JFrame)

class NBFrame(JFrame):
    """Represents the converted frame from NetBeans."""
```

## DefaultTableModel
[JTable][jtable-doc] uses a model to populate the data and cells. We are using
the [DefaultTableModel][defaulttablemodel-doc]. One of its constructors creates
a model from a 2D array containing the data and a string array with the column
names (or headers).

```python
tableData = [
    [None, None, None, None, None],
    [None, None, None, None, None],
    [None, None, None, None, None]
]
tableColumns = ["#", "Issue Type/Name", "Severity", "Host", "Path"]
# create the table model
tableModel = table.DefaultTableModel(tableData, tableColumns)
```

The [TableModel][tablemodel-doc] interface has methods for returning the column
types (`getColumnClass`) or if cells are editable (`isCellEditable`) among other
things. The designer has created these because I
added types to columns. By default, they are all `java.lang.Object.class`. These
are commented out in this version of the extension but we will use them later.

We are also setting up an auto sorter, this lets users sort the table by
clicking on the columns. This is a neat idea but it will cause some headaches
later.

```python
# set the table model
# if this fails, we have to use
self.jTable1.setModel(tableModel)
self.jTable1.setAutoCreateRowSorter(True)

# wrap the table in a scrollpane
self.jScrollPane1.setViewportView(self.jTable1)
```

The table might contain more rows than can be displayed in the GUI, so the
designer has created a [JScrollPane][jscrollpane-doc] and assigned the table to
it. This allows us to scroll to see all rows.

The rest of the auto-generated GUI code looked complex. The best I could do
was convert it, run the extension and fix errors. The only interesting part was
these lines:

```java
javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
getContentPane().setLayout(layout);
```

Because we are inside a JFrame, we can replace it with:

```python
layout = GroupLayout(self.getContentPane())
self.getContentPane().setLayout(layout)
```

# Using a JPanel
We do not want a detached frame. We want our extension to be in the Burp tab. To
display our creation in a Burp tab we need to convert it to a panel. I tried
creating an `NBPanel` class that inherits JPanel but it did not work out. It
messed up and was displayed on top of every tab.

The fix (might not be the correct fix but works in this case) is to create the
panel and assign it to a field of NBPanel (and not inherit anything). The result
is in `03-NBPanel` directory:

```python
# NBPanel is not inheriting anything.
class NBPanel():
    """Represents the converted frame from NetBeans."""
```

Now the part above with `getContentPane()` becomes:

```python
# create the main panel
self.panel = JPanel()
layout = GroupLayout(self.panel)
self.panel.setLayout(layout)
```

Inside our extension, we create an object and then return the panel.

{{< codecaption title="03-NBPanel\extension.py\getUiComponent" lang="python" >}}
def getUiComponent(self):
    # GUI happens here
    from NBPanel import NBPanel
    nbp = NBPanel()
    return nbp.panel
{{< /codecaption >}}

The panel works:

{{< imgcap title="NBPanel with an empty table" src="04-panel.png" >}}

# Customizing the Table
The table is editable. This is useful but not here. I want
to edit the rows in a different pop-up because data will have more rows than
displayed in the table.

We need to create our own [TableModel][tablemodel-doc] named `IssueTable`. The
source resides in `04-CustomTableModel`:

{{< codecaption title="04-CustomTableModel/IssueTable.py" lang="python" >}}
class IssueTableModel(DefaultTableModel):
    """Extends the DefaultTableModel to make it readonly (among other
    things)."""

    def __init__(self, data, headings):
        # call the DefaultTableModel constructor to populate the table
        DefaultTableModel.__init__(self, data, headings)

    def isCellEditable(self, row, column):
        """Returns True if cells are editable."""
        # make all rows and columns uneditable.
        # do we need to check the column value here?
        canEdit = [False, False, False, False, False]
        return canEdit[column]
        # return False

    def getColumnClass(self, column):
        """Returns the column data class. Optional in this case."""
        from java.lang import Integer, String, Object
        # return Object if you don't know the type.
        # only works if we are not changing the number of columns
        columnClasses = [Integer, String, String, String, String]
        return columnClasses[column]
{{< /codecaption >}}

* `__init__`: We are calling the parent constructor.
* `isCellEditable` allows us to decide which cell is editable. In this case, we
  are using a list with an element for each column. More detailed control is
  possible because we have both row and column. It's easier to just return
  `False` to make everything uneditable.
* `getColumnClass` returns the class of each column.

## Handling Mouse Events
We can detect when the table is clicked and act accordingly. This is done by
implementing the [MouseListener][mouselistener-doc] interface and adding it to
the table. Our custom mouse listener is in the `IssueTableMouseListener` class.

It has two helper functions. `getClickedIndex` returns the index number of the
item. Index is the first column so it detects which row is selected and then
returns the value of the first column. **Note**: This will be unreliable if we do
not disable column reordering. See below in the `IssueTable` section.

```python
def getClickedIndex(self, event):
    """Returns the value of the first column of the table row that was
    clicked. This is not the same as the row index because the table
    can be sorted."""
    # get the event source, the table in this case.
    tbl = event.getSource()
    # get the clicked row
    row = tbl.getSelectedRow()
    # get the first value of clicked row
    return tbl.getValueAt(row, 0)
    # return event.getSource.getValueAt(event.getSource().getSelectedRow(), 0)
```

`event.getSource()` returns the object/component that sourced the event (the
table in this case). We can get the selected row (and also column with
`getSelectedColumn`). Then we return the first value of the row which is the
index. `getClickedRow` returns the data in the clicked row as a
[java.util.Vector][vector-doc].

```python
def getClickedRow(self, event):
    """Returns the complete clicked row."""
    tbl = event.getSource()
    return tbl.getModel().getDataVector().elementAt(tbl.getSelectedRow())
```

The interface has a few methods but we are only interested in `mouseClicked` to
detect single and double-clicks. The following code prints the data in the row
after each click.

```python
# event.getClickCount() returns the number of clicks.
def mouseClicked(self, event):
    if event.getClickCount() == 1:
        # print "single-click. clicked index:", self.getClickedRow(event)

        # modify the items in the panel
        print "single-click: ", self.getClickedRow(event)

    if event.getClickCount() == 2:
        # open the dialog to edit
        print "double-click: ", self.getClickedRow(event)
```

For more information, please see the Java tutorial
[How to Write a Mouse Listener][mouselistener-tutorial].

Finally, we have the actual table.

```python
class IssueTable(JTable):
    """Issue table."""

    def __init__(self, data, headers):

        # set the table model
        model = IssueTableModel(data, headers)
        self.setModel(model)
        self.setAutoCreateRowSorter(True)
        # disable the reordering of columns
        self.getTableHeader().setReorderingAllowed(False)
        # assign panel to a field
        self.addMouseListener(IssueTableMouseListener())
```

Inside `NBPanel` we set the table:

```python
# setting up the table
# initial data in the table
tableData = [
    [3, "Issue3", "Severity3", "Host3", "Path3"],
    [1, "Issue1", "Severity1", "Host1", "Path1"],
    [2, "Issue2", "Severity2", "Host2", "Path2"],
]
tableHeadings = ["#", "Issue Type/Name", "Severity", "Host", "Path"]
from IssueTable import IssueTable
self.jTable1 = IssueTable(tableData, tableHeadings)

# wrap the table in a scrollpane
self.jScrollPane1.setViewportView(self.jTable1)
```

{{< imgcap title="Populated custom table" src="05-panel2.png" >}}

The data is printed to console after clicking on each row.

{{< imgcap title="Row data printed after mouseclicks" src="06-rowdata-printed.png" >}}

# Updating the Panel with The Selected Row
In this step, we want to update the read-only items in the panel such as the
name, host, and path with the data from the selected row in the table. You
probably have noticed that somewhere in between I changed the severity combobox
to a text box. This works better for read-only data. The code for this section is in 
`05-UpdatePanel`.

Updating the panel should be done inside `mouseClicked`. But while we can get
the table through `event.getSource()`, we do not have access to the main panel.
I guess with some trickery we could traverse the hierarchy and get it, but it
looks like too much work. Instead, I choose the simple way of passing a "global"
panel object between modules. This is not pythonic but does the job.

The panel class has been renamed to `MainPanel` and resides in `MainPanel.py`
(doh). At the end of the file, there is an instance of `MainPanel`.

```python
# create "global" panel
mainPanel = MainPanel()
```

This is then loaded in `extension.py` and used.

{{< codecaption title="05-UpdatePanel/extension.py" lang="python" >}}
def getUiComponent(self):
    # GUI happens here
    from MainPanel import mainPanel
    return mainPanel.panel
{{< /codecaption >}}

Inside `IssueTable.py` we do the same and use `mainPanel` in `mouseClicked`.

{{< codecaption title="05-UpdatePanel/IssueTable.py/mouseClicked" lang="python" >}}
def mouseClicked(self, event):
    if event.getClickCount() == 1:
        # print "single-click. clicked index:", self.getClickedIndex(event)
        rowData = self.getClickedRow(event)

        # let's see if we can modify the panel
        print rowData
        # import mainPanel to modify it
        from MainPanel import mainPanel
        mainPanel.textName.text = rowData.get(1)
        mainPanel.textSeverity.text = rowData.get(2)
        mainPanel.textHost.text = rowData.get(3)
        mainPanel.textPath.text = rowData.get(4)
{{< /codecaption >}}

This mostly works. After clicking each item, it's updated in the rest of the
panel.

{{< imgcap title="Updating the panel with row data" src="07-update-panel.gif" >}}

However, there is a problem. If we sort the table, the view changes and if we
click on any row, it will update it to the data that was there before sorting.
For example, in the gif, issue2 is the 3rd item. After we sort the table by the
index (`#`) column, it will be the second item (which was issue1 before). After
clicking on it, the panel information does not change to issue2. If we click on
the 3rd item (now issue3), the panel will be updated with issue2.

{{< imgcap title="Panel update problem after sorting" src="08-update-panel-sort.gif" >}}

We can read about this behavior in the [JTable Documentation][jtable-doc]:

> All of JTables row based methods are in terms of the RowSorter, which is not
> necessarily the same as that of the underlying TableModel. For example, the
> selection is always in terms of JTable so that when using RowSorter you will
> need to convert using convertRowIndexToView or convertRowIndexToModel.

We need to pass the row from the table (`table.getSelectedRow()`) to
[table.convertRowIndexToModel][convertrowindextomodel-doc].

{{< codecaption title="Fixed getClickedRow" lang="python" >}}
def getClickedRow(self, event):
    """Returns the complete clicked row."""
    tbl = event.getSource()
    return tbl.getModel().getDataVector()
        .elementAt(tbl.convertRowIndexToModel(tbl.getSelectedRow()))
{{< /codecaption >}}

This fixes the issue.

{{< imgcap title="Sort issue fixed" src="09-sort-fixed.gif" >}}

# Populating the Table from Outside
Hardcoding the table data in `MainPanel` is not practical. My initial way to do
this was manually assigning something to the `jTable1` from inside
`getUiComponent`. See the code for this section in `06-UpdateTable`.

```python
# 06-UpdateTable/MainPanel.py
self.jTable1 = IssueTable(None, None)

# 06-UpdateTable/extension.py
tableData = [
    [3, "Issue3", "Severity3", "Host3", "Path3"],
    [1, "Issue1", "Severity1", "Host1", "Path1"],
    [2, "Issue2", "Severity2", "Host2", "Path2"],
]
tableHeadings = ["#", "Issue Type/Name", "Severity", "Host", "Path"]
from IssueTable import IssueTable
mainPanel.jTable1 = IssueTable(tableData, tableHeadings)
return mainPanel.panel
```

But it resulted in an empty table (no headings or data). The panel is already
created, so after adding the table I needed to do something else (maybe
redraw?). I decided I need to change the structure a bit. Hence, instead of
creating the `burpPanel` inside `MainPanel.py`, I would create the variable
and then create and assign it in `extension.py`. I also decided to change the
name of `mainPanel` to `burpPanel` (less confusing).

{{< codecaption title="Modified code for 06-UpdateTable" lang="python" >}}
# MainPanel.py
# create "global" panel
# mainPanel = MainPanel()
burpPanel = None

# extension.py/getUiComponent
def getUiComponent(self):
    tableData = [
        [3, "Issue3", "Severity3", "Host3", "Path3"],
        [1, "Issue1", "Severity1", "Host1", "Path1"],
        [2, "Issue2", "Severity2", "Host2", "Path2"],
    ]
    tableHeadings = ["#", "Issue Type/Name", "Severity", "Host", "Path"]
    from IssueTable import IssueTable
    table = IssueTable(tableData, tableHeadings)
    import MainPanel
    MainPanel.burpPanel = MainPanel.MainPanel(table)
    return MainPanel.burpPanel.panel
{{< /codecaption >}}

The constructor for `MainPanel` has also been modified to add an optional table
parameter. We are using this new table parameter to pass the IssueTable.

{{< codecaption title="Modified constructor" lang="python" >}}
class MainPanel():
    """Represents the converted frame from NetBeans."""

    # mostly converted generated code
    def __init__(self, table=None):
        # removed
        self.jTable1 = table
{{< /codecaption >}}

Let's also experiment with adding data to the table in real-time after the form
has been created. The `IssueTable` class gets a new method:

{{< codecaption title="06-UpdateTable/IssueTable.py" lang="python" >}}
class IssueTable(JTable):
    """Issue table."""

    def addRow(self, data):
        """Add a new row to the tablemodel."""
        self.getModel().addRow(data)
{{< /codecaption >}}

Note that we are not checking the data for the correct length. Later, we
need to create objects to pass to the table to display and add. After creating
the table, we add a new row:

{{< codecaption title="06-UpdateTable/extension.py/getUiComponent" lang="python" >}}
def getUiComponent(self):
    # GUI happens here
    tableData = [
        [3, "Issue3", "Severity3", "Host3", "Path3"],
        [1, "Issue1", "Severity1", "Host1", "Path1"],
        [2, "Issue2", "Severity2", "Host2", "Path2"],
    ]
    tableHeadings = ["#", "Issue Type/Name", "Severity", "Host", "Path"]
    from IssueTable import IssueTable
    table = IssueTable(tableData, tableHeadings)
    import MainPanel
    MainPanel.burpPanel = MainPanel.MainPanel(table)

    table.addRow([4, "Issue4", "Severity4", "Host4", "Path4"])

    return MainPanel.burpPanel.panel
{{< /codecaption >}}

It works but to be sure, we want to add another row after we interact with the
tab in Burp. To do so, I am going to modify the double click section in the
`mouseClicked` method in `IssueTableMouseListener`. When we double-click any
cell, a new row should be added to the table.

{{< codecaption title="06-UpdateTable/IssueTable.py/IssueTableMouseListener" lang="python" >}}
# event.getClickCount() returns the number of clicks.
def mouseClicked(self, event):
    if event.getClickCount() == 1:
        # removed
    if event.getClickCount() == 2:
        # open the dialog to edit
        # print "double-click. clicked index:", self.getClickedIndex(event)
        tbl = event.getSource()
        tbl.addRow([11, "dblclick-name", "dblclick-severity", "dblclick-host", "dblclick-path"])
{{< /codecaption >}}

Works in real-time. In this gif, double-click on row 4 added a new row.

{{< imgcap title="Double-click adds a new row" src="10-double-click-add.gif" >}}

# Revamping the TableModel
Up until now, our table is manual. It's about time we created an Issue
object and used it in the table.

## Issue Object
We now have a new object called `Issue` (I would have preferred to call it a
finding but Burp calls them issues and do we). Issue has a bunch of fields and
not all fields are shown in the table.

{{< codecaption title="07-ObjectTableModel/Issues.py class" lang="python" >}}
class Issue():
    """Issue represents one finding."""
    # index of the finding in the table.
    index = None  # type: int
    # issue name/type.
    name = ""  # type: str
    # severity: could be an enum but we will use a string to support custom
    # values.
    severity = ""  # type: str
    # host - might be better to merge it with path.
    host = ""  # type: str
    path = ""  # type: str
    description = ""  # type: str
    remediation = ""  # type: str
    # request and response will be stored as base64 encoded strings.
    request = ""  # type: str
    response = ""  # type: str
{{< /codecaption >}}

You can ignore the type hints but they are useful when coding in IntelliJ IDEA
(VS Code does not support Jython).

Requests and responses are generally byte arrays so we will store them in
base64. Hence, we will have these extra methods to do it.

{{< codecaption title="07-ObjectTableModel/Issues.py request/response methods" lang="python" >}}
def getRequest(self):
    # type: () -> bytearray
    """Base64 decode the request and return the results."""
    return b64decode(self.request)

def setRequest(self, req):
    # type: (bytearray) -> None
    """Base64 encode the request and store it."""
    self.request = b64encode(req)

def getResponse(self):
    # type: () -> bytearray
    """Base64 decode the response and return the results."""
    return b64decode(self.response)

def setResponse(self, resp):
    # type: (bytearray) -> None
    """Base64 encode the response and store it."""
    self.response = b64encode(resp)
{{< /codecaption >}}

Which converts our constructor to:

{{< codecaption title="07-ObjectTableModel/Issues.py constructor" lang="python" >}}
def __init__(self, index=None, name="", severity="", host="", path="",
                description="", remediation="", request="", response=""):
    """Create the issue."""
    self.index = index
    self.name = name
    self.severity = severity
    self.host = host
    self.path = path
    self.description = description
    self.remediation = remediation
    self.setRequest(request)
    self.setResponse(response)
{{< /codecaption >}}

## Modified UI
To display requests and responses, I changed them to Burp's
[IMessageEditor][imessageeditor-doc]. Description and remediation are now
[JTextAreas][jtextarea-doc] (these allow displaying styleddocuments that we used
in part 1).

IMessageEditors cannot be constructed normally. We have to use
[IBurpExtenderCallbacks.htmlcreateMessageEditor][createmessageeditor-doc] to get
an instance. As a result, we need to pass an instance of callbacks to MainPanel
via the constructor.

{{< codecaption title="07-ObjectTableModel/MainPanel.py constructor" lang="python" >}}
class MainPanel():
    """Represents the converted frame from NetBeans."""

    # mostly converted generated code
    def __init__(self, callbacks, table=None):
        # removed
        self.tabIssue = JTabbedPane()
        self.textAreaDescription = JTextArea()
        self.panelRequest = callbacks.createMessageEditor(None, False)
        self.panelResponse = callbacks.createMessageEditor(None, False)
        self.textAreaRemediation = JTextArea()
{{< /codecaption >}}

A small gotcha when adding the IMessageEditors to the tab. You need to call
`getComponent` on them to pass them as seen in the
[CustomLogger example][customlogger-l45].

```python
# request tab
self.panelRequest.setMessage("", True)
self.tabIssue.addTab("Request", self.panelRequest.getComponent())

# response tab
self.panelResponse.setMessage("", False)
self.tabIssue.addTab("Response", self.panelResponse.getComponent())
```

## IssueTableModel
The bulk of the change happens in the `IssueTable.py` file.  `IssueTableModel`
is now extending the [AbstractTableModel][abstracttablemodel-doc] class. Looking
at the description, we only *need* to implement three methods. I followed this
guide from 2008 and `CustomLogger` does the same:

* https://tips4java.wordpress.com/2008/11/21/row-table-model/

In both examples, there is an underlying data structure which is an array of
objects. The custom tablemodel manages adding and removing items. The
table just displays them.

{{< codecaption title="07-ObjectTableModel/IssueTable.py" lang="python" >}}
class IssueTableModel(AbstractTableModel):
    """Represents the extension's custom issue table. Extends the
    AbstractTableModel to make it readonly."""
    # column names
    columnNames = ["#", "Issue Type/Name", "Severity", "Host", "Path"]
    # column classes

    columnClasses = [java.lang.Integer, java.lang.String, java.lang.String,
                     java.lang.String, java.lang.String]

    # list to hold all the issues
    # if this does not work use an ArrayList
    # from java.util import ArrayList
    # issues = ArrayList() - issues.add(whatever)
    issues = list()

    def __init__(self, issues=None):
        """Create an issue table model and populate it (if applicable)."""
        self.issues = issues
{{< /codecaption >}}

We can see the usual column names/classes. Then we have the `issues` list which
will hold all of them and is populated in the constructor.

Next comes the three methods we need to implement after inheriting from
`AbstractTableModel`.

{{< codecaption title="07-ObjectTableModel/IssueTable.py implemented methods" lang="python" >}}
def getColumnCount(self):
    # type: () -> int
    """Returns the number of columns in the table model."""
    return len(self.columnNames)

def getRowCount(self):
    # type: () -> int
    """Returns the number of rows in the table model."""
    return len(self.issues)

def getValueAt(self, row, column):
    # type: (int, int) -> object
    """Returns the value at the specified row and column."""
    if row < self.getRowCount() and column < self.getColumnCount():
        # is this going to come back and bite us in the back because we
        # are ignoring the hidden fields?
        issue = self.issues[row]
        if column == 0:
            return issue.index
        if column == 1:
            return issue.name
        if column == 2:
            return issue.severity
        if column == 3:
            return issue.host
        if column == 4:
            return issue.path
        return None
{{< /codecaption >}}

We are not displaying every `Issue` field so `getValueAt` only returns some of
them. This is where we decide which column displays what field and can do any
transformation that we want.

I added some extra utility methods like `addIssue` and `removeIssue`. There is a
method named `setValueAt` which is not needed here because our table is
read-only.

## IssueTableMouseListener
The MouseListener is the same as before with some minor modifications mostly in
the `mouseClicked` method.

{{< codecaption title="07-ObjectTableModel/IssueTable.py mouseClicked" lang="python" >}}
def mouseClicked(self, event):
    if event.getClickCount() == 1:
        # print "single-click. clicked index:", self.getClickedIndex(event)
        rowData = self.getClickedRow(event)
        assert isinstance(rowData, Issue)

        # let's see if we can modify the panel
        # import burpPanel to modify it
        from MainPanel import burpPanel, MainPanel
        assert isinstance(burpPanel, MainPanel)
        burpPanel.textName.text = rowData.name
        burpPanel.textSeverity.text = rowData.severity
        burpPanel.textHost.text = rowData.host
        burpPanel.textPath.text = rowData.path
        burpPanel.textAreaDescription.text = rowData.description
        burpPanel.textAreaRemediation.text = rowData.remediation
        burpPanel.panelRequest.setMessage(rowData.getRequest(), True)
        burpPanel.panelResponse.setMessage(rowData.getResponse(), False)
{{< /codecaption >}}

After every mouse click, we want to display everything in the bottom panel. Note
the difference in assignments to `panelRequest` and `panelResponse`. We are
storing the requests in base64 inside the Issue object so we must use the helper
methods (that handle the encoding/decoding) to get them. 

Double-click creates a new issue and adds it to the table.

{{< codecaption title="07-ObjectTableModel/IssueTable.py mouseClicked" lang="python" >}}
    if event.getClickCount() == 2:
        # open the dialog to edit
        # print "double-click. clicked index:", self.getClickedIndex(event)
        # print "double-click"
        tbl = event.getSource()
        mdl = tbl.getModel()
        assert isinstance(mdl, IssueTableModel)
        curRow = mdl.getRowCount()
        newRow = str(curRow+1)
        issue = Issue(index=newRow, name="Issue"+newRow,
                        severity="Severity"+newRow, host="Host"+newRow,
                        path="Path"+newRow, description="Description"+newRow,
                        remediation="Remediation"+newRow,
                        request="Request"+newRow, response="Response"+newRow)
        tbl.addRow(issue)
{{< /codecaption >}}

Looks respectable:

{{< imgcap title="Custom IssueTableModel" src="11-object-table.gif" >}}

# What Did We Learn Here Today
We learned a lot of stuff and I think this is a good place to stop. In the next
session, I will start by adding the edit functionality to the table. We will
modify the double-click to create a new frame to edit the clicked issue and a
new button to add new issues.

<!-- Links -->
[paul-ritchie-twitter]: https://twitter.com/cornerpirate
[paul-ritchie-github]: https://github.com/cornerpirate
[defaulttablemodel-doc]: https://docs.oracle.com/javase/8/docs/api/javax/swing/table/DefaultTableModel.html
[jtable-doc]: https://docs.oracle.com/javase/8/docs/api/javax/swing/JTable.html
[tablemodel-doc]: https://docs.oracle.com/javase/8/docs/api/javax/swing/table/TableModel.html
[jscrollpane-doc]: https://docs.oracle.com/javase/8/docs/api/javax/swing/JScrollPane.html
[jframe-doc]: https://docs.oracle.com/javase/8/docs/api/javax/swing/JFrame.html
[mouselistener-doc]: https://docs.oracle.com/javase/8/docs/api/java/awt/event/MouseListener.html
[vector-doc]: https://docs.oracle.com/javase/8/docs/api/java/util/Vector.html
[mouselistener-tutorial]: https://docs.oracle.com/javase/tutorial/uiswing/events/mouselistener.html
[convertrowindextomodel-doc]: https://docs.oracle.com/javase/8/docs/api/javax/swing/JTable.html#convertRowIndexToModel-int-
[abstracttablemodel-doc]: https://docs.oracle.com/javase/8/docs/api/javax/swing/table/AbstractTableModel.html
[imessageeditor-doc]: https://portswigger.net/burp/extender/api/burp/IMessageEditor.html
[createmessageeditor-doc]: https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html#createMessageEditor(burp.IMessageEditorController,%20boolean)
[jtextarea-doc]: https://docs.oracle.com/javase/8/docs/api/javax/swing/JTextArea.html
[customlogger-l45]: https://github.com/PortSwigger/custom-logger/blob/master/python/CustomLogger.py#L45
