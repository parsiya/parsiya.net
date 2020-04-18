---
title: "The Encrypted Logz - Some Simple Reverse Engineering"
date: 2020-04-17T17:30:22-07:00
draft: false
toc: true
comments: true
twitterImage: 19-generate.png
categories:
- reverse engineering
- crypto
---

I was looking at an application (not related to my day job) and I decided to
reverse engineer how it creates logs. I cannot name the app (yet) but hopefully,
this is useful.

<!--more-->

# What does it Look Like?
I executed the app and saw events in procmon creating logs in.

* `C:\Users\Parsia\AppData\Local\[brand]\[app-suite-name]\Logs`.

Opened a log file and it looked encrypted. Why encrypted? Look at all the jumble
of data with high entropy. These kinds of files usually either compressed files
or encrypted data.

How do we know it's encrypted? Compressed files usually have large headers. So
the start of the file does not have high entropy. This one has a tiny header and
we can see the word `LOGZ`.

{{< imgcap title="Encrypted log" src="01-encrypted-log.png" >}}

How do we figure out who writes to it? Procmon.

1. Run procmon.
2. Set filter.`Path` - `begins with` - `path/to/log/directory`.
3. Run the app.
4. See who edits the log.

{{< imgcap title="procmon filter" src="02-procmon-filter.png" >}}

We can see the file access events. It's the main `app.exe`.

{{< imgcap title="Log write events in procmon" src="03-procmon-events.png" >}}

Double-click on an event and select the `Stack` tab. It's using `Qt5Core.dll 5.9.2.0`.

{{< imgcap title="Log write stack" src="04-event-stack.png" >}}

# Symbols
Having symbols is nice. Qt5 is an open source project and we can download its
symbols.

## Qt5 Symbols
You can find the symbols for version `5.9.2.0` at:

* https://download.qt.io/archive/qt/5.9/5.9.2/

Because we are running an x86 app (32-bit) and it's a desktop version (not UWP),
we are looking for this file
`qt-opensource-windows-x86-pdb-files-desktop-5.9.2.zip` on the page above.

Inside the archive, there are a bunch of Windows 8.1 and Windows 10 files. We do
not need the Windows 8.1 files.

Windows 10 files come in four flavors:

* x86 vs. x64: We will choose 32-bit.
* MSVC 2015 vs. MSVC 2017: How do we figure this out?

{{< imgcap title="Qt PDBs" src="05-qt-pdb.png" >}}

Looking inside the app directory we can see all the Qt5 DLLs.

{{< imgcap title="Qt DLLs" src="06-qt-dlls.png" >}}

We already know it's a 32-bit DLL. Scroll back up and look at the `Address`
column in the procmon event stack image. It has only 4 bytes or 32-bits.

To detect the MSVC version we must discover the linker info.

[Detect It Easy](https://github.com/horsicq/Detect-It-Easy) does the job and
tells us it's linker version 14 or MSVC 2015 [^1].

[^1]: PEID also detects the linker version but its signatures are out of date to
figure out the name of the compiler.

{{< imgcap title="'Detect It Easy' results" src="07-detect-it-ez.png" >}}

We can discard the unneeded symbols. Let's put the correct PDBs inside
`C:\Symbols\@MySymbols`. The symbol lookup is alphabetical so you put all of
your symbols further up in the chain to make it faster (is this still a thing?).

### Ghidra PDB Issues
As an example, I dropped `Qt5Core.dll` in Ghidra and loaded the PDB via
`File (menu) > Load PDB File`. I got a bunch of errors

```
PDB> Unable to create stack variable buffer at offset -4 in ?createNativeFile@QTemporaryFile@@SAPAV1@AAVQFile@@@Z
PDB> Unable to create stack variable dt at offset -4 in ?toDateTime@QLocale@@QBE?AVQDateTime@@ABVQString@@0@Z
PDB> Unable to create stack variable indices at offset -4 in ?replace@QByteArray@@QAEAAV1@PBDH0H@Z
PDB> Unable to create stack variable buf at offset -4 in ?processNameByPid@QLockFilePrivate@@SA?AVQString@@_J@Z
PDB> Unable to create stack variable tzi at offset -4 in getRegistryTzi
```

Unfortunately, Ghidra's PDB import is not that great. To troubleshoot we can
also, generate the XML file via the `pdb.exe` command.

* `ghidra_9.1.2_PUBLIC\Ghidra\Features\PDB\os\win64\pdb.exe c:\path\to\pdb -fulloutput > somefile.pdb.xml`

This resulting xml can be imported in Ghidra instead of the PDB file. This is not going
to help us here but it can show us where the issue is. It's also useful for
[creating for Ghidra usage in non-Windows operating systems][ghidra-linux].

[ghidra-linux]: https://dannyquist.github.io/windows-symbols-ghidra/

The tool creates a 100MB file for `Qt5Core.dll`. Navigating to the file we can
see that it's cut-off somewhere.

{{< imgcap title="PDB xml for Qt5Core.dll" src="08-symbol-xml.png" >}}

There were also issues with the `2000` character limit for symbols. This is a
[known problem][2000comment].

[2000comment]: https://github.com/NationalSecurityAgency/ghidra/issues/94#issuecomment-512855100

## Importing from IDA to Ghidra
I also tried importing the PDB in IDA Freeware 7.0 and it worked perfectly.

{{< imgcap title="PDB loaded in IDA Freeware 7.0" src="09-ida-freeware.png" >}}

In these situations, one option is to import the symbols in IDA and then use the
Ghidra plugin to export the project. You can import it in Ghidra. This needs
IDAPython which is not available in IDA Freeware.

At this point, I had enough to get started on decrypting the logs.

# Analysis
Now we can get into the main executable. Fortunately, (for me) the installer
includes the PDB files for the main executables. This is great news.

{{< imgcap title="PDBs included with the installer" src="22-pdbs.png" >}}

Dropping the main `exe` into Ghidra and the PDB resulted in a lot of errors. Similar
to the errors above but it does not stop us. Then we can do `Auto Analysis` to
continue. The result is not as great as IDA but it's great for paying 0 dollars.

How do we proceed from here? We can:

1. Randomly search for things.
2. Trace the writes to log files.

## Just Guess Until You Find Something
When you encrypt a file, you have to be able to decrypt it too. Having symbols
means we can search for `decrypt` (or `encrypt`). Decrypt is probably easier to
trace because the log files are encrypted as the messages come but decryption
usually happens in one go so everything might be in one place.

I searched for `Decrypt` and found the function that decrypts a log file named,
well, `DecryptLogFile`.

{{< imgcap title="DecryptLogFile function" src="21-decryptlogfile.png" >}}


`DecryptLogFile` appears to be a wrapper for `FUN_008f6100`.

```cpp
string __cdecl DecryptLogFile(path *param_1, path *param_2)
{
  FUN_008f6100(param_1,param_2);
  return param_1;
}
```

The parameters are of type `boost::filesystem::path`. We can guess one of them
is the encrypted log file and the other is where the decrypted results will be
stored. Let's look at the assembly for `FUN_008f6100`. I have cleaned up the
decompiled code.

Notice the difference between the number of parameters above and in the
function? I am not sure where `param_1` comes from? Maybe it's a field and
`FUN_008f6100` is actually a method (i.e., `thiscall`)?

```cpp
void FUN_008f6100(std::string *param_1, path inputFile, path outputFile)
{
    QIODevice::QIODevice qioDevice [8];
    inputFileString = QString::fromStdWString((std::basic_string *)&inputFile);
    QFile::QFile(qioDevice, inputFileString));
    
    isInputFileOpened = open(qioDevice,(QFlags<enum_QIODevice::OpenModeFlag>)0x1);
    if (isInputFileOpened == false) {
       cout << "Can\'t open input file";
    }
    else {
        inputSize = size(qioDevice);
        if ( inputSize > -1) {
            inputDataStream = QDataStream::QDataStream(qioDevice);
            fourCharString = "    ";
            fourCharStringPtr = *fourCharString;
            QDataStream::readRawData(inputDataStream, fourCharStringPtr, 4);
            if (fourCharStringPtr == c_header) // c_header = LOGZ {
                // Read four more bytes
                versionString = QDataStream(inputFileStream, 4);
                if (versionString == 0x2010ab01) {
                    outputFileString = QString::fromStdWString((std::basic_string *)&outputFile);
                    outputFile = QFile::QFile(outputFileString));
                    isOutputFileOpened = QFile::open(outputFileStream,(QFlags<enum_QIODevice::OpenModeFlag>)0xa);
                    if (isOutputFileOpened == false) {
                        cout << "Can\'t open output file";
                    } else {
                        // This is where decryption happens.
                        FUN_008f6bd0(param_1, inputDataStream, outputFileStream);
                    }
                else {
                } else {
                    cout << "Bad version";
                }
            } else {
                cout << "Bad header";
            }
    return;
}
```

This function does some sanity checks.

1. Checks if the input file exists and can be opened.
2. Reads the first four bytes and compares them with `LOGZ`. If not prints `Bad Header`.
3. Reads the second four bytes and compares them with `0x2010ab01`. If not prints `Bad Version`.
4. Creates the output file.

We have already seen the header and version bytes in the encrypted log file
above. They appear at the start of every encrypted log file, too.

Our next destination is `FUN_008f6bd0(param_1, inputDataStream, outputFileStream)`
where the main decryption happens.

```cpp
void FUN_008f6bd0(std::string param_1, QDataStream::QDataStream inputData, QDataStream::QDataStream outputData)
{
    // Initialize the PRNG.
    mersenne_twister_engine<unsigned_int> mtPRNG [2500];

    // See it with the default seed (0x1571). This is what the constructor does.
    seed(mtPRNG, &default_seed);
    // Removed
    appSeed = 0x25082011;
    // Seed the PRNG with the correct seed.
    seed(mtPRNG,&appSeed);
    // Get a buffer of 20000 bytes.
    // Removed code creates an output buffer named outputBuffer. 
    ByteArray((ByteArray *)&bufferByteArray20000,0x20000,'\0',0);
    while( true ) {
        // Try and read 20000 bytes.
        numberOfBytesRead = *(int *)(bufferByteArray20000 + 8);
        // Get a wrapper with the input buffer
        inputBuffer = (char **)Get((DataWrap *)&bufferByteArray20000);
        // Read 20000 bytes.
        numberOfBytesRead =
                QDataStream::ReadRawData(inputData,*inputBuffer,numberOfBytesRead);
        // Pass them to `FUN_008f6370`.
        FUN_008f6370(inputBuffer, outputBuffer, numberOfBytesRead);
        if (numberOfBytesRead < 1) break;
    }
    // removed

```

`mersenne_twister_engine<unsigned_int, ...` is a PRNG.

* http://www.cplusplus.com/reference/random/mt19937/

It's not cryptographically secure but we are encrypting some random local log
files. It's seeded twice. First one is the `default_seed` followed by
`0x25082011`. The default seed is `0x1571` and the constructor does it
automatically.

```cpp
#include <random>
// Constructor automatically seeds it with 0x1571 and then 0x25082011.
mt19937 generator(0x25082011);
```

A 20000 byte buffer is read from input and passed to `FUN_008f6370`.
This function is a wrapper for `FUN_008f6370`:

```cpp
undefined4 FUN_008f6370(ByteArray* inputBuffer, byte* outputBuffer, uint numberOfBytesRead)
{
  FUN_008f5d90(inputBuffer, outputBuffer, numberOfBytesRead);
  return param_1;
}
```

`FUN_008f5d90` is the most interesting function. We see our twister again.

{{< imgcap title="Mersenne Twister Engine" src="17-local80.png" >}}

Further down we see references to
`..\\..\\..\\src\\RcLogV2\\Output\\LogEncFileOutputV2.cpp` and some classes that
look interesting thanks to `assert` statements.

{{< imgcap title="Assert statements" src="18-assert.png" >}}

If we search for `local_80` in the decompiled code, we see this interesting
function `boost::random::mersenne_twister_engine::generate_uniform_int`.

{{< imgcap title="generate_uniform_int" src="19-generate.png" >}}

Surprisingly, I could not find it in the docs but managed to find it in the
`hpp` files.

```cpp
emplate<class Engine, class T>
T generate_uniform_int(
    Engine& eng, T min_value, T max_value,
    boost::mpl::true_ /** is_integral<Engine::result_type> */)
{
```

It generates `uint32` values (because we are using the int32 version of the
Mersenne Twister) between min and max values. The function call in assembly is:

```asm

008f5fb3 8b 5d ec        MOV        EBX,dword ptr [EBP + local_84] ; param_1
        LAB_008f5fb6                                    XREF[1]:     008f5fe3(j)  
008f5fb6 8b 45 f0        MOV        EAX,dword ptr [EBP + local_80] ; mtPRNG
008f5fb9 53              PUSH       EBX
008f5fba ff b0 c8        PUSH       dword ptr [EAX + 0x9c8] ; *mtPRNG+2054
            09 00 00
008f5fc0 ff b0 c4        PUSH       dword ptr [EAX + 0x9c4] ; *mtPRNG+2058
            09 00 00
008f5fc6 50              PUSH       EAX ; mtPRNG
008f5fc7 e8 24 f5        CALL       boost::random::detail::generate_uniform_int
            ff ff
```

Which is `generate_uniform_int(mtPRNG, *mtPRNG+2054, *mtPRNG+2058, param_1);`.
After the function call we see:

```asm
008f5fcc 8b 55 78        MOV        EDX,dword ptr [EBP + param_2]
008f5fcf 8d 7f 01        LEA        EDI,[EDI + 0x1]
008f5fd2 83 c4 10        ADD        ESP,0x10
008f5fd5 8a 0a           MOV        CL,byte ptr [EDX]
008f5fd7 42              INC        EDX
008f5fd8 32 c8           XOR        CL,AL
008f5fda 89 55 78        MOV        dword ptr [EBP + param_2],EDX
008f5fdd 88 4f ff        MOV        byte ptr [EDI + -0x1],CL
008f5fe0 83 ee 01        SUB        ESI,0x1
008f5fe3 75 d1           JNZ        LAB_008f5fb6 ; go back up to call `generate_uniform_int`
```

This is a typical XOR. Counter is `esi` (note `SUB ESI,0x1` in the end). When
esi is not zero, `JNZ` sends the execution back up to the function call to get
another uint32. When esi reaches zero, the jump is not taken and we finish the loop.
By tracing the app we see that `edi` is actually `param_3`. `param_2` is
probably the plaintext, `param_3` is the size of ciphertext/plaintext.

```cpp
for (int i=0; i<sizeOfPlaintext; i++) {
    // Get a uint32 from the mt19937 generator.
    key = generate_uniform_int(mtPRNG, *mtPRNG+2054, *mtPRNG+2058, param_1);
    ciphertext[i] = plaintext[i] XOR (AL)key;
    // Decompiled code here is `ciphertext[i] = plaintext[i] XOR (byte)key;` which is wrong
}
```

### The Encryption Algorithm
The XOR is tricky here. We are XOR-ing `AL` with the plaintext. The decompiled
code in Ghidra is `ciphertext[i] = plaintext[i] XOR (byte)key;` which is wrong.

If we go by decompiled code and cast the `uint32` to `byte` we get the least
significant byte. However, when numbers are stored in a register like eax `AL`
will point to the most significant byte so `(key & 0xFF000000) >> 24` does the
job.

```cpp
void FUN_008f5d90(ByteArray *param_1,byte *param_2,uint param_3)
    mersenne_twister_engine<unsigned_int> *mtPRNG;
    // removed
    for (int i=0; i<sizeOfPlaintext; i++) {
        // Get a uint32 from the mt19937 generator.
        key = generate_uniform_int(mtPRNG, *mtPRNG+2054, *mtPRNG+2058, param_1);
        ciphertext[i] = plaintext[i] XOR ((num & 0xFF000000) >> 24);
    }
    return ciphertext;
}
```

### Min and Max Values
The `generate_uniform_int` function call has two parameters `min` and `max`.
These point to the minimum and maximum values for the generated numbers. For
`std::mersenne_twister_engine` these are `0` and `2^32 - 1` (for int32 version
of the function).

These cannot be set for `std::mersenne_twister_engine` according to the docs. In
the docs for [std::mersenne_twister_engine::min][min-docs] we read:

> Minimum value: Returns the minimum value potentially returned by member
> operator(), which for mersenne_twister_engine is always zero.

Similar for and [max][max-docs]:

> Returns the maximum value potentially returned by member operator(), which for
> mersenne_twister_engine is 2^w-1 (where w is the word size specified as the
> second class template parameter).

[min-docs]: http://www.cplusplus.com/reference/random/mersenne_twister_engine/min/
[max-docs]: http://www.cplusplus.com/reference/random/mersenne_twister_engine/max/

It seems like it's pointing to object fields (?) or methods (?). That means we
do not need to define min and max values in our code.

----------

## The Bad Route
I initially started writing this route for this write-up. I was ashamed that I
had found the original solution by searching for a function name. Then I
realized why not?

This is the long route and not fun BUT I discovered some valuable info here.We
will see how debug mode is detected and how console access is enabled.

For the long route, I started with the event I saw in procmon.

`Qt5Core.dll > QFSFileEngine::write + 0x29`. Searching for it in Ghidra or in
the exports for `Qt5Core.dll` returns nothing. Searching online we can find
references to it in the v4.8 docs.

* https://doc.qt.io/archives/qt-4.8/qfsfileengine.html

Note: I do not know why it's not in the symbols. So I decided to do some dynamic
analysis:

1. Run the app via x64dbg.
2. Go to the address for the procmon event.
    1. The new address in that run was `0x6f87b6b9`.
3. Go a bit up to see the call to `?write@QFSFileEngine@@UAE_JPBD_J@Z`.
4. Put a breakpoint and rerun the app.
5. Go to the `Call Stack` tab in x64dbg after the breakpoint is reached.

{{< imgcap title="Call to write in x64dbg" src="10-x64dbg-trace.png" >}}

{{< imgcap title="Call stack in x64dbg" src="11-call-stack.png" >}}

Now we can search for `LogFileOutputBase` in Ghidra.

{{< imgcap title="LogFileOutputBase" src="12-logfileoutputbase.png" >}}

This is a method that writes the data passed in the parameter to the log file. I
did not see any encryption in the source code. Meaning the parent class might
handle it.

Looking at the incoming references (bottom left in Ghidra), we can see:

```
Incoming References - LogFileOutputBase
    FUN_008f5720 <-- This references LogFileOutputBase
        CreateLogEncFileOutput <-- FUN_008f5720 calls this
    FUN_008f76c0  <-- This references LogFileOutputBase
        CreateLogFileOutput <-- FUN_008f5720 calls this
```

The parent class is created by using one of the two methods above. Just by
looking at the names we can see that one creates an encrypted log file and the
other does not.

Let's go to `CreateLogEncFileOutput`. It has one parameter (string) and returns
a `FileResult` object. I could guess that it creates a log file and returns a
handle to it. Then we can write to the handle and not worry about the underlying
encryption.

```cpp
FileResult __cdecl CreateLogEncFileOutput(char *param_1)
{
    // Removed
    local_30 = operator_new(0x9fc); // local_30 = new int(0x9fc);
    this = (LogFileOutputBase *)FUN_008f5720(); // What is this?
    FileName(this);
    shared_ptr<class_RcLogV2::IOutputDevice><class_`anonymous_namespace'::LogEncFileOutput>
            ((shared_ptr<class_RcLogV2::IOutputDevice> *)&stack0xffffffb0,(LogEncFileOutput *)this);
    FVar1 = FileResult((FileResult *)param_1,in_stack_ffffffb0,in_stack_ffffffb4);
    // Removed
    return FVar1;
}
```

It looks like `FUN_008f5720` creates and returns the filehandle. We see some
interesting stuff in it.

{{< imgcap title="FUN_008f5720" src="13-mt19937.png" >}}

We have already seen `mersenne_twister_engine<unsigned_int, ...` so I will skip
explaining it this time. An educated guess tells us that the PRNG is used to
create a key to encrypt the file. But we do not know how, yet. A pointer to this
object is stored in `local_60`.

After checking that it can create or open the file, we get to this code. The
decompiled code in Ghidra gives us the general idea of what's happening but is
not correct.

```asm
        LAB_008f5886                                    XREF[1]:     008f5821(j)  
008f5886 57              PUSH       EDI
008f5887 8d 4e 14        LEA        ECX,[ESI + 0x14]
008f588a ff 15 1c        CALL       dword ptr [->QT5CORE.DLL::?setDevice@QDataStre
            c2 f1 01
```

This calls [void QDataStream::setDevice(QIODevice *d)][setdevice] which sets the
I/O device to most likely the log file we just created. This means we can now
use the `QDataStream` object to write to it.

[setdevice]: https://doc.qt.io/qt-5/qdatastream.html#setDevice

```asm
008f5890 6a 04           PUSH       0x4
008f5892 ff 35 e0        PUSH       dword ptr [->s_LOGZ]            = 030fa850
         3a 87 03                                                   = "LOGZ"
008f5898 8d 4e 14        LEA        ECX,[ESI + 0x14]
008f589b ff 15 7c        CALL       dword ptr [->QT5CORE.DLL::?writeRawData@QDataS
            c0 f1 01
```

Calls [int QDataStream::writeRawData("LOGZ", 4)][writeraw]. This writes `LOGZ`
to the start of the file. This is exactly what we saw above.

[writeraw]: https://doc.qt.io/qt-5/qdatastream.html#writeRawData

```asm
008f58a1 68 01 ab        PUSH       0x2010ab01
            10 20
008f58a6 8d 4e 14        LEA        ECX,[ESI + 0x14]
008f58a9 ff 15 78        CALL       dword ptr [->QT5CORE.DLL::??6QDataStream@@QAEA
            c0 f1 01
```

This call writes `0x2010ab01` to the stream. This also appears in the log file
but because it was not in printable hex I did not notice it.

IDA actually figures out what method it is.

```asm
call    ds:__imp_??6QDataStream@@QAEAAV0@I@Z ; QDataStream::operator<<(uint)
```

[QDataStream << 0x2010ab01][operator] writes a the byte to the stream.

[operator]: https://doc.qt.io/qt-5/qdatastream.html#operator-lt-lt

Next we have:

```asm
008f58af 8b 07           MOV        EAX,dword ptr [EDI]
008f58b1 8b cf           MOV        ECX,EDI

008f58b3 8b 40 38        MOV        EAX,dword ptr [EAX + 0x38]
008f58b6 ff d0           CALL       EAX
008f58b8 83 f8 08        CMP        EAX,0x8
008f58bb 0f 85 bb        JNZ        LAB_008f597c
            00 00 00
```

Honestly, I cannot figure out what it exactly does but we have written 8 bytes
and there is a compare with 8. It's either calling a method or accessing a
field. The most likely scenario is that it checks if it has written 8 bytes to
the stream.

```cpp
// Create the datastream.
?setDevice@QDataStream@@QAEXPAVQIODevice@@@Z(param_1 + 5,(QIODevice *)this);
// Write the header
?writeRawData@QDataStream@@QAEHPBDH@Z(param_1 + 5,c_header,4);
// Write `0x2010ab01`. 
??6QDataStream@@QAEAAV0@I@Z(param_1 + 5,0x2010ab01);
// Get the number of bytes written
lVar5 = (**(code **)(*this + 0x38))();
// Compare it with 8.
if (lVar5 != 8) {
    local_64 = (undefined4 *)0x0;
    local_8._0_1_ = 10;
    // If it was wrong, return an error message.
    local_5c = string("Bad header size");
```

The rest of the method is not interesting. So we have figured out the PRNG and
the header. But we do not know how the encryption happens.

Returning into `CreateLogEncFileOutput` we see that a `FileResult` is created
and returned.

```cpp
FileResult __cdecl CreateLogEncFileOutput(char *param_1)
{
    // Removed
    local_30 = operator_new(0x9fc); // local_30 = new int(0x9fc);
    local_8 = 0;
    this = (LogFileOutputBase *)FUN_008f5720();
    // We are now here.
    FileName(this);
    // Removed
    FVar1 = FileResult(this);
    // Removed
    return FVar1;
}
```

Now we need to follow the returned `FileResult` and see how data is written to
it.

Select the `CreateLogEncFileOutput` function, right-click and `Find references
to` we get to `FUN_013697c0`. I have cleaned up the code and removed the
unnecessary parts.

```cpp
void __thiscall FUN_013697c0(void *param_1, undefined4 *param_1_00,
    LogDirections *param_2, undefined4 param_3, int param_4)
{
    // This checks if we are running in debug mode.
    isDebugMode = ?ModanoDebugMode@ModanoUtils@@YA_NXZ(param_1);
    if (isDebugMode) {
        // If running in debug mode create plaintext log.
        logFile = CreateLogFileOutput((char* local_28);
    }
    else {
        // If not debug mode create encrypted log.
        logFile = CreateLogEncFileOutput(char* local_68);
    }

    // removed
    if (isDebugMode) {
        ~FileResult(local_28);
    }
    // removed
    if (!isDebugMode) {
        ~FileResult(local_68);
    }

    // File permissions?
    param_1_00[4] = 0;
    param_1_00[5] = 0;
    param_1_00[5] = 7;
    param_1_00[4] = 0;
    puVar5 = param_1_00;
    if (7 < (uint)param_1_00[5]) {
        puVar5 = (undefined4 *)*param_1_00;
    }
    // removed
    return;
}
```

Seems like it creates a log file based on whether we have debug mode enabled or
not. Let's rename it to `CreateLogFile`. There is not much in the rest of the
function. As a detour let's check the debug mode.

### Debug mode
Click on the `ModanoDebugMode@ModanoUtils` function.

```cpp
bool __thiscall ?ModanoDebugMode@ModanoUtils@@YA_NXZ(void *this)
{
  if ((g_debugEnabled == (optional<bool>)0x0) &&
     (DAT_03b34bfd = (bool)FUN_0132a220(), g_debugEnabled == (optional<bool>)0x0)) {
    g_debugEnabled = (optional<bool>)0x1;
    return DAT_03b34bfd;
  }
  return DAT_03b34bfd;
}
```

It checks if the global variable `g_debugEnabled` is not zero. If it's zero, it
returns with what we can assume is `false`.

If it's not zero, it calls `FUN_0132a22`. `AL` (the return value of this
function is in `EAX` and `AL` is the first byte) is stored in `DAT_03b34bfd` and
returned. It also sets `g_debugEnabled` to `1`. Otherwise, `DAT_03b34bfd` is
returned without being set.

So `FUN_0132a22` sets debug mode. Let's check it. Cleaned up decompiled code
tells us what it does:

```cpp
void FUN_0132a220(void)
{
    // Get the name of the executable.
    executableName = Utils::ExeName::Instance();
    // Get the executable directory.
    executableDirectory = Utils::ExeName::GetExeDirAsStr(executableName);
    // debugFilePath = "path/to/executable/directory/debug"
    debugFilePath = concat(executableDirectory, "debug");
    // Return the file_status of debugFilePath
    fileStatus = boost::filesystem::detail::status(debugFilePath, system::error_code& ec);
    // If the status is not `status_error` (0) and is not `file_not_found` (1)
    if ((fileStatus[0] != 0) && (fileStatus[0] != 1)) {
        // Show the console window.
        ShowConsolWindow();
    }
    return;
}
```

`fileStatus` is of type [Boost::Filesystem::file_status][filestatus] and it can
contain values of enum [Boost::Filesystem::file_type][filetype].

```cpp
enum file_type
{
    status_error, file_not_found, regular_file, directory_file,
    symlink_file, block_file, character_file, fifo_file, socket_file,
    type_unknown
};
```

`0` and `1` are `status_error` and `file_not_found` respectively. The code
explicitly checks if the result is 0 or 1.

[filestatus]: https://www.boost.org/doc/libs/1_66_0/libs/filesystem/doc/reference.html#file_status
[filetype]: https://www.boost.org/doc/libs/1_66_0/libs/filesystem/doc/reference.html#file_type

In short, it checks **if there is a file named `debug` in the executable directory.**
Enables debug mode and shows the console window.

To figure out what the console window is. Click on `ShowConsolWindow`. It prints
the app output to the console. If you run the app from a command line and you have
debug mode enabled you will see messages printed to the console:

```cpp
void __cdecl ShowConsolWindow(void)
{
    Console *this;
    ulong uVar1;
    int iVar2;

    this = Win32::Console::Instance();
    if (*this == (Console)0x0) {
        uVar1 = Win32::ToolHelp::GetParentProcessId(0);
        iVar2 = Win32::Console::RedirectIOToConsole(uVar1);
        if (iVar2 == 0) {
            Win32::Console::Allocate(this);
            return;
        }
        Win32::Console::RedirectIOToConsole(this);
        *this = (Console)0x1;
    }
    return;
}
```

The debug mode is used in many places. Incoming references for the
`ModanoDebugMode@ModanoUtils` are:

{{< imgcap title="Functions that check for debug mode" src="14-debug-references.png" >}}

### Back to Hunting for Encryption
After our little side-quest, we are back here. We know `CreateLogEncFileOutput`
creates an encrypted log file and returns a `FileResult` handle. It's referenced
in `FUN_013697c0/CreateLogFile` which we saw it checked for debug mode and
returned a log file accordingly (plaintext vs. encrypted).

Now we need to figure out what happens to the `FileResult` and how it's handled.
Following `CreateLogFile` we can see it's called by `FUN_01369160` which is a
wrapper. We can rename it to `CreateLogFileWrapper`.

```cpp
void CreateLogFileWrapper(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)
{
    // Removed
    return CreateLogFile(param_1,param_2,param_3,param_4);
}
```

This is in turn called by `FUN_01368870`.

{{< imgcap title="Call stack" src="15-wrapper-call.png" >}}

### Rage Quit
I went down the rabbit hole and wasted a few hours trying to trace
the calls with nothing to show. The only nice thing was finding how to
enable the debug mode.

Then I realized there is an easier way of doing what I have been trying to do.
We know we are using a `mersenne_twister_engine` and it's a somewhat unique
string. Why not search for it in the binary?

I selected an instance that I saw above then did `Right-click > References > find uses of`.

The result has 135 locations but most of them are probably internal. We should
start with the ones with `FUN_00` labels because they are the most "fun"
(dadjoke.png).

{{< imgcap title="Mersenne uses" src="16-uses-of-mersenne.png" >}}

And we find it in `FUN_008f5d90`. `local_80` is the `mt19937` variable. We have
seen this function before above. But this time it's in the context of decrypting
the logs. XOR is transitive so encryption and decryption do the same.

# DecryptLog Code
Now we can write code. I could not find implementations of mt19937 32-bit in Go.
Python supposedly uses the same engine to generate `random` output but I did not
get the result I wanted either. So I had to write C++ code.

Not having written C++ I spent a lot of time creating useless functions to warm
up and get used to vectors. I have used the `std::byte` type in the code so you
need to use the instructions in the code to use C++17.

The final code is at:

* https://github.com/parsiya/Parsia-Code/tree/master/decrypt-log

{{< imgcap title="Decrypted log" src="20-decrypted-log.png" >}}

# What Did We Learn Here Today?

1. Installers might include symbols with the main executable.
2. Symbols are fun.
3. Ghidra's PDB processing has some issues.
4. The Mersenne Twister Engine is part of the C++ standard library.
5. Debug mode can be set with some silly methods (e.g., having a file named
   `debug`).
6. Ghidra's decompiler is sometimes misleading so be sure to check the
   disassembly and not trust it blindly.
