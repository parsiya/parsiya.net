---
title: "Cheating at Moonlighter - Part 3 - Enabling Debug HUD"
date: 2019-01-29T22:52:01-05:00
draft: false
toc: true
comments: true
twitterImage: 15-debughud.jpg
categories:
- Game Hacking
tags:
- Moonlighter
- dnSpy
---

In this part, I am going to use dnSpy to enable the Debug HUD. We will analyze how it's enabled and how it can be accessed.

* [Cheating at Moonlighter - Part 1 - Save File]({{< relref "/post/2019-01-23-moonlighter-1/index.markdown#anchor" >}} "Cheating at Moonlighter - Part 1 - Save File")
* [Cheating at Moonlighter - Part 2 - Changing Game Logic with dnSpy]({{< relref "/post/2019-01-27-moonlighter-2/index.markdown" >}} "Cheating at Moonlighter - Part 2 - Changing Game Logic with dnSpy")

<!--more-->

Looking at `StatsModificator.intelligence`, I went down this rabbit hole to see how items are created.

{{< imgcap title="Item creation call analysis" src="00-item-create.png" >}}

And I saw these two methods in a class named `HUDDebug`. They have curious names `GiveItemToWill` and `GiveWeaponToWill`. If my guess is correct, there's a debug UI somewhere in the game that allows spawning items.

{{< imgcap title="HUDDebug Class" src="01-huddebug.png" >}}

It has a `Start()` method, we can analyze it to see what calls it.

Seems like nothing calls it, same with `Awake()`.

{{< imgcap title="HUDDebug analysis" src="02-analyze-huddebug.png" >}}

These are unity methods. According to this video https://unity3d.com/learn/tutorials/topics/scripting/awake-and-start:

1. `Awake()`: Called first even if the script is not enabled. Used for initialization.
2. `Start()`: Called only once after awake and before update if the script is enabled.
3. `Update()`: Called after the script is enabled and can be called multiple times.

These are called by the engine, so the `Analyze` tab will not have the chain.

# Enabling Debug Mode
Inside `Update()` we can see:

{{< imgcap title="HUDDebug.Update()" src="03-update.png" >}}

Pay attention to line 76. There's an `if` condition that enables everything. We can analyze `IsDebugEnabled`:

{{< imgcap title="IsDebugEnabled analysis" src="04-debug-enabled.png" >}}

Woot. It seems like we found it. Now we need to modify this to only return `true`.

{{< imgcap title="IL instructions for get_IsDebugEnabled" src="05-debug-il.png" >}}

To return true, we need to return 1. We can delete lines 0 to 6 and only keep lines 7 and 8:

```
 7: ldc.i4.1    // push 1 to the stack
 8: ret         // return
```

Highlight lines 0 to 6 and press delete (or use the context menu) to remove them. Press `Ok` to get the modified C# code.

{{< imgcap title="Modified get_IsDebugEnabled" src="06-true.png" >}}

This enables debug mode for every run. But what else is out there?

## Debug Shortcuts
Let's go back to the analysis results for `GameManager.IsDebugEnabled`

{{< imgcap title="IsDebugEnabled analysis" src="07-debug-analyze.png" >}}

We have already looked at `HUDDebug.Update`, now we look at the other two.

`HeroMerchant.Update()` has some shortcuts.

{{< imgcap title="HeroMerchant.Update()" src="08-heromerchant-update.png" >}}

### KeyCodes
[Input.GetKeyDown](https://docs.unity3d.com/ScriptReference/Input.GetKeyDown.html) detects when a key is pressed and released. The parameter to the method is an enum of type [KeyCode](https://docs.unity3d.com/ScriptReference/KeyCode.html) or a string. It took me a while to find out the associated numbers.

I found it in the decompiled code at:

* https://github.com/jamesjlinden/unity-decompiled/blob/master/UnityEngine/UnityEngine/KeyCode.cs

[Here's a local copy](KeyCode.cs), in case the repository is taken down.

It's based on ASCII-Hex decimal values with extra keys (e.g. gamepad) in the end.

Now we can decipher some debug shortcuts:

{{< imgcap title="Potion Shortcut" src="09-potion-shortcut.png" >}}

* `104`: `H`
* `304`: `LeftShift`

Note we can also change the item granted with anything we want.

``` cs
if (Input.GetKeyDown(98) && Input.GetKey(304))
{
    this.TeleportToFloorEnd();
}
```

We can teleport to the last room of any dungeon floor:

* `98`: `B`
* `304`: `LeftShift`

And so on.

### Controller Shortcuts
`HeroMerchantController.Update()` defines controller shortcuts.

{{< imgcap title="Controller shortcuts" src="10-controller-shortcut.png" >}}

### Save/Reset Shortcuts
There are a couple of more shortcuts inside `HUDDebug.Update()`:

{{< imgcap title="Save/reset shortcuts" src="11-save-shortcut.png" >}}

* Save: `LeftShift` + `S`
* Reset: `LeftShift`+ `R`

## Enabling Debug HUD
We still need to enable the HUD. It must have a shortcut key. Searching the internet tells us it's `Tab`.

See this page about a CheatEngine trainer:

* http://fearlessrevolution.com/viewtopic.php?p=47682#p47682

How can we find it ourselves? Back inside `HUDDebug.Update()` we can see a block that enables and disables `consoleDebugPanel`:

{{< imgcap title="Enabling and disable consoleDebugPanel" src="12-enable-panel.png" >}}

Inside the `if` we can see that `GameManager.Instance.consoleDebug` is referenced. Let's analyze that.

{{< imgcap title="consoleDebug  analysis" src="13-analyze-consoledebug.png" >}}

Double-click on `GameManager.Update()`:

{{< imgcap title="GameManager.Update()" src="14-gamemanager-update.png" >}}

We can see it's triggered by holding the `ButtonRightStick` for a second (I think). A bit further up we can see the equivalent keyboard shortcut.

``` cs
if (Input.GetKeyDown(9))
```

It's the `Tab` key which confirms what we found online. We can press `Tab` in the game to enable debug HUD.

{{< imgcap title="Debug HUD" src="15-debughud.jpg" >}}

And it's quite extensive.

# Lessons Learned
We learned:

* How to use dnSpy's Analyze feature to track variables/methods/etc.
* How to enable debug mode.
* Shortcut keys for various things such as potions.
* Shortcut key to enable the debug HUD.

My next plan was to use Cheat Engine to make cheats and enable debug HUD. But it's already done. In the next part, I will write my thoughts about some questions that I was asked about such cheating. Maybe after that, I will return and do the Cheat Engine part but I will need to re-learn the tool again.