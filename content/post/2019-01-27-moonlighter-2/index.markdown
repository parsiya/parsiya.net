---
title: "Cheating at Moonlighter - Part 2 - Changing Game Logic with dnSpy"
date: 2019-01-27T20:47:30-05:00
draft: false
toc: true
comments: true
twitterImage: 21-very-strong.png
categories:
- Game Hacking
tags:
- Moonlighter
- dnSpy
---

In part 1 we messed a bit with Moonlighter but modifying the save file. In this part, we will modify game logic using dnSpy.

We will modify our damage, player stats and discover a hidden stat.

<!--more-->

# Why dnSpy?
Moonlighter is built with the Unity game engine (C#). Game logic is usually in `Assembly-CSharp.dll`. In my VM, it's at:

* `C:\Program Files (x86)\Steam\steamapps\common\Moonlighter\Moonlighter_Data\Managed\Assembly-CSharp.dll`

I was not successful in debugging the game with dnSpy. But the instructions are here:

* https://github.com/0xd4d/dnSpy/wiki/Debugging-Unity-Games

This is my first unity game so I might be doing something wrong or it does not work with Steam versions.

# Increasing Will's Damage
Game logic is inside `{}`:

{{< imgcap title="Moonlighter's classes" src="00-classes-dll.png" >}}

Going around the list, I saw the `Bow` class and clicked on it.

{{< imgcap title="The Bow class" src="01-bow-class.png" >}}

Inside, I searched for the string `damage` and I got lucky.

{{< imgcap title="Searching for \"Damage\" in the class" src="02-damage.png" >}}

## DealDamageToEnemy
`DealDamageToEnemy` sounds interesting. Let's double-click on it. We end up in the `Enemy` class.

{{< imgcap title="DealDamageToEnemy" src="03-deal-damage.png" >}}

We can analyze this a bit. `attackStrength` and enemy defense are used to calculate the damage using `CalcHitDamage`:

* `this.totalDamage = this.CalcHitDamage(this.hitStrength, this.otherDefense);`

Then the damage is applied:

* `this.enemyStats.CurrentHealth -= this.totalDamage;`

Note: It doesn't matter if the enemy is invincible (`invencible` in the code) or not, the damage is still applied.

## `CalcHitDamage`
Double-click on `CalcHitDamage`:

``` cs
// Token: 0x0600150F RID: 5391 RVA: 0x00082838 File Offset: 0x00080C38
public virtual float CalcHitDamage(float hitStrength, float targetDefense)
{
    float num = (float)Mathf.RoundToInt(hitStrength * (targetDefense / 100f));
    return Mathf.Clamp(hitStrength - num, 0f, float.PositiveInfinity);
}
```

This code calculates the target's resistance and deducts it from `hitStrength`.


## Increasing Will's Damage
We don't know the value of damage numbers and the hitpoints of enemies yet. Let's brainstorm a bit:

1. Return `float.PositiveInfinity`. This might result in an integer underflow. I do not know to be honest but we will definitely try.
2. Return `hitStrength + num` instead. This will definitely increase our damage but will it be enough to kill enemies in one hit?
3. Multiply the output by a constant.
4. Change the lower band of [Mathf.Clamp](https://docs.unity3d.com/ScriptReference/Mathf.Clamp.html) to a large number (e.g. 10000f).

### Returning float.PositiveInfinity
Let's try this one and see what happens.

Right-click on the `return` line and select `Edit IL Instructions...`.

{{< imgcap title="CalcHitDamage's IL instructions" src="04-calchitdamage-il.png" >}}

IL is a stack-based language. Values are pushed to the stack before functions or operators are called.

Look at lines 13 and 14. Line 13 calls `Math.Clamp` and the next line returns it. In order to return infinity, we need to add another instruction before the `return` and copy line 12 to it (pushes infinity to the stack).

1. Click on `12` to select that line.
2. `Ctrl+C` to copy
3. Click on `13` and `Ctrl+V` to paste.
4. Press `Ok`.

{{< imgcap title="Modified CalcHitDamage" src="05-modified-calchit.png" >}}

Save the module, overwrite the original DLL with the modified one and start the game.

{{< imgcap title="No damage" src="06-no-damage.gif" >}}

Our evil plan was foiled.

### Return hitStrength + num
Grab a fresh copy and edit IL instructions again. This time we need to change the `sub` instruction in line 10 to `add`. Click on `sub` and dnSpy shows a helpful drop-down menu of all valid instructions. Choose `add`.

{{< imgcap title="Changing sub to add" src="07-sub-to-add.png" >}}

{{< imgcap title="Sub changed to add" src="08-sub-to-add-result.png" >}}

This is better. We are one-shotting enemies. Our damage is a constant `436` with `King Sword` from part 1 regardless of enemy type.

{{< imgcap title="Doing constant damage" src="09-damage.gif" >}}

We have accomplished our goal of increasing Will's damage. But you can try the other methods or fiddle with the method in any way you want. Experiment!

# Modifying Will's Stats
Player stats are important. They are used to calculate damage. Remember `attackStrength` or `hitStrength` in the previous section? They should come from somewhere based on our weapon. Let's track them.

Right-click on `CalcHitDamage` and select `Analyze`. A new window opens up. It shows who calls the target method (`Used By` which is similar to x-ref in IDA) and what the target method calls and other information.

{{< imgcap title="Analyzing CalcHitDamage" src="10-analyze-calchit.png" >}}

Two functions look promising:

* `HeroMerchantProjectile.DealDamage(GameObject)`
* `Weapon.OnMainAttackHit(GameObject)`

## HeroMerchantProjectile.DealDamage
Let's start with `HeroMerchantProjectile.DealDamage`.

{{< imgcap title="HeroMerchantProjectile.DeadlDamage" src="11-deal-damage1.png" >}}

We can see that the `intelligence` stat is used to calculate bow damage.

On a side note, clicking on `Value` opens an object called `ObscuredFloat` in the `Stat` class. I vaguely remember reading about this obscured values in Unity on some Cheat Engine forum threads. It's something we might return and look at again when we are dealing with Cheat Engine. Apparently, they are hard to track in memory.

{{< imgcap title="ObscuredFloat" src="12-obscured.png" >}}

### The Case of the Missing Intelligence
There is no intelligence stat in the game. This is a picture from part 1 that show's Will's inventory. There's no intelligence stat. It shows `Vitality`, `Strength`, `Defence` and `Speed`. Is the empty green space supposed to be the intelligence?

{{< imgcap title="Will's stats - no intelligence here" src="13-inv-old.png" >}}

At first, I thought it's missing in the PC version. I looked at screenshots of the Nintendo Switch version and they looked the same.

Items do not grant intelligence either. This picture shows an item's stats in the blacksmith's UI.

{{< imgcap title="Item stats - no intellience here either" src="14-weapon-old.png" >}}

In dnSpy, right-click on `intelligence` and select `Analyze`.

{{< imgcap title="Intelligence analysis" src="15-intelligence-analyze.png" >}}

We can see it's set in `HeroInventoryPanel.UpdateLabels()`:

{{< imgcap title="HeroInventoryPanel.UpdateLabels" src="16-update-labels.png" >}}

It's updated along with other stats but does not appear in the UI. This is not good because it's an important stat.

## Adding Extra Stats
Look inside `EquipmentStats.AddToHeroMerchant(HeroMerchantStats)`.

{{< imgcap title="EquipmentStats.AddToHeroMerchant" src="17-add-to-hero-merchant.png" >}}

Stats are added to the base stats. We can modify each stat and add any amount. For example, to add `10000` to strength we need to modify line 57: `strength.Value += num2;`. Right-click line 57 and select `Edit IL Instructions ...`.

{{< imgcap title="Line 57 IL instructions" src="18-line-57-il.png" >}}

See those highlighted lines? Those are IL instructions for line 57 in the source code (coincidentally it also starts from line 57). dnSpy has helpfully highlighted them for us. We must add two instructions before the final `add` on line 61. One to load `10000f` and another to `add` it to the previous value.

{{< imgcap title="Line 57 modified" src="19-line-57-modified.png" >}}

And the result in decompiled C# is:

{{< imgcap title="Line 57 modified in C#" src="20-strength-modified.png" >}}

Now Will has `90436` strength:

{{< imgcap title="Strong Will" src="21-very-strong.png" >}}

Why did Will's strength increase by `90000`? My guess is that each equipped item calls `AddToHeroMerchant` individually. We have nine items (remember there were nine items in the `willEquippedItems` array in the save file in part 1?). Will does `90436` damage now.

{{< imgcap title="Much strong, very damage, wow" src="22-strong-gif.gif" >}}

We could easily do the same and modify any other stat.

## A Closer Look at Base Stats
Back in the analysis result for `HeroMerchantStats.Intelligence` we can see it's modified inside `HeroMerchantStats.Init()`:

{{< imgcap title="HeroMerchantStats.Init" src="23-stats-init.png" >}}

``` cs
this.intelligence = new Stat(
    Constants.GetFloat("kMaxIntelligence"),
    Constants.GetFloat("kMinIntelligence"),
    Constants.GetFloat("kBaseIntelligence")
);
```

This line creates a new character stat named `intelligence`. Then sets the maximum, minimum and base values. Let's see where these default values are set. Double-Click on `Constants.GetFloat` to go there:

{{< imgcap title="Constants.GetFloat" src="24-get-float.png" >}}

A little bit further up in the same file, we can see how these constants are obtained.

{{< imgcap title="Constants.ReadFile" src="25-read-file.png" >}}

They are read from a JSON file named `constants`. If we run a recursive grep for "constants" in the `Moonlighter_Data` directory, we find a few files. We need to open `resources.assets`. Either use a tool to extract it or open it with a hex editor (e.g. HxD) and search for the string `constants`.

I used [Unity Assets Bundle Extractor](https://github.com/DerPopo/UABE/releases). I needed to install [Microsoft Visual C++ 2010 Redistributable Package (x64)](https://www.microsoft.com/en-us/download/details.aspx?id=14632) before running it.

Sort by `Type` and look for files with the `TextAsset` type.

{{< imgcap title="TextAssets" src="26-text-assets.png" >}}

We can dump each file. The base stats are inside the `constants` dump:

{{< imgcap title="Base stats" src="27-constants.png" >}}

There's more stuff here. For example, item drop probabilities.

Other files here contain other things such as items (we can get a list of all items), recipes, and enemy stats. By editing these files, we can change enemy stats, items stats, recipes, and more.

# Conclusion
We learned:

* How to edit game logic for Unity games.
* How to use dnSpy's analysis feature.
* Edit IL instructions to increase Will's damage and stats.
* Discovered a hidden stat called Intelligence that does not appear in the game's UI.

I saw some hidden features in the decompiled DLL. In the next part, I will try to enable them.