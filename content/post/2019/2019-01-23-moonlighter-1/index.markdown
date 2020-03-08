---
title: "Cheating at Moonlighter - Part 1 - Save File"
date: 2019-01-23T20:03:08-05:00
draft: false
toc: true
comments: true
twitterImage: 11-items-equipped.png
categories:
- Game Hacking
tags:
- Moonlighter
- procmon
---

[Moonlighter](http://moonlighterthegame.com/) is a nice game. Over the new year break, I played it for 10 hours a day for 2-3 days. It's your typical dungeon crawler with a twist. You have a shop and you can sell items in your shop and do a bit of price manipulation based on supply and demand.

It has some grinding. At each dungeon level (there are four), you have grind the items needed for crafting the next level equipment. After farming for multiple hours to get a few drops of one item, I decided to cheat at it.

This post talks about how I discovered the save file and how we can modify it to give ourselves any item in the game. In the next part, I will discuss modifying the game to one-shot enemies and other things. It's a straightforward game for getting into "game hacking."

<!--more-->

# Setup

* Moonlighter Steam version
* Windows 10 64-bit VM in VirtualBox
* Steam offline mode
  * Moonlighter is not a multi-player game and is not VAC enabled, but I wanted to be safe. I do not think modifying the save and game files will get my steam account banned, but I do not want it to happen. I have so many games (that I will never play) in my account.

# Save File Location
I am using the Steam version. If you have a different version, your save file location will be different. We can discover the save file in two ways:

* Searching for it.
* Discovering it with procmon.

## Searching for Save File Location
This [reddit comment][reddit-save-file] mentions two locations:

* Steam version: ` [Your Steam Installation Folder]\Steam\userdata[Your Steam ID]\606150\remote`
* Non-Steam: `C:\Users[Your Windows Username]\AppData\LocalLow\11BitStudios\Moonlighter`

## Using Procmon
Procmon logs many events. We need to minimize the total number of captured events and then use filter to further reduce the number. To do this, we need to find an event that forces a game save. There are different ways to do this (I think every loading screen does it). Two of the easiest are:

* Closing the shop
* Sleeping

I chose the first.

1. Start the game, do not start procmon yet. The game is already slow in the VM and procmon will make it worth. Finishing the tutorial in the VM was hard (lol).
2. Start procmon.
3. Open the shop.
4. Immediately close it.
5. Skip the summary screen.
6. Alt+tab out and stop capturing events with `File > Capture Events`.
7. Quit the game.

Now I had `27000` events (excluding profiling events).

### Filtering by Process
This is a great tool. Open the Process Tree at `Tools > Process Tree`.

In the process tree, right-click `Steam` and select `Add process and children to include filter`. This is a handy filter. It allows us to filter all children. It filters by process ID so it will not work between different executions.

**Note:** It's tempting to just select `Moonlighter` and that is what I initially did. But in this case, Steam is handling the save file.

{{< imgcap title="Procmon's Procee Tree" src="00-procmon-process-tree.png" >}}

After selecting, the filtering takes a few seconds and we are down to around `409` events. Oh boy. This turned out easier than I thought.

{{< imgcap title="Results after filtering by process" src="01-procmon-after-filter.png" >}}

### Filtering by Write Events
Assuming things are saved in a file and not registry (registry is an option but usually not in games because save files are big). We can filter by `File System Activity` using the icon in the toolbar. This reduces the number of events to `341`.

{{< imgcap title="Filtering by File System Activity" src="02-procmon-after-file-filter.png" >}}

But our most important filter is next. We forced a save game write event, we only need to keep write events.

We need to pay attention to two operations here: `WriteFile` and `CreateFile`. I am not sure about the difference in procmon vs. WinAPI but I use both to be sure. We need to add two filters:

* `Operation` - `is` - `WriteFile` then `Include`.
* `Operation` - `is` - `CreateFile` then `Include`.

{{< imgcap title="Write events" src="03-after-create-write-file.png" >}}

We're now down to `89` events which is pretty manageable for manual review.

### Unity Analytics
We can learn a few things. For example, [Unity analytics][unity-analytics] files are at this location:

* `C:\Users\IEUser\AppData\LocalLow\11BitStudios\Moonlighter\Unity\f522e32a-6e64-4c70-afbd-bf0463165292\Analytics`

The `config` file has some interesting info.

``` json
{
    "prefs": {},
    "analytics": {
        "enabled": true
    },
    "connect": {
        "limit_user_tracking": false,
        "player_opted_out": false,
        "enabled": true
    },
    "performance": {
        "enabled": true
    }
}
```

Supposedly they are collecting analytics and users have not opted out. I have not seen such a setting in the game and I have no idea what kind of data are being collected in game. But that is for another day.

If our guess is correct, we can stop the analytics by disabling it in that file.

### Save File Location
But what we are looking for is at:

* `C:\Program Files (x86)\Steam\userdata\{{steamID}}\606150\remote`

{{< imgcap title="Save file location" src="04-userdata-files.png" >}}

### Notes About the Save File
* **MAKE MULTIPLE COPIES OF IT.**
* If you mess up the save game, the game will get stuck at the loading screen. If this happens, quit the game and restore from a safe copy.
* Sometimes the game gets stuck on the loading screen even with a good save game. To be sure, always kill Steam before every new run.

# Save File Structure
Unsurprisingly, it's the largest file `gameslot`. It's a JSON file.

Beautify it with CyberChef:

{{< imgcap title="Beautified save file" src="05-beautified-json.png" >}}

## Gold
It does not get easier than this. Let's search for `gold`.

```json
"willWishlistedRecipes": "",
"equippedWeaponSet": 0,
"willGold": 100,
```

We can modify it and give ourselves more gold. Will is the name of the main character.

I gave Will 10 million gold. It's a reasonable number.

{{< imgcap title="Will is rich" src="06-10mil-gold.png" >}}

## Equipment
`willEquippedItems` is an array of items. Some are empty. Seems like there's an order, meaning the first items could be head, next could be weapon and etc. We do not know which is which yet. Starting from zero we have:

* 0, 1, 2: empty.
* 3: `Training Sword`.
* 4: `Broom Spear`.
* 5 and 6: `Dash`.
* 7: `HP Potion I`.
* 8, 9: empty

``` json
"willEquippedItems": [
    {
        "prefabName": null,
        "plusLevel": 0,
        "name": "",
        "quantity": 0,
        "sellingPrize": 0,
        "curseName": null,
        "enchantmentLevel": 0,
        "enchantmentType": 0,
        "enchantmentEffectName": null
    },
    // .. removed
    {
        "prefabName": "ItemStack",
        "plusLevel": 0,
        "name": "Training Sword",
        "quantity": 1,
        "sellingPrize": 0,
        "curseName": "",
        "enchantmentLevel": 0,
        "enchantmentType": 0,
        "enchantmentEffectName": ""
    },
    {
        "prefabName": "ItemStack",
        "plusLevel": 0,
        "name": "Broom Spear",
        "quantity": 1,
        "sellingPrize": 0,
        "curseName": "",
        "enchantmentLevel": 0,
        "enchantmentType": 0,
        "enchantmentEffectName": ""
    },
    {
        "prefabName": "ItemStack",
        "plusLevel": 0,
        "name": "Dash",
        "quantity": 1,
        "sellingPrize": 0,
        "curseName": "",
        "enchantmentLevel": 0,
        "enchantmentType": 0,
        "enchantmentEffectName": ""
    },
    // removed
]
```

Let's look at our equipped items to see what's what.

{{< imgcap title="Will's inventory before modification" src="07-inventory.png" >}}

* 0, 1, 2: Unknown - empty.
* 3: Weapon Slot 1 - `Training Sword`.
* 4: Weapon Slot 2 - `Broom Spear`.
* 5 and 6: Unknown - `Dash`. These two do not appear in the inventory. It's the ability `Dash` forward and backward (bound to the `space` key) but I am not sure why it's a separate skill. These might be the two inventory slots on top and under the potion slot (see the picture).
* 7: Potion slot: `HP Potion I`.
* 8 and 9: Unknown - empty.

There's also a `willInventory` array with items in the inventory. We can see the top row in the picture.

``` json
{
    "prefabName": "ItemStack",
    "plusLevel": 0,
    "name": "Rich Jelly",
    "quantity": 3,
    "sellingPrize": 0,
    "curseName": "",
    "enchantmentLevel": 0,
    "enchantmentType": 0,
    "enchantmentEffectName": null
},
{
    "prefabName": "ItemStack",
    "plusLevel": 0,
    "name": "Whetstone",
    "quantity": 10,
    "sellingPrize": 0,
    "curseName": "",
    "enchantmentLevel": 0,
    "enchantmentType": 0,
    "enchantmentEffectName": null
},
```

We can modify any slot and give will any item/quantity. To figure out item names, we can look under `recipesSeen` and see a handy list.

``` json
"recipesSeen": [
    {
        "name": "Training Sword",
        "seen": true,
        "plusLevel": 0
    },
    {
        "name": "Training Big Sword",
        "seen": true,
        "plusLevel": 0
    },
    {
        "name": "Training Gloves",
        "seen": true,
        "plusLevel": 0
    },
]
```

But it is not complete. Especially for this playthrough inside the Virtual Machine.

To test our theory, let's give ourselves another `Broom Spear` in weapon slot 1 instead of the `Training Sword`. And now we have two broom spears.

{{< imgcap title="Two broom spears" src="08-two-broom-spears.png" >}}

That was fun, but how do we give ourselves better items? We do not know their names.

Assuming we cannot search online (which has all the item names), we can use an in-game feature. The blacksmith can craft armor and weapons. To get the blacksmith, we need to build the building for 500 gold. Luckily, we have 10 million. Looking at his items, we can see their names and use them.

{{< imgcap title="Blacksmith's items" src="09-blacksmith-items.png" >}}

We cannot see all items yet, but their names appear in the top-right corner of the screen. Being a sneaky archer, I want to get the items with speed bonuses:

* `Fabric Bandana IV`
* `Fabric Chestplate IV`
* `Fabric Boots IV`
* `King Sword`. The label says `King Short Sword` but the actual in-game item is `King Sword`.
* `Exeter Bow`

The only remaining problem is figuring out which `willEquippedItems` array host which item. That's easy, we will add the items in our inventory and then equip them in game.

Items can also be enchanted (and cursed for elemental items).`enchantmentLevel` and `enchantmentType` set to `1`. For example, the max non-elemental bow is set like this in inventory.

``` json
{
    "prefabName": "ItemStack",
    "plusLevel": 0,
    "name": "Exeter Bow",
    "quantity": 1,
    "sellingPrize": 0,
    "curseName": "",
    "enchantmentLevel": 1,
    "enchantmentType": 1,
    "enchantmentEffectName": null
}
```

And now Will has all these shiny items (I made a mistake and gave him 10 chest plates).

{{< imgcap title="Items added to Will's inventory" src="10-items-added.png" >}}

Equip them and trigger another save event. For example, enter a dungeon and then leave using the pendant.

{{< imgcap title="Items equipped in game" src="11-items-equipped.png" >}}

{{< imgcap title="Equipped items in save file" src="12-equipped-items-in-save-file.png" >}}

We can update the `willEquippedItems` array:

* 0: Head slot - `Fabric Bandana IV`.
* 1: Chest slot - `Fabric Chestplate IV`.
* 2: Leg slot - `Fabric Boots IV`.
* 3: Weapon Slot 1 - `Training Sword`.
* 4: Weapon Slot 2 - `Broom Spear`.
* 5 and 6: Unknown - `Dash`.
* 7: Potion slot: `HP Potion I`.
* 8 and 9: Unknown - empty.

Adding items to the shop and chests is similar. Later in the game, we get quests. People ask Will to get them a certain number of an item in a few days. Quests appear in the save file under `willActiveQuests` and completed quests are under `completedQuests`. We can modify the quest and rewards to anything we want to get that money. This is a completed quest.

``` json
"completedQuests": [
{
    "Key": 21,
    "Value": {
        "quest": {
            "culture": "Golem",
            "floor": 0,
            "target": "Ancient Wood",
            "quantity": 5,
            "daysToComplete": 3,
            "reward": 20000,
            "killQuestTarget": "",
            "killQuestTargetKey": "",
            "giverType": "Merchant",
            "description": "QUEST_ANCIENT_WOOD_GENDER_DESCRIPTION"
        },
        "completed": true,
        "failed": true,
        "completeDay": 21,
        "giverVisitorPrefabName": "Freak Girl - Tomo",
        "giverVisitorIsMale": false
    }
},
```

I am not going to talk about the rest of the save file. It's pretty obvious.

# Lessons Learned
We learned:

* How to locate the save file of Moonlighter (Steam edition).
* Where Unity Analytics are stored.
* The structure of the save file.
* How to modify the save file and change everything in the game.

In the next part, I will mess with the game files to change game mechanics (e.g. one shotting everything).

<!-- Links -->
[reddit-save-file]: https://www.reddit.com/r/Moonlighter/comments/8mzr0n/save_file_location/e084yv8/
[unity-analytics]: https://unity.com/solutions/mobile-business/operate-your-live-game
