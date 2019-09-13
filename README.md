# deREferencing

 [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

deReferencing is an IDA Pro plugin that implements new registers and stack views. Adds dereferenced pointers, colors and other useful information, similar to some GDB plugins (e.g: PEDA, GEF, pwndbg, etc).

Supports following architectures: **x86, x86-64, ARM, ARM64, MIPS32 and MIPS64**

## Requirements

* IDA-Pro >= 7.2

## Install

Just drop the `dereferencing.py` file and the `dereferencing` folder into IDA's plugin directory.

To install just for the current user, copy the files into one of these directories:

| OS          | Plugin path                          |
| ----------- | ------------------------------------ |
| Linux/macOS | `~/.idapro/plugins`                  |
| Windows     | `%AppData%\Hex-Rays\IDA Pro\plugins` |

## Usage

Both views can be opened from the menu `Debugger -> Debugger Windows` or by shortcuts:

* deREferencing - Registers (`Alt-Shift-D`)
* deREferencing - Stack (`Alt-Shift-E`)

You also can save the desktop layout using the `Windows -> Save desktop` option, so that the plugin starts automatically in other debugging sessions.

## Configuration

Config options can be modified vía `deferencing/config.py` file.

### Snapshots

### Registers view

![registers](https://user-images.githubusercontent.com/1675387/64848469-925f0680-d611-11e9-8418-06c5354894be.png)

### Stack view

![stack](https://user-images.githubusercontent.com/1675387/64848678-144f2f80-d612-11e9-8cb1-f3f3a837b267.png)

## Thanks

Special mention to my colleague [@roman_soft](https://twitter.com/roman_soft) for give me some ideas during the development of the plugin.

## Bugs / Feedback / PRs

Any comment, issue or pull request will be highly appreciated :-)

## Author

* Daniel García Gutiérrez - @danigargu
