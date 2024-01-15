# DarkTool Warzone

## Overview
DarkTool Warzone is a external game cheat for Warzone using a kernel driver.

## Getting Started

### Prerequisites
- Visual Studio: DarkTool Warzone is built using Visual Studio, so make sure you have it installed on your Windows machine.
- Windows 10 or 11: DarkTool Warzone is specifically designed for Windows operating systems.
- Windows Driver Kit (WDK): To build the driver

### Clone the Repository
```bash
git clone https://github.com/DarkIceXD/DarkTool-Warzone.git
```

or download the .zip using GitHub.

### Opening the Solution
- Launch Visual Studio.
- Click on "File" in the top-left corner.
- Select "Open" and then "Project/Solution."
- Navigate to the DarkTool-Warzone directory and choose the "DarkTool Warzone.sln" file.

### Compiling the Project
- Once the solution is open in Visual Studio, ensure that the correct configuration "Release" and platform "x64" are selected.
- Right-click on the project in the Solution Explorer.
- Choose "Build" from the context menu.
- Make sure to build the driver too.

### Usage
- Start the compiled DarkTool Warzone.exe
- Use some kind of driver loader like [KDmapper](https://github.com/TheCruZ/kdmapper)
- Close the DarkTool Warzone.exe
- Start the game
- Start DarkTool Warzone.exe again
