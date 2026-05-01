# NOTICE!
This project is **NOT** complete.
I've currently paused development on ethanol to focus on personal responsibilities and other projects.

The source contained in this project is **testing** things such as memory scanning and invoking subroutines, with the inevitable goal of providing external script execution.

## Goal
The idea I have for this project is simple: external script execution.

More technically, I'd like to perform this via:
- Compiling LuaU bytecode, creating a script context, and executing it by pushing it to the scheduler or stack directly.
- Potentially escalating script identity using said context
- Injection of custom pre-defined globals written in Rust or C.

## My Ability
I am **not** a Rust developer, and have barely touched native languages.
As such, this is not a project that is feasible without the assistance of either:
- An experienced Rust developer
- An experienced LuaU reverse engineer, etc.
- Skidding/AI

The most feasible solution for me is the third, as such you may notice the employment of AI practices and commenting, though I'm attempting to learn through guidance of this LLM. I am reversing the APK used for Sober (Linux Roblox) and consulting other open source projects that do what I plan on implementing. I've done a mock of this project in skidded C++ before, so I'm not entirely unfamiliar.
