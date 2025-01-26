# Yapping

The Roblox Pattern Scanner is a high-performance memory scanning tool written in Rust, designed to locate specific byte patterns within the Roblox client process memory. It works by first identifying the running Roblox process, obtaining necessary handle permissions, and determining the base module address where scanning will begin.

The patterns are located on the build directory, you can view it and try to tweak the code even more. This code was rushed

Once the process is located, the scanner efficiently reads memory in 4MB chunks, implementing a pattern matching system that supports wildcards for flexible pattern definitions. The tool is optimized to skip protected memory regions and uses RAII-style resource management for safe Windows API interactions.

## Build

- Check the release on the target directory

## Credits
Created by bufferization
