### [Manual](https://github.com/Tisit/WinBOLT/blob/main/Manual.md)

### [Glossary](https://github.com/Tisit/WinBOLT/blob/main/Glossary.md)

## Cop-out for this repo

[BOLT](https://github.com/llvm/llvm-project/tree/main/bolt) is a post-link optimizer that is part of LLVM toolchain. It rearranges code layout to improve performance. Its support for Windows seems limited. 

I found the premise of this tool interesting when I first heard about it. My idea was to run it on Factorio binaries to have my megabase run few % faster. But I never came around doing this. With the rise of vibe coding I wanted to try that out myself. Making Windows version of BOLT sounded interesting. I started prompting Claude Opus and basically this is the end of the story. I very quickly got something working. This tool leverages ETW traces for LBR data and uses it to rewrite the binary just like BOLT. But it is also able to rewrite the whole program if it is linked the right way and PDB is available. To my understanding this is something that Microsoft did/does. Tool like this is described in this [video](https://www.youtube.com/watch?v=jH0BYAkPj78) from David Plummer (Dave's Garage channel).

Motivation for BOLT was large scale datacenter software. From my tests even small binaries like zopfli (100k) benefit from layout optimization. I was also able to confirm original claim from BOLT developers that using this tool on PGO optimized software is still beneficial. Overall the speedups I gained were under 10%. In daily usage rather not noticeable.

Here are some numbers:
| Target | Speedup|
|--------|--------|
|SQLite speedtest1| 4.4 to 5.5% |
|zopfli| 8.0 to 8.4% |
|zopflipng| about 19% |
|ripgrep| 4.05%|
|7z.dll| 6.0%|

Note: Everything in this reposidory besides this readme was created using Claude Code. I didn't look at the code almost at all. I'm not even a programmer. So if you are allergic to LLM slop, worried about code maintainability or obsess over rewrites I advise you to avert your gaze. Otherwise you may find this tool interesting, usable even.

Note 2: That Factorio binary I mentioned at the beginning? I optimized it, sure. It worked with smaller base. But megabases I tested were memory bound. So I gained nothing beside knowledge here.
