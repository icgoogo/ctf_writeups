## picoctf 2024 heap1
this challenge is the continuation of heap0. so, better you check the heap0 first. 

if we decompile the binary with idafree, nothing really change except `if ( !strcmp(safe_var, "pico") )`
if we want it to be true, then we should fill the start of safe_var heap with "pico". then you will get the flag. 
