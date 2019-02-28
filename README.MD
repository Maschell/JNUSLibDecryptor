# JNUSLib Decryptor

A simple wrapper of [JNUSLib](https://github.com/Maschell/JNUSLib) to decrypt local files (.app/.h3/.tmd).

# Usage
Optional: 
- Create file `common.key` containing the Wii U common key in binary into the folder next to the .jar instead of providing it via the command line.

```
JNUSLib Decryptor 0.1 - Maschell

usage:
 -commonkey <WiiU common key>   Optional. HexString. Will be used if no "common.key" in the folder
                                of this .jar is found
 -file <regular expression>     Decrypts the files that matches the given regular expression.
 -help                          shows this text
 -in <input file>               Input file. Expects a folder which contains the .app, and .tmd
                                files.
 -out <output path>             The path where the result will be saved
 -overwrite                     Optional. Overwrites existing files
 -titlekey <Ticket title key>   Optional. HexString. Will be used if no "title.tik" in the folder is
                                found
 -whole                         Decrypts the whole content files.
 ```

Requires Java 8.

# Building

This is a maven project. Use following command to create a .jar with dependencies in the `target` folder. 
```
mvn clean package
```

# Used libraries
- [JNUSLib](https://github.com/Maschell/JNUSLib)  
- [lombok](https://projectlombok.org/)  
- [commons-cli](https://commons.apache.org/proper/commons-cli/)
