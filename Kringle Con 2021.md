![](https://i.imgur.com/BtFkj4b.jpg)


# Yara - Fitzy Shorts - PiTerminal
There is a binary that is getting caught up by a yara rule so we need to find out what rule is causing the issue and then modify the binary to allow it to execute

![](https://i.imgur.com/Z17jdJN.png)

looks like rule 135 is holding us up

```
snowball2@fa90e0beda80:~$ vim yara_rules/rules.yar
```

```python
rule yara_rule_135 {
   meta:
      description = "binaries - file Sugar_in_the_machinery"
      author = "Sparkle Redberry"
      reference = "North Pole Malware Research Lab"
      date = "1955-04-21"
      hash = "19ecaadb2159b566c39c999b0f860b4d8fc2824eb648e275f57a6dbceaf9b488"
   strings:
      $s = "candycane"
   condition:
      $s
}
```

Opening the binary in vim we can see our problem string

![](https://i.imgur.com/TkIJt1B.png)

I learned that opening a binary without using the -b flag will add bytes to the file and can corrupt the binary.

Since we know the string we want to replace though we can use sed to replace candycane with newstring

```python
sed 's/candycane/newstring/g' the_critical_elf_app > newapp
```

running the newapp we get:
![](https://i.imgur.com/AcaM6nq.png)

```python
rule yara_rule_1056 {
   meta:
        description = "binaries - file frosty.exe"
        author = "Sparkle Redberry"
        reference = "North Pole Malware Research Lab"
        date = "1955-04-21"
        hash = "b9b95f671e3d54318b3fd4db1ba3b813325fcef462070da163193d7acb5fcd03"
    strings:
        $s1 = {6c 6962 632e 736f 2e36}
        $hs2 = {726f 6772 616d 2121}
    condition:
        all of them
}
```

![](https://i.imgur.com/CgTIOw0.png)
*yara docs for "all of them"*

The post on Stackexchange for using VIM with binaries
[](https://vi.stackexchange.com/posts/11906/timeline)

# TL;DR Answer

Open the file with Vim in binary mode:

```
vim -b <file_to_edit>
```

In Vim, get into hex editing mode like so:

```
:%!xxd -p
```

To save:

```
:%!xxd -p -r
:w
```

Decoding the Hex Strings we get a somewhat important string and a not so important one.

```
6c6962632e736f2e36 > libc.so.6
726f6772616d2121 > rogram!!
```

we can change just rogram!! to Rogram!! and we should bypass this rule 

```
sed 's/rogram!!/Rogram!!/g' the_critical_elf_app > tmp
```

![](https://i.imgur.com/9hgDq6W.png)

Now, we are at yara rule 1732

```python
rule yara_rule_1732 {
   meta:
      description = "binaries - alwayz_winter.exe"
      author = "Santa"
      reference = "North Pole Malware Research Lab"
      date = "1955-04-22"
      hash = "c1e31a539898aab18f483d9e7b3c698ea45799e78bddc919a7dbebb1b40193a8"
   strings:
      $s1 = "This is critical for the execution of this program!!" fullword ascii
      $s2 = "__frame_dummy_init_array_entry" fullword ascii
      $s3 = ".note.gnu.property" fullword ascii
      $s4 = ".eh_frame_hdr" fullword ascii
      $s5 = "__FRAME_END__" fullword ascii
      $s6 = "__GNU_EH_FRAME_HDR" fullword ascii
      $s7 = "frame_dummy" fullword ascii
      $s8 = ".note.gnu.build-id" fullword ascii
      $s9 = "completed.8060" fullword ascii
      $s10 = "_IO_stdin_used" fullword ascii
      $s11 = ".note.ABI-tag" fullword ascii
      $s12 = "naughty string" fullword ascii
      $s13 = "dastardly string" fullword ascii
      $s14 = "__do_global_dtors_aux_fini_array_entry" fullword ascii
      $s15 = "__libc_start_main@@GLIBC_2.2.5" fullword ascii
      $s16 = "GLIBC_2.2.5" fullword ascii
      $s17 = "its_a_holly_jolly_variable" fullword ascii
      $s18 = "__cxa_finalize" fullword ascii
      $s19 = "HolidayHackChallenge{NotReallyAFlag}" fullword ascii
      $s20 = "__libc_csu_init" fullword ascii
   condition:
      uint32(1) == 0x02464c45 and filesize < 50KB and
      10 of them
}
```

Lots going on but the filesize being < 50KB catches my eye in the conditions.
I set a loop in bash to echo a bunch of 0s and ls -la the file and stopped it when the file was over 50KB
```
x=1; while [ $x -le 1000 ]; do echo "00000000000000000000000000000" >> tmp $(( x++ )); done
```

```
snowball2@3e3932c7df99:~$ ./tmp
Machine Running.. 
Toy Levels: Very Merry, Terry
Naughty/Nice Blockchain Assessment: Untampered
Candy Sweetness Gauge: Exceedingly Sugarlicious
Elf Jolliness Quotient: 4a6f6c6c7920456e6f7567682c204f76657274696d6520417070726f766564
```

![](https://i.imgur.com/BAMtawN.png)


![](https://i.imgur.com/7AFNBUT.png)
![](https://i.imgur.com/yQQcfSs.png)


# Exiftool naughty/nice records

The dates made this trivial since all the modified dates are in perfect order.

![](https://i.imgur.com/Mc152kV.png)

