Fake Access Points (Evolved)
----------------------------
(Using Atheros wireless cards in Linux)

Get the `ieee80211.h` and `ieee80211_radiotap.h` headers from e.g. the MadWiFi distribution:

http://cvs.sourceforge.net/viewcvs.py/madwifi/madwifi/net80211/

Compile:

```
$ gcc --std=gnu99 -Wall -o fakeaps_evolved fakeaps_evolved.c
```
or
```
$ gcc --std=gnu99 -Wall -o fakeaps_evolved_with_manual_definition fakeaps_evolved_with_manual_definition.c
```

Start the program

```
$ ./fakeaps_evolved [atheros raw device] [channel it is tuned to] [802.11 version: 'g' or 'n']
```
Example:
```
$ ./fakeaps_evolved wlan0 11 n
```


Version with manual definition of the frames
--------------------------------------------
The program 'fakeaps_evolved_with_manual_definition.c' has more options: it can just inject (it is no longer an AP) 802.11g, 11n and 11ac. You can send frames generated by the program (mode 'p') and also frames directly written by you byte-by-byte (mode 'u').

```
./fakeaps_evolved [atheros raw device] [channel it is tuned to] [802.11 version: 'g' (11g), 'n' (11n), 'v' (11ac), 'a' (send AMPDUs)] [mode: 'p' (program-built frame. Only for 11g and 11n), 'u' (user-defined frame)]
```
Example:
```
$ ./fakeaps_evolved_with_manual_definition wlp1s0 9 n p
```

Before using it:
1. Customize the array of access points below, if you want.
2. Bring up your Atheros interface on the desired channel.
3. Enable the raw device (`echo "1" > /proc/sys/dev/ath0/rawdev`)
4. Configure the raw device to use radiotap headers (`echo "2" > /proc/sys/dev/ath0/rawdev_type`)
5. Bring up the raw device (`ifconfig ath0raw up`)


Improved by Jose Ruiz, Cristian Hernandez and Jose Saldana, from University of Zaragoza.

Initial version written by Evan Jones: http://www.evanjones.ca/software/fakeaps.c

Released under a BSD Licence
