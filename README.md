Fake Access Points (Evolved) using Atheros wireless cards in Linux

How to Compile:

- Get the `ieee80211.h` and `ieee80211_radiotap.h` headers from e.g. the MadWiFi distribution:

http://cvs.sourceforge.net/viewcvs.py/madwifi/madwifi/net80211/

```
$ gcc --std=gnu99 -Wall -o fakeaps_evolved fakeaps_evolved.c
```

Start the program

```
$ ./fakeaps_evolved [atheros raw device] [channel it is tuned to] [802.11 version: 'g' or 'n']
```


Before using it:
1. Customize the array of access points below, if you want.
2. Bring up your Atheros interface on the desired channel.
3. Enable the raw device (echo "1" > /proc/sys/dev/ath0/rawdev)
4. Configure the raw device to use radiotap headers (echo "2" > /proc/sys/dev/ath0/rawdev_type)
5. Bring up the raw device (ifconfig ath0raw up)


Improved by Jose Ruiz, Cristian Hernandez and Jose Saldana, from University of Zaragoza.

Initial version written by Evan Jones: http://www.evanjones.ca/software/fakeaps.c

Released under a BSD Licence
