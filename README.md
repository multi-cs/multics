# Multi CardServer R82 - Custom Build 

MultiCS is cardserver proxy.
Original Author: [Evileyes](http://www.infosat.org)


## Changelog
- [NEW] SSL implementation for HTTP Server
- [ENH] Handle CSAT/TNTSAT nano e0 ECM. There's a new option in profiles called SKIPCWC (similar to oscam "disablecrccws"). Add the following to the affected profiles to activate (only to the affected profiles or it will cause problems!):
ENABLE SKIPCWC: 1
- [FIX] When adding cache peer to running multics it connects to it without need to restart.
- [FIX] ECM sent to cs378x servers where counted twice so hit percentage was showing half the real statistic in servers.
- [ENH] Allow enable/disable camd35 clients. Allow debug camd35 clients.
- [ENH] Create /camd35client URI and update links from /camd35 URI to allow access detailed camd35 client information.
- [ENH] Allow enable/disable cs378x clients. Allow debug cs378x clients.
- [ENH] Create /cs378xclient URI and update links from /cs378x URI to allow access detailed cs378x client information.
- [FIX] Add cccam build number 3367 that is the corresponding to 2.3.0

## Compilation 
use the shell script
```
$ make target=?(ppc-old,ppc,mipsel,mipsel-pli4,sh4,sparc,arm-coolstream,rpi,fritzbox,armeb,aarch64,ppc64el)
```


## How to

```
Copy multics (folder) and multics.? (folder config) to /var/multics/
Chmod -R 775 /var/multics/
Start multics : /var/multics/multics.? -b or /var/multics/multics.? -b -C /config_path
```  

## Todo

- New GUI with JS improvements
- Translations
- ideas?


## Thanks to
- [Evileyes](http://www.infosat.org)
- [Janderklander77](https://github.com/janderklander77)
- [Messi89](https://github.com/messi89)
- [aikonas](http://multics.info/members/aikonas.14048)
