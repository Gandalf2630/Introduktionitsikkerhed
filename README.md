1# linuxcommands
BANIDT LVL 0

┌──(kali㉿kali)-[~]
└─$ ssh bandit0@bandit.labs.overthewire.org -p 2220 

backend: gibson-1
bandit0@bandit.labs.overthewire.org's password: 

Welcome to OverTheWire!


bandit0@bandit:~$ ls
readme
bandit0@bandit:~$ cat readme
Congratulations on your first steps into the bandit game!!
Please make sure you have read the rules at https://overthewire.org/rules/
If you are following a course, workshop, walkthrough or other educational activity,
please inform the instructor about the rules as well and encourage them to
contribute to the OverTheWire community so we can keep these games free!

The password you are looking for is: ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If

bandit0@bandit:~$ history
    1  ls
    2  cat readme
    3  history
bandit0@bandit:~$ 



BANDIT LVL 1
┌──(kali㉿kali)-[~]
└─$ ssh bandit01@bandit.labs.overthewire.org -p 2220      

backend: gibson-1
bandit01@bandit.labs.overthewire.org's password: 
Permission denied, please try again.
bandit01@bandit.labs.overthewire.org's password: 

                                                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ ssh bandit01@bandit.labs.overthewire.org -p 2220

backend: gibson-1
bandit01@bandit.labs.overthewire.org's password: 
Permission denied, please try again.
bandit01@bandit.labs.overthewire.org's password: 
Permission denied, please try again.
bandit01@bandit.labs.overthewire.org's password: 

zsh: suspended  ssh bandit01@bandit.labs.overthewire.org -p 2220
                                                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ ssh bandit00@bandit.labs.overthewire.org -p 2220

backend: gibson-1
bandit00@bandit.labs.overthewire.org's password: 
Permission denied, please try again.
bandit00@bandit.labs.overthewire.org's password: 
Permission denied, please try again.
bandit00@bandit.labs.overthewire.org's password: 
bandit00@bandit.labs.overthewire.org: Permission denied (publickey,password).
                                                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ history
    1  ssh bandit@bandit.labs.overthewire.org -p 2220 
    2  ssh bandit0@bandit.labs.overthewire.org -p 2220 
    3  ssh bandit01@bandit.labs.overthewire.org -p 2220 
    4  ssh bandit1@bandit.labs.overthewire.org -p 2220 
    5  setxkbmap dk
    6  ssh bandit1@bandit.labs.overthewire.org -p 2220 
    7  ssh bandit2@bandit.labs.overthewire.org -p 2220 
    8  ssh bandit3@bandit.labs.overthewire.org -p 2220 
    9  ssh bandit4@bandit.labs.overthewire.org -p 2220 
   10  ssh bandit5@bandit.labs.overthewire.org -p 2220 
   11  history
   12  ^[[200~$ history~
   13  history
   14  $ history
   15  HISTTIMEFORMAT="%F %T " && history
   16  history > full_history.txt
   17  history -c
   18  history -m 
   19  history 5
   20  history 1
   21  history
   22  history | grep "ls"
   23  sudo nano .bashrc
   24  ssh bandit01@bandit.labs.overthewire.org -p 2220 
   25  less ~/.bash_history
   26  rm ~/.bash_history && history -c
   27  . ~/.bashrc
   28  \n
   29  history | grep mv
   30  export HISTTIMEFORMAT="%F %T "\n
   31  source ~/.bashrc
   32  history
   33  cat ~/.bash_history
   34  HISTTIMEFORMAT="%F %T " history
   35  history
   36  apt update
   37  sudo apt update
   38  history
   39  # Source - https://stackoverflow.com/questions/15116806/how-can-i-see-all-of-the-bash-history\n# Posted by diveintohacking\n# Retrieved 2025-11-06, License - CC BY-SA 3.0\n\n$ history\n .\n .\n .\n 8720  exit\n 8721  clear\n 8722  history\n
   40  # Source - https://stackoverflow.com/questions/15116806/how-can-i-see-all-of-the-bash-history\n# Posted by etusm\n# Retrieved 2025-11-06, License - CC BY-SA 3.0\n\ncat ~/.bash_history\n
   41  cat ~/.bash_history
   42  # Source - https://stackoverflow.com/questions/15116806/how-can-i-see-all-of-the-bash-history\n# Posted by etusm\n# Retrieved 2025-11-06, License - CC BY-SA 3.0\n\nvim ~/.bash_history \n
   43  ssh bandit01@bandit.labs.overthewire.org -p 2220
   44  ssh bandit00@bandit.labs.overthewire.org -p 2220
                                                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ history 1000     
    1  ssh bandit@bandit.labs.overthewire.org -p 2220 
    2  ssh bandit0@bandit.labs.overthewire.org -p 2220 
    3  ssh bandit01@bandit.labs.overthewire.org -p 2220 
    4  ssh bandit1@bandit.labs.overthewire.org -p 2220 
    5  setxkbmap dk
    6  ssh bandit1@bandit.labs.overthewire.org -p 2220 
    7  ssh bandit2@bandit.labs.overthewire.org -p 2220 
    8  ssh bandit3@bandit.labs.overthewire.org -p 2220 
    9  ssh bandit4@bandit.labs.overthewire.org -p 2220 
   10  ssh bandit5@bandit.labs.overthewire.org -p 2220 
   11  history
   12  ^[[200~$ history~
   13  history
   14  $ history
   15  HISTTIMEFORMAT="%F %T " && history
   16  history > full_history.txt
   17  history -c
   18  history -m 
   19  history 5
   20  history 1
   21  history
   22  history | grep "ls"
   23  sudo nano .bashrc
   24  ssh bandit01@bandit.labs.overthewire.org -p 2220 
   25  less ~/.bash_history
   26  rm ~/.bash_history && history -c
   27  . ~/.bashrc
   28  \n
   29  history | grep mv
   30  export HISTTIMEFORMAT="%F %T "\n
   31  source ~/.bashrc
   32  history
   33  cat ~/.bash_history
   34  HISTTIMEFORMAT="%F %T " history
   35  history
   36  apt update
   37  sudo apt update
   38  history
   39  # Source - https://stackoverflow.com/questions/15116806/how-can-i-see-all-of-the-bash-history\n# Posted by diveintohacking\n# Retrieved 2025-11-06, License - CC BY-SA 3.0\n\n$ history\n .\n .\n .\n 8720  exit\n 8721  clear\n 8722  history\n
   40  # Source - https://stackoverflow.com/questions/15116806/how-can-i-see-all-of-the-bash-history\n# Posted by etusm\n# Retrieved 2025-11-06, License - CC BY-SA 3.0\n\ncat ~/.bash_history\n
   41  cat ~/.bash_history
   42  # Source - https://stackoverflow.com/questions/15116806/how-can-i-see-all-of-the-bash-history\n# Posted by etusm\n# Retrieved 2025-11-06, License - CC BY-SA 3.0\n\nvim ~/.bash_history \n
   43  ssh bandit01@bandit.labs.overthewire.org -p 2220
   44  ssh bandit00@bandit.labs.overthewire.org -p 2220
   45  history
   46  history 1000
                                                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ ssh bandit@bandit.labs.overthewire.org -p 2220  

!!! You are trying to log into this SSH server on port 2220 with a username
!!! that does not match the bandit game.

backend: gibson-1
bandit@bandit.labs.overthewire.org's password: 
Permission denied, please try again.
bandit@bandit.labs.overthewire.org's password: 
Permission denied, please try again.
bandit@bandit.labs.overthewire.org's password: 
bandit@bandit.labs.overthewire.org: Permission denied (publickey,password).
                                                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ ssh bandit@bandit.labs.overthewire.org -p 2220
backend: gibson-1
bandit@bandit.labs.overthewire.org's password: 
Permission denied, please try again.
bandit@bandit.labs.overthewire.org's password: 

                                                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ ssh bandit.labs.overthewire.org -p 2220       

backend: gibson-1
kali@bandit.labs.overthewire.org's password: 
Permission denied, please try again.
kali@bandit.labs.overthewire.org's password: 

                                                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ ssh bandit0@bandit.labs.overthewire.org -p 2220 

backend: gibson-1
bandit0@bandit.labs.overthewire.org's password: 


bandit0@bandit:~$ ls
readme
bandit0@bandit:~$ cat readme
Congratulations on your first steps into the bandit game!!
Please make sure you have read the rules at https://overthewire.org/rules/
If you are following a course, workshop, walkthrough or other educational activity,
please inform the instructor about the rules as well and encourage them to
contribute to the OverTheWire community so we can keep these games free!

The password you are looking for is: ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If

bandit0@bandit:~$ ^C
bandit0@bandit:~$ exit
logout
Connection to bandit.labs.overthewire.org closed.
                                                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ ssh bandit01@bandit.labs.overthewire.org -p 2220
backend: gibson-1
bandit01@bandit.labs.overthewire.org's password: 
Permission denied, please try again.
bandit01@bandit.labs.overthewire.org's password: 
                                                                                                                                
┌──(kali㉿kali)-[~]
└─$ ssh bandit1@bandit.labs.overthewire.org -p 2220 
backend: gibson-1
bandit1@bandit.labs.overthewire.org's password: 

Welcome to OverTheWire!

bandit1@bandit:~$  an OverTheWire game server. 




──(kali㉿kali)-[~]
└─$ ssh bandit1@bandit.labs.overthewire.org -p 2220
                         _                     _ _ _   
                        | |__   __ _ _ __   __| (_) |_ 
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_ 
                        |_.__/ \__,_|_| |_|\__,_|_|\__|
                                                       

                      This is an OverTheWire game server. 
            More information on http://www.overthewire.org/wargames

backend: gibson-1
bandit1@bandit.labs.overthewire.org's password: 

bandit1@bandit:~$ ls
-
bandit1@bandit:~$ cd
bandit1@bandit:~$ cat -
s
s
^C
bandit1@bandit:~$ find
.
./.bash_logout
./.bashrc
./.profile
./-
bandit1@bandit:~$ find -
-
bandit1@bandit:~$ find ./.bash_logout
./.bash_logout
bandit1@bandit:~$ find ./.profile
./.profile
bandit1@bandit:~$ cat ./.profile
# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
bandit1@bandit:~$ file
Usage: file [-bcCdEhikLlNnprsSvzZ0] [--apple] [--extension] [--mime-encoding]
            [--mime-type] [-e <testname>] [-F <separator>]  [-f <namefile>]
            [-m <magicfiles>] [-P <parameter=value>] [--exclude-quiet]
            <file> ...
       file -C [-m <magicfiles>]
       file [--help]
bandit1@bandit:~$ file ./.profile
./.profile: ASCII text
bandit1@bandit:~$ cd ./.profile
-bash: cd: ./.profile: Not a directory
bandit1@bandit:~$ cd -
/home/bandit1
bandit1@bandit:~$ cat bandit1
cat: bandit1: No such file or directory
bandit1@bandit:~$ cat /home
cat: /home: Is a directory
bandit1@bandit:~$ cd /home
bandit1@bandit:/home$ cd /bandit1
-bash: cd: /bandit1: No such file or directory
bandit1@bandit:/home$ ls
bandit0   bandit14  bandit2   bandit25      bandit29      bandit31-git  bandit7    behemoth3  drifter0   drifter15  drifter7     formulaone3  krypton4    leviathan2  manpage0  manpage6  maze4  narnia0  narnia6  utumno1  utumno7   vortex12  vortex18  vortex23  vortex6
bandit1   bandit15  bandit20  bandit26      bandit29-git  bandit32      bandit8    behemoth4  drifter1   drifter2   drifter8     formulaone5  krypton5    leviathan3  manpage1  manpage7  maze5  narnia1  narnia7  utumno2  utumno8   vortex13  vortex19  vortex24  vortex7
bandit10  bandit16  bandit21  bandit27      bandit3       bandit33      bandit9    behemoth5  drifter10  drifter3   drifter9     formulaone6  krypton6    leviathan4  manpage2  maze0     maze6  narnia2  narnia8  utumno3  vortex0   vortex14  vortex2   vortex25  vortex8
bandit11  bandit17  bandit22  bandit27-git  bandit30      bandit4       behemoth0  behemoth6  drifter12  drifter4   formulaone0  krypton1     krypton7    leviathan5  manpage3  maze1     maze7  narnia3  narnia9  utumno4  vortex1   vortex15  vortex20  vortex3   vortex9
bandit12  bandit18  bandit23  bandit28      bandit30-git  bandit5       behemoth1  behemoth7  drifter13  drifter5   formulaone1  krypton2     leviathan0  leviathan6  manpage4  maze2     maze8  narnia4  ubuntu   utumno5  vortex10  vortex16  vortex21  vortex4
bandit13  bandit19  bandit24  bandit28-git  bandit31      bandit6       behemoth2  behemoth8  drifter14  drifter6   formulaone2  krypton3     leviathan1  leviathan7  manpage5  maze3     maze9  narnia5  utumno0  utumno6  vortex11  vortex17  vortex22  vortex5
bandit1@bandit:/home$ cat bandit1
cat: bandit1: Is a directory
bandit1@bandit:/home$ file bandit1
bandit1: directory
bandit1@bandit:/home$ cd /bandit1
-bash: cd: /bandit1: No such file or directory
bandit1@bandit:/home$ /bandit0
-bash: /bandit0: No such file or directory
bandit1@bandit:/home$ /bandit2
-bash: /bandit2: No such file or directory
bandit1@bandit:/home$ cd /bandit2
-bash: cd: /bandit2: No such file or directory
bandit1@bandit:/home$ file /bandit2
/bandit2: cannot open `/bandit2' (No such file or directory)
bandit1@bandit:/home$ ls
bandit0   bandit14  bandit2   bandit25      bandit29      bandit31-git  bandit7    behemoth3  drifter0   drifter15  drifter7     formulaone3  krypton4    leviathan2  manpage0  manpage6  maze4  narnia0  narnia6  utumno1  utumno7   vortex12  vortex18  vortex23  vortex6
bandit1   bandit15  bandit20  bandit26      bandit29-git  bandit32      bandit8    behemoth4  drifter1   drifter2   drifter8     formulaone5  krypton5    leviathan3  manpage1  manpage7  maze5  narnia1  narnia7  utumno2  utumno8   vortex13  vortex19  vortex24  vortex7
bandit10  bandit16  bandit21  bandit27      bandit3       bandit33      bandit9    behemoth5  drifter10  drifter3   drifter9     formulaone6  krypton6    leviathan4  manpage2  maze0     maze6  narnia2  narnia8  utumno3  vortex0   vortex14  vortex2   vortex25  vortex8
bandit11  bandit17  bandit22  bandit27-git  bandit30      bandit4       behemoth0  behemoth6  drifter12  drifter4   formulaone0  krypton1     krypton7    leviathan5  manpage3  maze1     maze7  narnia3  narnia9  utumno4  vortex1   vortex15  vortex20  vortex3   vortex9
bandit12  bandit18  bandit23  bandit28      bandit30-git  bandit5       behemoth1  behemoth7  drifter13  drifter5   formulaone1  krypton2     leviathan0  leviathan6  manpage4  maze2     maze8  narnia4  ubuntu   utumno5  vortex10  vortex16  vortex21  vortex4
bandit13  bandit19  bandit24  bandit28-git  bandit31      bandit6       behemoth2  behemoth8  drifter14  drifter6   formulaone2  krypton3     leviathan1  leviathan7  manpage5  maze3     maze9  narnia5  utumno0  utumno6  vortex11  vortex17  vortex22  vortex5
bandit1@bandit:/home$ file
Usage: file [-bcCdEhikLlNnprsSvzZ0] [--apple] [--extension] [--mime-encoding]
            [--mime-type] [-e <testname>] [-F <separator>]  [-f <namefile>]
            [-m <magicfiles>] [-P <parameter=value>] [--exclude-quiet]
            <file> ...
       file -C [-m <magicfiles>]
       file [--help]
bandit1@bandit:/home$ du bandit1
20      bandit1
bandit1@bandit:/home$ cat 20
cat: 20: No such file or directory
bandit1@bandit:/home$ cd 20
-bash: cd: 20: No such file or directory
bandit1@bandit:/home$ du 20
du: cannot access '20': No such file or directory
bandit1@bandit:/home$ file 20
20: cannot open `20' (No such file or directory)
bandit1@bandit:/home$ cat bandit2
cat: bandit2: Is a directory
bandit1@bandit:/home$ cd bandit2
bandit1@bandit:/home/bandit2$ ls
--spaces in this filename--
bandit1@bandit:/home/bandit2$ cat --spaces in this filename--
cat: unrecognized option '--spaces'
Try 'cat --help' for more information.
bandit1@bandit:/home/bandit2$ cat --spaces in this filename--
cat: unrecognized option '--spaces'
Try 'cat --help' for more information.
bandit1@bandit:/home/bandit2$ 
bandit1@bandit:/home/bandit2$ cat --spacesinthisfilename-
cat: unrecognized option '--spacesinthisfilename-'
Try 'cat --help' for more information.
bandit1@bandit:/home/bandit2$ file --spaces in this filename-
file: unrecognized option '--spaces'
Usage: file [-bcCdEhikLlNnprsSvzZ0] [--apple] [--extension] [--mime-encoding]
            [--mime-type] [-e <testname>] [-F <separator>]  [-f <namefile>]
            [-m <magicfiles>] [-P <parameter=value>] [--exclude-quiet]
            <file> ...
       file -C [-m <magicfiles>]
       file [--help]
bandit1@bandit:/home/bandit2$ du --spaces in this filename--
du: unrecognized option '--spaces'
Try 'du --help' for more information.
bandit1@bandit:/home/bandit2$ find spaces in this filename
find: ‘spaces’: No such file or directory
find: ‘in’: No such file or directory
find: ‘this’: No such file or directory
find: ‘filename’: No such file or directory
bandit1@bandit:/home/bandit2$ find --spaces in this filename-
find: unknown predicate `--spaces'
bandit1@bandit:/home/bandit2$ find --spaces--in--this--filename--
find: unknown predicate `--spaces--in--this--filename--'
bandit1@bandit:/home/bandit2$ cat spaces
cat: spaces: No such file or directory
bandit1@bandit:/home/bandit2$ æs
æs: command not found
bandit1@bandit:/home/bandit2$ ls
--spaces in this filename--
bandit1@bandit:/home/bandit2$ cat filename
cat: filename: No such file or directory
bandit1@bandit:/home/bandit2$ cat bandit2
cat: bandit2: No such file or directory
bandit1@bandit:/home/bandit2$ find bandit2
find: ‘bandit2’: No such file or directory
bandit1@bandit:/home/bandit2$ find --spacesinthisfilename--
find: unknown predicate `--spacesinthisfilename--'
bandit1@bandit:/home/bandit2$ cat spacesinthisfilename
cat: spacesinthisfilename: No such file or directory
bandit1@bandit:/home/bandit2$ find ./
./
./.bash_logout
./.bashrc
./--spaces in this filename--
./.profile
bandit1@bandit:/home/bandit2$ find ./-
find: ‘./-’: No such file or directory
bandit1@bandit:/home/bandit2$ cat ./-
cat: ./-: No such file or directory
bandit1@bandit:/home/bandit2$ cat - ./
^C  
bandit1@bandit:/home/bandit2$ cat ./-~
cat: ./-~: No such file or directory
bandit1@bandit:/home/bandit2$ 
bandit1@bandit:/home/bandit2$ 
bandit1@bandit:/home/bandit2$ 
bandit1@bandit:/home/bandit2$ 
bandit1@bandit:/home/bandit2$ 
bandit1@bandit:/home/bandit2$ 
bandit1@bandit:/home/bandit2$ cat < -
-bash: -: No such file or directory
bandit1@bandit:/home/bandit2$ cd bandit1
-bash: cd: bandit1: No such file or directory
bandit1@bandit:/home/bandit2$ ls
--spaces in this filename--
bandit1@bandit:/home/bandit2$ cd /home
bandit1@bandit:/home$ cd /bandit1
-bash: cd: /bandit1: No such file or directory
bandit1@bandit:/home$ /cd
-bash: /cd: No such file or directory
bandit1@bandit:/home$ cd
bandit1@bandit:~$ s
s: command not found
bandit1@bandit:~$ cat < -
263JGJPfgU6LtdEvgfWU1XP5yac29mFx
bandit1@bandit:~$ 

BANDIT 2

┌──(kali㉿kali)-[~]
└─$ ssh bandit2@bandit.labs.overthewire.org -p 2220 
                         _                     _ _ _   
                        | |__   __ _ _ __   __| (_) |_ 
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_ 
                        |_.__/ \__,_|_| |_|\__,_|_|\__|
                                                       

                      This is an OverTheWire game server. 
            More information on http://www.overthewire.org/wargames

backend: gibson-1
bandit2@bandit.labs.overthewire.org's password: 

      ,----..            ,----,          .---.
     /   /   \         ,/   .`|         /. ./|
    /   .     :      ,`   .'  :     .--'.  ' ;
   .   /   ;.  \   ;    ;     /    /__./ \ : |
  .   ;   /  ` ; .'___,/    ,' .--'.  '   \' .
  ;   |  ; \ ; | |    :     | /___/ \ |    ' '
  |   :  | ; | ' ;    |.';  ; ;   \  \;      :
  .   |  ' ' ' : `----'  |  |  \   ;  `      |
  '   ;  \; /  |     '   :  ;   .   \    .\  ;
   \   \  ',  /      |   |  '    \   \   ' \ |
    ;   :    /       '   :  |     :   '  |--"
     \   \ .'        ;   |.'       \   \ ;
  www. `---` ver     '---' he       '---" ire.org


Welcome to OverTheWire!

If you find any problems, please report them to the #wargames channel on
discord or IRC.

--[ Playing the games ]--

  This machine might hold several wargames.
  If you are playing "somegame", then:

    * USERNAMES are somegame0, somegame1, ...
    * Most LEVELS are stored in /somegame/.
    * PASSWORDS for each level are stored in /etc/somegame_pass/.

  Write-access to homedirectories is disabled. It is advised to create a
  working directory with a hard-to-guess name in /tmp/.  You can use the
  command "mktemp -d" in order to generate a random and hard to guess
  directory in /tmp/.  Read-access to both /tmp/ is disabled and to /proc
  restricted so that users cannot snoop on eachother. Files and directories
  with easily guessable or short names will be periodically deleted! The /tmp
  directory is regularly wiped.
  Please play nice:

    * don't leave orphan processes running
    * don't leave exploit-files laying around
    * don't annoy other players
    * don't post passwords or spoilers
    * again, DONT POST SPOILERS!
      This includes writeups of your solution on your blog or website!

--[ Tips ]--

  This machine has a 64bit processor and many security-features enabled
  by default, although ASLR has been switched off.  The following
  compiler flags might be interesting:

    -m32                    compile for 32bit
    -fno-stack-protector    disable ProPolice
    -Wl,-z,norelro          disable relro

  In addition, the execstack tool can be used to flag the stack as
  executable on ELF binaries.

  Finally, network-access is limited for most levels by a local
  firewall.

--[ Tools ]--

 For your convenience we have installed a few useful tools which you can find
 in the following locations:

    * gef (https://github.com/hugsy/gef) in /opt/gef/
    * pwndbg (https://github.com/pwndbg/pwndbg) in /opt/pwndbg/
    * gdbinit (https://github.com/gdbinit/Gdbinit) in /opt/gdbinit/
    * pwntools (https://github.com/Gallopsled/pwntools)
    * radare2 (http://www.radare.org/)

--[ More information ]--

  For more information regarding individual wargames, visit
  http://www.overthewire.org/wargames/

  For support, questions or comments, contact us on discord or IRC.

  Enjoy your stay!

bandit2@bandit:~$ ls
--spaces in this filename--
bandit2@bandit:~$ cd
bandit2@bandit:~$ cd --spaces in this filename--
-bash: cd: --: invalid option
cd: usage: cd [-L|[-P [-e]] [-@]] [dir]
bandit2@bandit:~$ s
s: command not found
bandit2@bandit:~$ cd [-L|[-P [-e]] [-@]] [dir]
-bash: cd: [-L: No such file or directory
[-P: command not found
bandit2@bandit:~$ cd -L
bandit2@bandit:~$ cd [-L]
-bash: cd: [-L]: No such file or directory
bandit2@bandit:~$ cat [-L]
cat: '[-L]': No such file or directory
bandit2@bandit:~$ find
.
./.bash_logout
./.bashrc
./--spaces in this filename--
./.profile
bandit2@bandit:~$ find ./.profile
./.profile
bandit2@bandit:~$ cd ./.profile
-bash: cd: ./.profile: Not a directory
bandit2@bandit:~$ du ./.profile
4       ./.profile
bandit2@bandit:~$ s
s: command not found
bandit2@bandit:~$ cd ./.bash_logout
-bash: cd: ./.bash_logout: Not a directory
bandit2@bandit:~$ cd ./--spaces in this filename--
-bash: cd: too many arguments
bandit2@bandit:~$ cd spacesinthisfilename
-bash: cd: spacesinthisfilename: No such file or directory
bandit2@bandit:~$ cat --spaces in this filename--
cat: unrecognized option '--spaces'
Try 'cat --help' for more information.
bandit2@bandit:~$ ls
--spaces in this filename--
bandit2@bandit:~$ cd
bandit2@bandit:~$ cd --spaces in this filename-
-bash: cd: --: invalid option
cd: usage: cd [-L|[-P [-e]] [-@]] [dir]
bandit2@bandit:~$ cd dir
-bash: cd: dir: No such file or directory
bandit2@bandit:~$ cd e
-bash: cd: e: No such file or directory
bandit2@bandit:~$ dir -P
dir: invalid option -- 'P'
Try 'dir --help' for more information.
bandit2@bandit:~$ cd LPe@dir
-bash: cd: LPe@dir: No such file or directory
bandit2@bandit:~$ find dir
find: ‘dir’: No such file or directory
bandit2@bandit:~$ ls
--spaces in this filename--
bandit2@bandit:~$ cd --LPe@dir
-bash: cd: --: invalid option
cd: usage: cd [-L|[-P [-e]] [-@]] [dir]
bandit2@bandit:~$ cd
bandit2@bandit:~$ cd
bandit2@bandit:~$ cd s
-bash: cd: s: No such file or directory
bandit2@bandit:~$ cat dir
cat: dir: No such file or directory
bandit2@bandit:~$ cat -@
cat: invalid option -- '@'
Try 'cat --help' for more information.
bandit2@bandit:~$ cat -e
s
s$
^X^C
bandit2@bandit:~$ cat -et
^C
bandit2@bandit:~$ cat -P
cat: invalid option -- 'P'
Try 'cat --help' for more information.
bandit2@bandit:~$ cat -L
cat: invalid option -- 'L'
Try 'cat --help' for more information.
bandit2@bandit:~$ ls
--spaces in this filename--
bandit2@bandit:~$ find spcaes
find: ‘spcaes’: No such file or directory
bandit2@bandit:~$ find in
find: ‘in’: No such file or directory
bandit2@bandit:~$ find this
find: ‘this’: No such file or directory
bandit2@bandit:~$ find filename
find: ‘filename’: No such file or directory
bandit2@bandit:~$ cd filename
-bash: cd: filename: No such file or directory
bandit2@bandit:~$ find filename
find: ‘filename’: No such file or directory
bandit2@bandit:~$ find cd
find: ‘cd’: No such file or directory
bandit2@bandit:~$ find LP
find: ‘LP’: No such file or directory
bandit2@bandit:~$ ls
--spaces in this filename--
bandit2@bandit:~$ cat --filename--
cat: unrecognized option '--filename--'
Try 'cat --help' for more information.
bandit2@bandit:~$ cat spaces
cat: spaces: No such file or directory
bandit2@bandit:~$ cat in
cat: in: No such file or directory
bandit2@bandit:~$ cat this
cat: this: No such file or directory
bandit2@bandit:~$ cat filename
cat: filename: No such file or directory
bandit2@bandit:~$ cd spaces
-bash: cd: spaces: No such file or directory
bandit2@bandit:~$ cat "spaces in this filename"
cat: 'spaces in this filename': No such file or directory
bandit2@bandit:~$ cat spaces\ in\ this\ filename
cat: 'spaces in this filename': No such file or directory
bandit2@bandit:~$ cat spaces\ in\ this\ filename
cat: 'spaces in this filename': No such file or directory
bandit2@bandit:~$ cat "spaces in this filename"
cat: 'spaces in this filename': No such file or directory
bandit2@bandit:~$ cat "spaces in this filename"
cat: 'spaces in this filename': No such file or directory
bandit2@bandit:~$ cat ./-
cat: ./-: No such file or directory
bandit2@bandit:~$ cat __spaces in this filename__
cat: __spaces: No such file or directory
cat: in: No such file or directory
cat: this: No such file or directory
cat: filename__: No such file or directory
bandit2@bandit:~$ find __spaces in this filename__
find: ‘__spaces’: No such file or directory
find: ‘in’: No such file or directory
find: ‘this’: No such file or directory
find: ‘filename__’: No such file or directory
bandit2@bandit:~$ ls
--spaces in this filename--
bandit2@bandit:~$ ^C
bandit2@bandit:~$ exit
logout
Connection to bandit.labs.overthewire.org closed.
                                                                                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ ssh bandit2@bandit.labs.overthewire.org -p 2220
                         _                     _ _ _   
                        | |__   __ _ _ __   __| (_) |_ 
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_ 
                        |_.__/ \__,_|_| |_|\__,_|_|\__|
                                                       

                      This is an OverTheWire game server. 
            More information on http://www.overthewire.org/wargames

backend: gibson-1
bandit2@bandit.labs.overthewire.org's password: 
Permission denied, please try again.
bandit2@bandit.labs.overthewire.org's password: 

      ,----..            ,----,          .---.
     /   /   \         ,/   .`|         /. ./|
    /   .     :      ,`   .'  :     .--'.  ' ;
   .   /   ;.  \   ;    ;     /    /__./ \ : |
  .   ;   /  ` ; .'___,/    ,' .--'.  '   \' .
  ;   |  ; \ ; | |    :     | /___/ \ |    ' '
  |   :  | ; | ' ;    |.';  ; ;   \  \;      :
  .   |  ' ' ' : `----'  |  |  \   ;  `      |
  '   ;  \; /  |     '   :  ;   .   \    .\  ;
   \   \  ',  /      |   |  '    \   \   ' \ |
    ;   :    /       '   :  |     :   '  |--"
     \   \ .'        ;   |.'       \   \ ;
  www. `---` ver     '---' he       '---" ire.org


Welcome to OverTheWire!

If you find any problems, please report them to the #wargames channel on
discord or IRC.

--[ Playing the games ]--

  This machine might hold several wargames.
  If you are playing "somegame", then:

    * USERNAMES are somegame0, somegame1, ...
    * Most LEVELS are stored in /somegame/.
    * PASSWORDS for each level are stored in /etc/somegame_pass/.

  Write-access to homedirectories is disabled. It is advised to create a
  working directory with a hard-to-guess name in /tmp/.  You can use the
  command "mktemp -d" in order to generate a random and hard to guess
  directory in /tmp/.  Read-access to both /tmp/ is disabled and to /proc
  restricted so that users cannot snoop on eachother. Files and directories
  with easily guessable or short names will be periodically deleted! The /tmp
  directory is regularly wiped.
  Please play nice:

    * don't leave orphan processes running
    * don't leave exploit-files laying around
    * don't annoy other players
    * don't post passwords or spoilers
    * again, DONT POST SPOILERS!
      This includes writeups of your solution on your blog or website!

--[ Tips ]--

  This machine has a 64bit processor and many security-features enabled
  by default, although ASLR has been switched off.  The following
  compiler flags might be interesting:

    -m32                    compile for 32bit
    -fno-stack-protector    disable ProPolice
    -Wl,-z,norelro          disable relro

  In addition, the execstack tool can be used to flag the stack as
  executable on ELF binaries.

  Finally, network-access is limited for most levels by a local
  firewall.

--[ Tools ]--

 For your convenience we have installed a few useful tools which you can find
 in the following locations:

    * gef (https://github.com/hugsy/gef) in /opt/gef/
    * pwndbg (https://github.com/pwndbg/pwndbg) in /opt/pwndbg/
    * gdbinit (https://github.com/gdbinit/Gdbinit) in /opt/gdbinit/
    * pwntools (https://github.com/Gallopsled/pwntools)
    * radare2 (http://www.radare.org/)

--[ More information ]--

  For more information regarding individual wargames, visit
  http://www.overthewire.org/wargames/

  For support, questions or comments, contact us on discord or IRC.

  Enjoy your stay!

bandit2@bandit:~$ cat ./-
cat: ./-: No such file or directory
bandit2@bandit:~$ ls
--spaces in this filename--
bandit2@bandit:~$ cat "spaces in this filename"
cat: 'spaces in this filename': No such file or directory
bandit2@bandit:~$ cd inhere
-bash: cd: inhere: No such file or directory
bandit2@bandit:~$ ls -a
.  ..  .bash_logout  .bashrc  .profile  --spaces in this filename--
bandit2@bandit:~$ cd .bash_logout
-bash: cd: .bash_logout: Not a directory
bandit2@bandit:~$ cd .bashrc
-bash: cd: .bashrc: Not a directory
bandit2@bandit:~$ cd .profile
-bash: cd: .profile: Not a directory
bandit2@bandit:~$ cd "spaces in this filename
> ^C
bandit2@bandit:~$ cd "spaces in this filename"
-bash: cd: spaces in this filename: No such file or directory
bandit2@bandit:~$ cd -bash
-bash: cd: -b: invalid option
cd: usage: cd [-L|[-P [-e]] [-@]] [dir]
bandit2@bandit:~$ cd -L
bandit2@bandit:~$ cd -P
bandit2@bandit:~$ cd -E
-bash: cd: -E: invalid option
cd: usage: cd [-L|[-P [-e]] [-@]] [dir]
bandit2@bandit:~$ cd -@
-bash: cd: -@: invalid option
cd: usage: cd [-L|[-P [-e]] [-@]] [dir]
bandit2@bandit:~$ cd dir
-bash: cd: dir: No such file or directory
bandit2@bandit:~$ cd [-L]
-bash: cd: [-L]: No such file or directory
bandit2@bandit:~$ cd [-P]
-bash: cd: [-P]: No such file or directory
bandit2@bandit:~$ cd [-e]]
-bash: cd: [-e]]: No such file or directory
bandit2@bandit:~$ cd [-@]]
-bash: cd: [-@]]: No such file or directory
bandit2@bandit:~$ cd [dir]
-bash: cd: [dir]: No such file or directory
bandit2@bandit:~$ cat spaces/ in/ this/ filename
cat: spaces/: No such file or directory
cat: in/: No such file or directory
cat: this/: No such file or directory
cat: filename: No such file or directory
bandit2@bandit:~$ cat "spaces in this filename"
cat: 'spaces in this filename': No such file or directory
bandit2@bandit:~$ cat 'spaces in this filename'
cat: 'spaces in this filename': No such file or directory
bandit2@bandit:~$ cat space/ in / this/ filename
cat: space/: No such file or directory
cat: in: No such file or directory
cat: /: Is a directory
cat: this/: No such file or directory
cat: filename: No such file or directory
bandit2@bandit:~$ cat spaces/ in/ this/ filename
cat: spaces/: No such file or directory
cat: in/: No such file or directory
cat: this/: No such file or directory
cat: filename: No such file or directory
bandit2@bandit:~$ ls -l
total 4
-rw-r----- 1 bandit3 bandit2 33 Oct 14 09:26 --spaces in this filename--
bandit2@bandit:~$ cat 'spaces in this filename'
cat: 'spaces in this filename': No such file or directory
bandit2@bandit:~$ cat spaces\ in\ this\ filename
cat: 'spaces in this filename': No such file or directory
bandit2@bandit:~$ cat "spaces in this filename"
cat: 'spaces in this filename': No such file or directory
bandit2@bandit:~$ cat -- --spaces\ in\ this\ filename--
MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
bandit2@bandit:~$ 


