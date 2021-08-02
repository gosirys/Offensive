v5.01 Irc-Scanner Private

Functions and particularity:

 1)Remote File Inclusion Scanner (RFI)
 2)Local File Inclusion Scanner (LFI)
 3)SQL Injection Scanner (SQL INJ)
 4)Mass Scan, which will scan on 14 different google domains, using foreach one the own language and country mode. It will make the same thing with yahoo and      alltheweb
 5)Integrated Shell, so you can give commands on the server where the Bot is launched from. If secuirty Mode is On, you will have to query the Bot, and use a
   special password (which is set in the source), to give it commands
 6)Spread on single RFI Vulnerable Host
 7)Spread on all the RFI Vulnerable Host found by the Scanner (If Spread mode is Enabled)
 8)Spread Mode, so you can choose to enable the Spread Mode or not, from source code and from the main channel too.
 9)Secuirty Mode, so you can choose to protect "dangerous" functions of te Bot, from source code and from the main channel too.
 10)Get the last 10 bugs of RFI,LFI and SQL Injection from a file 
 11)The Scanner will be controlled in the main channel, set in the source with the variable $chan1, and all the results will be printed in a secondary channel,
    so you can collect all the results in a secondary channel, set in the source with the variable $chan2
 12)In all scan type, you will have to set a -p number. It means that, foreach site to test, will be create a new process, and after a number of sites, which
    is set by you with the strin -p number, the bot will wait for the exit of the process created. So if you put -p 10, foreach sites the bot will use a new
    process, and will wait foreach 10 sites the exiting of the process created. What means this? If you are scanning on a very good bug, like a 0day, you will
    find a lot of vulnerable host, so to don't go in a excess flood, you will have to put a low number, like 10 or less, but the scan will be a bit slower.
    Instead, if you are scanning on a "normal" bug, so not a lot of results, u can put  like 100 as number, so you will not go in excess flood, (because there
    will be not a lot of results to print in the channels), and the scan will be faster.
 13)Kill, you can kill the bot when you want, and if Security Mode is On, you will have to query the Bot, and use a special password (which is set in the source)
    to kill it. The Bot will close the Irc connection, and will be killed all the perl process
 14)Before scan, you can cheek if the RFI Response works
 15)You can change the RFI-Response from the mian channel too (if Sec Mode is OFF) or querying the Bot (if Sec Mode is ON)
 16)BYPASS FUNCTION: If during the scan Google or Yahoo will ban the ip of the Bot, it will scan on engines that use the same bot, and search type, of the main
    ones.
 17)SEARCH ENGINES: Google, Yahoo, AllTheWeb, Msn, Ask, Altavista, Aol, Uol, Web.de, Einet, DmoZ.

* For a properly work of the Bot, it require to be launched on Linux or Unix derivated Box. Because some functions (which some are very important) use Linux Bash
 commands

###################################################################################################################################################################
###These are the features. Now i'm gonna to explain all of them.


1)To scan on RFI Bug on a cms, you will have to write in the Channel: !rfi bug dork -p sites/process

2)To scan on LFI Bug on a cms, you will have to write in the Channel: !lfi bug dork -p sites/process

3)To scan on SQL Injection Bug on a cms, you will have to write in the Channel: !sql bug dork -p sites/process
  If the number set in the -p number is 1, the bot will print the Hash and the Password too.

4)The Mass Google Scan will scan on:
   1)google.at
   2)google.com.au
   3)google.com.br
   4)google.ca
   5)google.ch
   6)google.cn
   7)google.de
   8)google.dk
   9)google.es
   10)google.fr
   11)google.it
   12)google.co.jp
   13)google.com.mx
   14)google.co.uk
  Foreach domain, the Bot will search the domain and the related language and country, so you will find .at sites, .com.au sites, .com.br sites etc.
  To use this scan type: !gmass[rfi/lfi/sql] bug dork -p site/process
  So to scan RFI bug, you will write: !gmass[rfi] bug dork -p sites/process
 THE SAME FOR YAHOO AND ALLTHEWEB

5)If Security Mode is Off, you can give commands to the server directly from the channel. Like: !cmd id, !cmd uname -a
  If Security Mode is On, to execute commands on the server, you will have to query the Bot, and write: !cmd command_to_execute -p password

6)If you have a host vulnerable to RFI, you can spread on it. Ex: Vuln Host and bug: www.site.com/file.php?bug= . You will write: 
  !SSpread www.site.com/file.php?bug=
  And then the Bot will try to Spread on it

8)You can choose to enable the Spread mode from the source, or from the channel. If Spread mode if enabled, the bot will spread on all the RFI results.
  Anyway, if Sec Mode is Off, to enable the spread mode you can write in the main chan: !Spread ON/OFF
  If Sec Mode is ON, you will have to query the nick, and write: !Spread ON/OFF -p password

9)The Secuirity Mode is made to protect the important functions, like kill the bot, enalbe/disbale the Spreading, executing commands on the server.
  To Enable or disable it, you can set it in the source, or querying the bot and writing then: !Sec ON/OFF -p password

10)When the website of the: Third Eye Secuirty will be finished, I will upload a file with the new RFI Bug, a file for the LFI and a file for the SQl Bugs.
   Writing in the chan: !new rfi bugs / !new lfi bugs / !new sql-inj bugs, you will see the last bugs updated by us. Anyway you can put the link you want
   in the source code

13)If Sec Mode is ON, to kill the Bot you will have to query it and write: !killme -p password
   If Sec Mode is Off, you can do it directly in the chan writing: !killme

14)The command to cheek if the RFI Response is working, wirte: !response. THIS RESPONSE IS very important for the RFI scan, becouse if the RFI Response will
   not work, you will never find a RFI result

15)To change the RFI Response, if Sec Mode is Off, you can do it in the main chan writing: !chid new_response
   If Sec Mode is ON, you will have to query the Bot and write: !chid new_response -p password

