```
yInjector v1.5 - SQL Injection Penetration Tool
```

# General Overview - v1.5 Release


yInjector is a SQL Injection penetration tool with many features available in order to make as simple as possible
the exploiting and dumping process of SQL Injections.


Main features available in v1.5 release:

* GET, POST, Cookie Requests and custom HTTP packets support
* Proxy Support
* Log Report option (v2.0 will support excel file format)


DBMS supported in v1.5

* MySQL
	* (v2.0 will support also: MSSQL)


# Exploitation methods

## Disclaimer
	
In case MySQL version is less than version 5, information_schema
won't be supported by the remote host.

information_schema DB is essential because it stores inside
all tables and columns name. Without this, unless the attacker
knows what columns from what table to extract, the exploitation
will fail.

v2.0 release will support :
a. In case mysql version < 5
		Table and Column name bruteforce attack: will try to guess
		useful table and column names.
		
Currently version (v1.5) supports Standard Injections only:
only SQL Injection that displays on the page the requested rows.

v2.0 release will support also :
a. Blind SQL Injection (Conditional)
b. Blind SQL Injection (Time based)
			
			
MSSQL *not* currently supported

v2.0 release will support:
a. Normal SQL Injection
b. Error based SQL Injection
c. Blind SQL Injection (Conditional)
d. Blind SQL Injection (Time based)
			


## Enumeration, Info, various Options available:
	
- DB name, RDBMS version, DB user
- Remote Host detection
- Magic Quotes status detection
- Load_File status detection
- Proxy support
- Log support
- Query Injections Bypass


## Columns finding:
	
Finds columns number to build an Injection p0c
The Injection creation process does also a lot of
tests on the columns of the SQL query:
there is the possibility in fact that certain column
have a length limit in the row to print, and because
of this is possible that the result gets cut and so
will be displayed only partially.
To avoid this, yInjector tests which columns is more
suitable avoiding broken information and problems
in the matching process.
			

## Complete exploitation:
	
After a parameter is given to the yInjector, it will
start to enumerate the columns of the select query
in order to build a full working SQL Injection with
the Columns finding step.
After that, the Dump process will start.
			

## Dump process:
	
The dump process is the core of this software.
Many are the options allowed.
In case the user on the SQL server has enough
privileges, the software will try to get all
databases hosted at the remote host.

From the option that can be chosen by the attacker,
the yInjector can automatically extracts :

1. All tables of a selected DB
2. All columns of a selected table of a selected DB
3. Selected columns of a selected table of a selected DB

In addition, the yInjector allows the attacker to create
and run his own customized query from a SQL console box.
			

## Extra features:

a. Local File access:
If possible, yInjector tries to load local files

MySQL :
	Uses load_file (hex converted to bypass MQ restrictions)
	Linux and Windows supp 

b. Hash cracker:
	In case of need to crack a MD5 hash, yInjector
	will try to consult the better online MD5 databases
	to crack the MD5 hash provided
			
c. Command Execution:

On MySQL :

In case Magic Quotes are disabled, yInjector provides
2 ways to get a Shell on the remote Host:

a. User provided:
	In case the attacker knows the internal file system path,
	yInjector will use it to create a file on the remote system,
	a backdoor that will spawn a shell.
	
b. Automated:
	In case the attacker does not know the internal file system path,
	yInjector will use a trick discovered by Giovanni Buzzin that
	will try to find the internal path by itself using load_file
	on Apache error logs.
	Once and only if the path has been found, the tool will use it
	to create a file on the remote system, a backdoor that will spawn
	a shell.
	\*b
	
Limits :
1. Magic Quotes has to be OFF.
2. User must have enough privileges to write files on the system

\*b. Apache error log path has to be found, otherwise yInjector won't
    be able to load the error file in order to get the internal path. 

On MSSQL :

(supported in the v2 release)
		
d. SQL query interactive box
	
yInjector provides an SQL query box to allow the user to perform his own
SQL query


