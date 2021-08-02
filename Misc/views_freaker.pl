#!/usr/bin/perl

# Views counter freaker
# by Giovanni Buzzin, "Osirys"
# osirys[at]autistici[dot]org

# The powerfull of this script depends by proxies used by it. If you find a site that
# provides better proxies, contact me ;)
# This little program just makes a lot of request to a page under different proxies.
# It's usefull if you want to see your views/clicks growing up
# Coded just for fun.

############################################################################
# PROOF
############################################################################
# osirys[~]>$ perl views_freaker.txt http://localhost/views.php
#
# -------------------------------
#      Views counter freaker
#            by Osirys
# -------------------------------
#
# [*] Getting proxies:
#        speedtest.at .. done.
#        samair.ru .. done.
# [*] Proxies downloaded !
# [*] Mixing now proxies ..
# [*] Mixed done ..
# [*] Cleaned ..
# [&] Counter freaker STARTED !
#
# [1/632]    Using proxy -> 220.227.138.82:8080
# [2/632]    Using proxy -> 118.98.169.12:3128
# [3/632]    Using proxy -> 195.101.116.12:80
# [4/632]    Using proxy -> 203.162.183.222:80
# [5/632]    Using proxy -> 218.4.65.118:8080
# [6/632]    Using proxy -> 203.149.32.30:8080
#  .....
# osirys[~]>
############################################################################



use HTTP::Request;
use LWP::UserAgent;

my $host          = $ARGV[0];
my $sleep_limit   = 3; # This is the limit of the random sleep between each request to the target (Protection to be not detected)
my $proxy_timeout = 5; # Limit of proxy request timeout. This is an high value, because the intent of this script is not to be
                       # fast, but working. Putting here a low number, it means that if the script is making a request under a low
                       # proxy, it will then not use it. Putting an higher number, will use the major of proxies.

($host) || die "[-] Usage: perl $0 http://site/page.php\n\n";

print "\n".
      "-------------------------------\n".
      "     Views counter freaker     \n".
      "           by Osirys           \n".
      "-------------------------------\n\n";

print "[*] Getting proxies:\n";
print "       speedtest.at ..";

# I put 450 (450:25=18), so 18 pages as limit, put how much you want (must be a multiple of 25)
# This website is good, it provides different proxies on each new request

for ($i = 0;$i <= 450;$i += 25) {
    my $link = "http://proxy.speedtest.at/proxybyActuality.php?offset=".$i;
    my $re = query($link);
    while ($re =~ m/<td align=left><b>([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]{1,6})<\/b>/g) {
        my $prox = $1.".".$2.".".$3.".".$4.":".$5;
        push(@proxies_a, $prox);
    }
}

print " done.\n";
print "       samair.ru ..";

# I put 10 as limit. So it searchs on 10 pages

for ($i = 1;$i<=10;$i++) {
    my $a = $i;
    if ($a =~ /[0-9]{1}/) {
        $a =~ s/$a/0$a/;
    }
    my $link = "http://www.samair.ru/proxy/proxy-".$a.".htm";
    my $re = query($link);
    while ($re =~ m/<tr><td>([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]{1,6})<\/td><td>/g) {
        my $prox = $1.".".$2.".".$3.".".$4.":".$5;
        push(@proxies_b, $prox);
    }
}

print " done.\n";
print "[*] Proxies downloaded !\n";
print "[*] Mixing now proxies ..\n";

# Starts here the "mixing" and cleaning function
# A mix to mix proxies coming from different sites
# A clean to remove double proxies

my $count = -1;
while ((my $y = @proxies_a)&&($stop != 1)) {
    $count++;
    if ($count =~ /(.*)(0|2|4|6|8)$/) {
        push(@f_proxies,$proxies_a[$count]);
        if ($count <= $#proxies_b) {
            push(@f_proxies,$proxies_b[$count]);
        }
    }
    else {
        push(@f_proxies,$proxies_a[$count]);
        if ($count <= $#proxies_b) {
            push(@f_proxies,$proxies_b[$count]);
        }
    }
    if ($count == $#proxies_a) {
        $stop = 1;
    }
}

if ($#proxies_a < $#proxies_b) {
    push(@f_proxies, @proxies_b[$#proxies_a+1..$#proxies_b]);
}

my $counts = -1;
my @ff_proxies;
foreach my $e(@f_proxies) {
    $counts++;
    $back = look($e,$counts);
    if ($back != 1) {
        push(@ff_proxies,$e);
    }
}

sub look() {
    my $e = $_[0];
    my $pos = $_[1];
    my $counter = -1;
    foreach my $el(@f_proxies) {
        $counter++;
        if ($el eq $e){
            if ($counter > $pos) {
                $found = 1;
                return($found);
            }
        }
    }
}

# end of "mixing" and cleaning function

print "[*] Mixed done ..\n";
print "[*] Cleaned ..\n";
print "[&] Counter freaker STARTED !\n\n";

my $start = 1;
my $tot   = scalar(@ff_proxies);
my $proxy_ = 1;

foreach my $p(@ff_proxies) {
    if ($start <= 9){
        print "[$start"."/"."$tot]    Using proxy -> $p\n";
    }
    elsif (($start >= 10)&&($start <= 99)) {
        print "[$start"."/"."$tot]   Using proxy -> $p\n";
    }
    elsif (($start >= 100)&&($start <= 999)) {
        print "[$start"."/"."$tot]  Using proxy -> $p\n";
    }
    else {
        print "[$start"."/"."$tot] Using proxy -> $p\n";
    }
    my $sleep = int(rand $sleep_limit);
    &query($host,$p);
    sleep($sleep);
    $start++;
}

print "\n[!] Done\n\n";
exit(0);

sub query() {
    my($link,$proxyz) = ($_[0],$_[1]);
    my $req = HTTP::Request->new(GET => $link);
    my $ua = LWP::UserAgent->new();
    if ($proxy_ == 1) {
        $ua->proxy('http', "http://".$proxyz);
        $ua->timeout($proxy_timeout);
        $ua->request($req);
    }
    else {
        $ua->timeout(3);
        $response = $ua->request($req);
        return($response->content);
    }
}