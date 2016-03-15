#!/usr/bin/perl -w

use utf8;
use strict;
use warnings;
#my $threadsAvailable = eval 'use threads; use threads::shared; use Thread::Semaphore; 1';
my $threadsAvailable = eval 'use threads; use threads::shared; 1';
use utf8;
use Net::Ping;
#use Net::Ping::External; # for none root users (ping)
use URI::Escape;
use Net::Wake; # WOL feature
use Socket;    # for none root users (get IP)
use POSIX qw(strftime);
use CGI;       # load CGI routines
#use CGI::Pretty; # load CGI routines with pretty print
use CGI::Carp qw(fatalsToBrowser);


my $types = {
			router  => {idx => 10, img => 'router.png'},
			switch  => {idx => 15, img => 'switch.png'},
			wlan    => {idx => 20, img => 'wlan.png'},
			server  => {idx => 30, img => 'server.png'},
			nas     => {idx => 35, img => 'nas.png'},
			printer => {idx => 40, img => 'printer.png'}, 
			tv      => {idx => 55, img => 'tv.png'},
			rpi     => {idx => 58, img => 'rpi.png'},
			android => {idx => 60, img => 'android.png'},
			client  => {idx => 60, img => 'client.png'},
			laptop  => {idx => 58, img => 'laptop.png'},
		};

# host pattern: <idx for NATed systems>+<host name>:<port>[<MAC address for WOL>]|<alias>
my $data = {
			'LAN' => {
						-idx    => 10,
						-domain => 'example.lan',
						router  => [qw /www/],
						switch  => [qw /switch/],
						wlan    => [qw /accesspoint/], 
						server  => [qw /server webserver:80/],
						nas     => [qw /nas:22/],
						printer => [qw /net-printer/],
						tv      => [qw /tv chromecast/],
						rpi     => [qw /pi-dev/],
						android => [qw /smartphone/],
						laptop  => [qw /laptip[00:11:22:33:44:55]/],
						client  => [qw /desktop[11:22:33:44:55:66]/],
					},
			'WAN' => {
						-idx    => 20,
						-domain => 'example.com',
						router  => [qw /1+webgate/],
						server  => [qw /2+webgate:22|Server/],
						nas     => [qw /storage|NAS/],
						
					},
		};



(my $scriptDir = $0) =~ s{^(.*?[\\/])([^\\/]+)$}{$1};
my $scriptName = $2||'';
my $q; #CGI page
my $imgRoot = "img/64/";
my $imgOk   = "$scriptName?id=ok.png";
my $imgFail = "$scriptName?id=fail.png";

my $start;
my $useThreads = ($threadsAvailable ? 1 : 0);
my $timeout = $useThreads ? 10 : 2;
my $timeoutWol = 20;
my $wolState;
my %pingHash;
$useThreads and eval 'share (%pingHash)';
my %ipHash;
$useThreads and eval 'share (%ipHash)';
my %ipErrorHash;
$useThreads and eval 'share (%ipErrorHash)';
my $p; # ping object

sub sendFile #($fileName)
{
	my $fileName = shift;
	
	unless ($fileName) {
		printHead ();
		print $q->p ("You have to specify a file to download.");
		printFoot ();
		return 0;
	}
	(my $ext = $fileName) =~ s/^.*?\.([^\.]+)$/$1/;
	my $file;
	my $contentType;
	if ($ext =~ m/css/i) {
		$file = "${scriptDir}$fileName";
		$contentType = "text/css";
	} else {
		$file = "${scriptDir}${imgRoot}$fileName";
		-f $file or $file = "${scriptDir}${imgRoot}fail.gif";
		$contentType = "image/$ext";
	}
	my $msg;
	open(SRC, "<$file") or $msg = $!;
	$msg and do {printHead (); print $q->p ("can't open image '$fileName': $msg"); printFoot (); return 0;};
	print "Content-Type:$contentType\n";
	print "\n";
	print <SRC>;
	close (SRC);
	return 1;
}

sub parseHostUri #($hostUri)
{
	my ($hostUri) = @_;
	$hostUri =~ m/^-/ and return;
	$hostUri =~ m/^(.*?)(?::(\d+))?(?:\[((?:[a-z\d]{2}:){5}[a-z\d]{2})\])?(?:\|(.+?))?$/i; # (<name>):(<port>)[(<mac>)]|<title>
	return ($1, $2, $3, $4);
}

sub wol #($mac)
{
	my ($mac) = @_;
	$mac or return;
	
	# http://search.cpan.org/~clintdw/Net-Wake-0.02/lib/Net/Wake.pm
	# Net::Wake::by_udp('255.255.255.255', '00:00:87:A0:8A:D2');
	return Net::Wake::by_udp ('255.255.255.255', $mac);
}

sub doWol #();
{
	my $qrystrg = $ENV{'QUERY_STRING'};
	if ($qrystrg) {
		my %qs;
		map {m/(.*)=(.*)/ and $qs{$1} = $2;} split(/&/, $qrystrg);
		
		if (exists $qs{mac} && $qs{mac}) {
			my $mac = uri_unescape ($qs{mac});
			$mac =~ /^\s*(([a-z\d]{2}[-:]){5}[a-z\d]{2})\s*$/i or return;
			($mac = $1) =~ s/-/:/g;
			$wolState = $mac;
			wol ($mac);
			sleep $timeoutWol;
			return 1;
		}
	}
	return;
}

sub sysPing #($hostOrIp, ?$timeout)
{
	my ($hostOrIp, $timeout) = @_;
	$timeout ||= 5;
	$hostOrIp =~ s/\.+$//g;
	
	my $pingPipe;
	open ($pingPipe, "ping -t $timeout -c 2 '$hostOrIp' 2>&1|") or do {print "<!-- sysPing for '$hostOrIp' failed: $? -->\n"; return;};
	if ($? == -1) {
		print "<!-- failed to execute: $! -->\n";
		return;
	} elsif ($? & 127) {
		printf "<!-- child died with signal %d, %s coredump -->\n",
		($? & 127),  ($? & 128) ? 'with' : 'without';
		return;
	} else {
		my $rc = $? >> 8;
		printf "<!-- child exited with value %d -->\n", $? >> 8;
		my $host;
		my $ip;
		my $ping = 100;
		my $dur;
		my $maxOut = 20;
		my $outCnt = 0;
		#my @out;
		while (<$pingPipe>) {
			chomp;
			#push @out, $_;
			/\bPING\s+\b($hostOrIp|[^\s]+)\b\s*\(((?:[\d]+\.){3}\d+)\)/i and $host = $1 and $ip = $2; # get host and ip from first line
			/(\d+)%\s*packet\s*loss/ and $ping = $1;
			/rtt\s*min\/avg\/max\/mdev\s*=\s*[\d\.]+\/([\d\.]+)\/[\d\.]+\/[\d\.]+\s*ms/i and $dur = $1;
			$outCnt++ > $maxOut and last; # break on endless ping
		}
		close $pingPipe;
		#use Data::Dumper;
		#print "<!-- ", Dumper (\@out), " -->";
		#print "<!--\nhost: $host\ndur:  $dur\nip:   $ip\nping: ".($ping < 100 ? 1 : 0)."\n  -->";
		#sleep 1;
		return (($ping < 100), $dur, $ip, $rc, $host);
	}
}
#die sysPing ('nautilus');

sub addIpHash #($ip, $fqdn)
{
	my ($ip, $fqdn) = @_;
	my $ignoreCname = ($fqdn =~ m/^CN\+/) ? 1 : 0;
	$fqdn =~ s/^(\d+|CN)\+//; # ignore same host with different port(NAT) or CNAME
	unless ($ignoreCname) {
		exists $ipHash{"$ip"} and $ipHash{"$ip"} =~ m/~~($fqdn)~~/i or $ipErrorHash{"$ip"}++;
	}
	$ipHash{"$ip"} .= "~~$fqdn~~";
	print "<!-- IP check: $ip\t$fqdn -->\n";
}

sub doPing #($hostUri, $domain, ?$semPing)
{
	my ($hostUri, $domain, $semPing) = @_;
	my ($host, $port, $mac, $title) = parseHostUri ($hostUri);
	my $ipHost = ($host =~ m/^\d+(\.\d+){3}$/);
	$domain = $ipHost ? "" : ($domain ? ".$domain" : "");
	
	my ($ping, $duration, $ip);
	eval {
		if ($host) {
			my $fqhn = $host.$domain;
			$fqhn =~ s/^(\d+|CN)\+//;
			if ($port) {
				eval {
					print "<!-- ping (tcp): $fqhn:$port -->\n";
					my $pp = Net::Ping->new ("tcp", 2);
					$pp->{port_num} = $port;
					($ping, $duration, $ip) = $pp->ping ($fqhn, $timeout);
					$pp->close ();
					$pp = undef;
				};
				if ($@) {
					print "<!-- ping (sys): $fqhn (port scan not available) -->\n";
					($ping, $duration, $ip) = sysPing ($fqhn, $timeout);
				}
			} else {
				#my $p = Net::Ping->new ("tcp", 2); # use echo
				eval {
					print "<!-- ping (net): $fqhn -->\n";
					my $p = Net::Ping->new ("icmp", 1);
					#my $p = Net::Ping->new ("syn", 1);
					#$p->{port_num} = 7;
					($ping, $duration, $ip) = $p->ping ($fqhn, $timeout);
					$p->close ();
					$p = undef;
				};
				if ($@) {
					print "<!-- ping (sys): $fqhn -->\n";
					($ping, $duration, $ip) = sysPing ($fqhn, $timeout);
				}
			}
		}
	};
	@! and print "<!-- ###### ERROR: @! -->\n";
	$ip       ||= "none";
	$duration ||= "";
	$host     ||= "";
	$domain   ||= "";
	$ping     ||= 0;
	print "<!-- checked:    $host$domain ".($ping ? "OK" : "FAIL")." (IP: $ip, $duration) -->\n";
	if ($useThreads) {
		#$semPing->down ();
		#lock %pingHash;
		$pingHash{"$host$domain"} = "$ping~#~$duration~#~$ip";
		#$ipHost or $ip and $pingHash{"$ip"}{"$host$domain"}++;
		$ip and addIpHash ("$ip", "$host$domain");
		#cond_signal (\%pingHash);
		#$semPing->up ();
		
		threads->exit (1);
	} else {
		$pingHash{"$host$domain"} = "$ping~#~$duration~#~$ip";
		#$ipHost or $ip and $pingHash{"$ip"}{"$host$domain"}++;
		$ip and addIpHash ("$ip", "$host$domain");
	}
	return 1;
}

sub pingHosts #()
{
	printHead ();
	#print $q->h1 ('Host list'), "\n"; # level 1 header
	
	#$p = Net::Ping->new ("tcp", 2); # use echo
	eval {
		$p = Net::Ping->new ("icmp", $timeout);
	};
	if ($@) {
		# fallback to external ping command
		$p = undef;
	}
	if ($useThreads) {
		my %threadHash;
		my $semPing;# = Thread::Semaphore->new();
		foreach my $domainKey (keys %$data) {
			my $domHash = $data->{$domainKey};
			my $domain = $domHash->{-domain};
			foreach my $type (keys %$types) {
				exists $domHash->{$type} or next;
				foreach my $hostUri (@{$domHash->{$type}}) {
					my $thr = threads->create (\&doPing, $hostUri, $domain, $semPing);
					$threadHash{$thr->tid ()} = $thr;
					#select(undef, undef, undef, 0.25);
				}
			}
		}
		print "<!-- joining threads -->\n";
		foreach my $thr (values %threadHash) {
			$thr->join ();
		}
		#while (scalar threads->list ()) {
		#	select (select, select, select, 0.2);
		#}
	}
	my @dSorted = (sort {$data->{$a}{-idx} <=> $data->{$b}{-idx}} keys %$data);
	my $tbl = [
			$q->th (['', @dSorted]),
		];
	
	foreach my $type (sort {$types->{$a}{idx} <=> $types->{$b}{idx}} keys %$types) {
		$useThreads or print "<!-- checking type: $type -->\n";
		my @cols;
		for (my $i = 0; $i < @dSorted; $i++) {
			$useThreads or print "<!--   checking domain: $dSorted[$i] -->\n";
	
			my $dHash = $data->{$dSorted[$i]};
			unless (exists $dHash->{$type}) {
				$useThreads or print "<!--     no hosts -->\n";
				push @{$cols[$i]}, '&nbsp;';
				next;
			}
			foreach my $hostUri (@{$dHash->{$type}}) {
				$hostUri =~ m/^-/ and next;
				my ($host, $port, $mac, $title) = parseHostUri ($hostUri);
				$useThreads or printf ("<!--     %-10s is ", $host);
				my ($ping, $duration, $ip);
				my $ipHost = ($host =~ m/^\d+(\.\d+){3}$/);
				my $domain = $ipHost ? "" : ($dHash->{-domain} ? ".$dHash->{-domain}" : "");
				if ($useThreads) {
					#my $domain = ($host =~ m/^\d+(\.\d+){3}$/) ? "" : ($dHash->{-domain} ? ".$dHash->{-domain}" : "");
					my $retPing = $pingHash{"$host$domain"};
					if ($retPing) {
						($ping, $duration, $ip) = split (/~\#~/, $retPing);
						$ipHost and $ip = $host;
					}
				} else {
					my $fqhn = $host.$domain;
					$fqhn =~ s/^(\d+|CN)\+//;
					if ($port) {
						eval {
							my $pp = Net::Ping->new ("tcp", 2);
							$pp->{port_num} = $port;
							($ping, $duration, $ip) = $pp->ping ($fqhn, 2);
							$pp->close ();
						};
						if ($@) {
							($ping, $duration, $ip) = sysPing ($fqhn, $timeout);
						}
					} else {
						if ($p) {
							($ping, $duration, $ip) = $p->ping ($fqhn, 2);
						} else {
							# use external ping
							($ping, $duration, $ip) = sysPing ($fqhn, $timeout);
						}
					}
					$ipHost and $ip = $host;
					#$ipHost or $ip and $pingHash{"$ip"}{"$host$domain"}++;
					$ip and addIpHash ("$ip", "$host$domain");
				}
				unless ($useThreads) {
					print "NOT " unless $ping;
					print "reachable. -->\n";
				}
				
				my $img;
				# define image for OK|FAIL
				if ($ping) { # OK
					$img = $q->img ({width => 20, height => 20, title => "reachable", alt => "reachable", src => $imgOk});
				} else { # FAIL with WOL feature
					my $imgAlt = "NOT reachable".($mac ? ", WOL is available" : "");
					$img = $q->img ({width => 20, height => 20, title => $imgAlt, alt => $imgAlt, src => $imgFail});
					my $wolStateMac = ($wolState && $wolState =~ m/^$mac$/i) ? 1 : 0;
					#my $wol = $mac ? $q->a ({class => "wol", onclick => "this.innerHTML='✉';", href => "?mac=".uri_escape ($mac), title => "WOL: $mac"}, ($wolStateMac ? "✓": "&#9737;") . " ") : "";
					$mac and $img = $q->a ( {class => "wol", 
											 onclick => "this.innerHTML='✉';", 
											 href => "?mac=".uri_escape ($mac), 
											 title => "WOL: $mac"}, 
											$wolStateMac ? "✓" : $img );
				}
				my $ipCheck = "";
				# show duplicate and missing IPs
				if (exists $ipErrorHash{"$ip"} && $ipErrorHash{"$ip"} > 1) {
					my $ipCnt = $ipErrorHash{"$ip"};
					my $ipFqdnList = join (", ", grep { $_ } split (/~~/, $ipHash{"$ip"}));
					$ipCheck = $q->span ({class => ($ip == "none") ? "ip_warn" : "ip_error", title => "IP counter: $ipCnt ($ipFqdnList)"}, ($ip == "none") ? " [no IP]" : " [IP error]");
				}
				#push @{$cols[$i]}, $q->a ({target => '_blank', title => "IP: $ip", href => "http://$host$domain" . ($port ? ":$port" : '')."/"}, $img . " " . ($name ? $name : $host) . $ipCheck);
				# symbols: http://danthemans.squidoo.com/html-special-characters
				(my $plainHost = $host) =~ s/^(\d+|CN)\+//;
				push @{$cols[$i]}, $q->a ({target => '_blank', title => "IP: $ip", href => "http://" . $plainHost . $domain . ($port ? ":$port" : '')."/"}, $img . " " . ($title ? $title : $plainHost) . $ipCheck);
			}
		}
		
		$useThreads or print "<!--    write table row -->\n";
		my $rowCnt = 0;
		map {@$_ > $rowCnt and $rowCnt = @$_} @cols;
		for (my $i = 0; $i < $rowCnt; $i++) {
			my @val;
			for (my $j = 0; $j < @cols; $j++) {
				my @col = @{$cols[$j]};
				push @val, 
				  defined $col[$i] ? $q->td ((@col < $rowCnt && @col == $i + 1) ? {class => 'status', rowspan => $rowCnt - @col + 1} : {}, $col[$i]): '';
			}
			
			my $imgUrl = $types->{$type}{img} ? "<img src=\"$scriptName?id=$types->{$type}{img}\" title=\"$type\" alt=\"$type\" /> " : '';
			push @$tbl, ($i == 0 ? $q->td ({class => 'type', rowspan => $rowCnt}, $i == 0 ? ($imgUrl ? $imgUrl : $type) : '') : '') . join ('', @val);
		}
	}
	unless ($useThreads) {
		defined $p and $p->close ();
		$p = undef;
	}
	
	print $q->table ({-cellspacing => 0, -cellpadding => '2', -border => '1'},
	    $q->caption ('host online status'),
		$q->Tr ({-valign => 'top'},
			$tbl
		  )
		);

	my $dateString = strftime ("%a %e %b %Y %H:%M:%S", localtime ());
	print "<div>time: ", (time () - $start)," sec".($useThreads ? " [WITH THREADING]" : "")."; GMT date and time: $dateString</div>\n";

	printFoot ();
	return 1;
}


sub printHead #()
{
	# create the HTTP header
	print $q->header (
			-content_language => "de-DE",
			-charset => 'UTF-8'
		);
	print $q->start_html (
				-lang    => 'de-DE',
				-title   => 'Host status',
				-style   => "$scriptName?id=ping.css"
			); # start the HTML
	return 1;
}

sub printFoot #()
{
	print $q->end_html; # end the HTML
	return 1;
}


my $id;
if (@ARGV) {
	$id = shift @ARGV;
	if ($id) {
		$id eq "file" or $id = undef;
	}
	$id and $id = {id => $id};
}
$q = CGI->new ($id); # create new CGI object

my $fileName = $q->param ('id');
if ($fileName) {
	sendFile ($fileName);
} else {
	$start = time ();
	doWol ();
	pingHosts ();
}

exit (0);
