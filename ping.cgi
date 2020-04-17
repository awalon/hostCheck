#!/usr/bin/perl -w

# debian packages:
#  libnet-ping-perl libnet-ping-external-perl
# TODO: Check oping (libnet-oping-perl)

use utf8;
use strict;
use warnings;
use Time::HiRes qw (time);
use Net::Ping;
#use Net::Ping::External; # for none root users (ping)
use IO::Socket; #and use IO::Socket::INET;
use Net::Wake; # WOL feature
use Socket;    # for none root users (get IP)
use POSIX qw(strftime);
use URI::Escape;
use CGI;       # load CGI routines
#use CGI::Pretty; # load CGI routines with pretty print
use CGI::Carp qw(fatalsToBrowser);

#my $threadsAvailable = eval 'use threads; use threads::shared; use Thread::Semaphore; 1';
my $threadsAvailable = eval 'use threads; use threads::shared; 1';
(my $scriptDir = $0) =~ s{^(.*?[\\/])?([^\\/]+)$}{$1};
my $scriptName = $2||'';
my $isDebug    = 0;
my $q; #CGI page
binmode(STDOUT,':utf8');
binmode(STDERR,':utf8');

# The default config, which will be overwritten by the values from external file
my $cfgHash = {
	'image' => {
		'rootFolder' => "img/default/",
		'okay'       => "$scriptName?id=ok.png",
		'fail'       => "$scriptName?id=fail.png",
	},
	'types' => {
		'router'  => { 'idx' => 10, 'img' => 'router.png' },
		'switch'  => { 'idx' => 15, 'img' => 'switch.png' },
		'wifi'    => { 'idx' => 20, 'img' => 'wifi.png' },
		'server'  => { 'idx' => 30, 'img' => 'server.png' },
		'nas'     => { 'idx' => 35, 'img' => 'nas.png' },
		'printer' => { 'idx' => 40, 'img' => 'printer.png' },
		'tv'      => { 'idx' => 55, 'img' => 'tv.png' },
		'raspi'   => { 'idx' => 58, 'img' => 'raspi.png' },
		'android' => { 'idx' => 60, 'img' => 'android.png' },
		'client'  => { 'idx' => 60, 'img' => 'client.png' },
		'laptop'  => { 'idx' => 58, 'img' => 'laptop.png' },
	},
	# host pattern: <idx for NATed systems>+<host name>:<port>[<MAC address for WOL>]|<alias>
	'hosts' => {
		'LAN' => {
			'-idx'    => 10,
			'-domain' => 'example.lan',
			'router'  => [ qw/www/ ],
			'switch'  => [ qw/switch/ ],
			'wifi'    => [ qw/accesspoint/ ],
			'server'  => [ qw/fileserver webserver:80/ ],
			'nas'     => [ qw/nas:22/ ],
			'printer' => [ qw/net-printer/ ],
			'tv'      => [ qw/tv chromecast/ ],
			'raspi'   => [ qw/raspi001/ ],
			'android' => [ qw/smartphone/ ],
			'laptop'  => [ qw/laptop[00:11:22:33:44:55]/ ],
			'client'  => [ qw/desktop[11:22:33:44:55:66]/ ],
		},
		'WAN' => {
			'-idx'    => 20,
			'-domain' => 'example.com',
			'router'  => [ qw/1+webgateway/ ],
			'server'  => [ qw/2+webgateway:22|Server/ ],
			'nas'     => [ qw/storage|NAS/ ],

		}
	},
};

# Read external config file
(my $cfgFile = $scriptName) =~ s{^(.*?)(\.[^\.]*)?$}{$scriptDir$1.cfg};
if (-f $cfgFile) {
	my $cfgHashNew = do $cfgFile;
	# Unfortunately 'do' error checking is very fragile
	# There's no way to differentiate certain errors from the file returning false or undef
	unless ($cfgHashNew) {
		die "couldn't parse $cfgFile: $@" if $@;
		die "couldn't do $cfgFile: $!" unless defined $cfgHashNew;
		die "$cfgFile did not return data";
	}
	# Check for root nodes
	exists $cfgHashNew->{image} and  $cfgHash->{image} = $cfgHashNew->{image};
	exists $cfgHashNew->{types} and  $cfgHash->{types} = $cfgHashNew->{types};
	exists $cfgHashNew->{hosts} and  $cfgHash->{hosts} = $cfgHashNew->{hosts};
}

# Get configuration from cfgHash
my $types   = $cfgHash->{types};
# Host pattern: <idx for NATed systems>+<hostname>:<port>[<MAC address for WOL>]|<alias>
my $data    = $cfgHash->{hosts};

my $start;
my $useThreads = ($threadsAvailable ? 1 : 0);
my $timeout = $useThreads ? 10 : 2;
my $timeoutWol = 20;
my $wolState;
my $pingType = 0; # 0 => Socket Ping; 1 => Net::Ping; 2 => Ping Cmd
my $wolType = 0; # 0 => Net::Wake; 1 => Net::Ping
my %pingHash;
$useThreads and eval 'share (%pingHash)';
my %ipHash;
$useThreads and eval 'share (%ipHash)';
my %serviceHash;
$useThreads and eval 'share (%serviceHash)';
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
	my $contentType = "text/html";
	$ext //= "png";
	if ($ext =~ m/css/i) {
		$file = "${scriptDir}$fileName";
		$contentType = "text/css";

	} elsif ($ext =~ m/png|jpe?g/i) {
		my $imgRoot = $cfgHash->{image}{rootFolder};

		$file = "${scriptDir}${imgRoot}$fileName";
		-f $file or $file = "${scriptDir}img/fail.png";
		$contentType = "image/$ext";

	} else {
		$file = "${scriptDir}img/fail.png";
		$ext  = "png";
		$contentType = "image/$ext";
	}

	my $msg;
	open(SRC, "<$file") or $msg = $!;
	$msg and do {
		printHead ();
		print $q->p ("can't open file '${fileName}' (${file}): ${msg}");
		printFoot ();
		return 0;
	};

	binmode(STDOUT,':raw');
	binmode(STDERR,':raw');

	print "Content-Type:$contentType\n";
	print "\n";
	print <SRC>;
	close (SRC);

	return 1;
}

sub parseHostUri #($hostUri)
{
	my ($hostUri, $domain) = @_;
	$hostUri =~ m/^-/ and return;
	$hostUri =~ m/^(?:(?<index>\d+)\+)?(?:(?<cname>CN+)\+)?(?<host>.*?)(\.(?<domain>[^:\|]+?)?)?(?::(?<proto>[uti])?(?<port>\d+))?(?:\[(?<mac>(?:[a-z\d]{2}:){5}[a-z\d]{2})\])?(?:\|(?<title>.+?))?$/i; # (<index>)+(<cname>)+(<name>):(<port>)[(<mac>)]|<title>
	my $host = {
		'index'    => $+{'index'},
		'cname'    => $+{'cname'},
		'name'     => $+{'host'},
		'domain'   => $+{'domain'} ? $+{'domain'} : $domain,
		'proto'    => $+{'proto'} ? ($+{'proto'} eq "i" ? 'icmp' : ($+{'proto'} eq "t" ? 'tcp' : ($+{'proto'} eq "u" ? 'udp' : 'tcp') ) ) : 'tcp', # default: TCP
		'port'     => $+{'port'} ? $+{'port'} : '',
		'mac'      => $+{'mac'},
		'title'    => $+{'title'},
		'uri'      => $hostUri,
		'fqdn'     => undef,
		'key'      => undef, # FQDN + port
		'isCname'  => $+{'cname'} ? 1 : 0,
		'isIp4'    => 0,
		'isIp6'    => 0,
	};
	$host->{name} =~ m/^\d+(\.\d+){3}$/ and $host->{isIp4} = 1; # IP Pattern?
	# IPv6 RegEx: https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
	$host->{name} =~ m/^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|[fF][eE]80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/ and $host->{isIp6} = 1; # IP Pattern?

	if ($host->{isIp4} || $host->{isIp6}) {
		$host->{'fqdn'} = $host->{name};
	} else {
		$host->{'fqdn'} = $host->{name}.($host->{domain} ? '.'.$host->{domain} : '')
	}
	$host->{'key'} = sprintf ("%s:%s", $host->{'fqdn'}, $host->{port});

	wantarray and return ($host->{name}, $host->{port}, $host->{mac}, $host->{title});
	return $host;
}

sub wol #($mac, ?$gateway)
{
	my ($mac, $gateway) = @_;
	$mac or return;

	$wolType //= 0;
	if ($wolType == 0) {
		# http://search.cpan.org/~clintdw/Net-Wake-0.02/lib/Net/Wake.pm
		# Net::Wake::by_udp('255.255.255.255', '00:00:87:A0:8A:D2');
		return Net::Wake::by_udp ('255.255.255.255', $mac);

	} elsif ($wolType == 1) {
		eval ("use Net::Ping qw(wakeonlan);");
		# Use Net::Ping instead (no additional module)
		# https://perldoc.perl.org/Net/Ping.html
		# wakeonlan($mac, [$host, [$port]])
		#  Default host: '255.255.255.255' Default port: 9
		return wakeonlan ($mac, $gateway);
	}

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

			my $gw; # Get optional gateway
			if (exists $qs{gw} && $qs{gw}) {
				$gw = uri_unescape ($qs{gw});
			}
			wol ($mac, $gw);
			sleep $timeoutWol;
			return 1;
		}
	}
	return;
}

sub socketPing #($hostOrIp, $port, ?$proto, ?$timeout)
{
	my ($hostOrIp, $port, $proto, $timeout) = @_;
	$proto ||= 'tcp';
	$timeout ||= 2;
	$hostOrIp =~ s/\.+$//g;

	my $connected = 0;
	my $startTime = time ();
	my $checkport = IO::Socket::INET->new (
		PeerAddr => "$hostOrIp",
		PeerPort => "$port",
		Proto    => $proto,
		Timeout  => $timeout,
	) and $connected = 1;

	$isDebug and print <<"EOF;";
<!-- #########
 Socket \@: $@
 Socket !: $!
 Socket ?: $?
-->
EOF;
	my $err = $@;
	my $msg = $!;
	my $duration = time() - $startTime;

	if ($checkport) {
		$isDebug and print "<!-- # ${hostOrIp}:$port is [$connected] up. -->\n";
		close $checkport;
	} else {
		$isDebug and print "<!-- # ${hostOrIp}:$port is [$connected] down: $msg -->\n";
	}

	my @addresses;
	my $ip;
	unless ($err =~ m/Bad.*hostname/i) {
		@addresses = gethostbyname ($hostOrIp)
		or print "<!-- Can't resolve '$hostOrIp': $! -->\n";
		# docstore.mik.ua/orelly/perl4/cook/ch18_02.htm
		@addresses = map { inet_ntoa($_) } @addresses[4 .. $#addresses];
	}
	($ip) = @addresses;

	wantarray and return (($checkport ? 1 : 0), $duration, $ip, $msg);
	return $checkport ? 1 : 0;
}

sub sysPing #($hostOrIp, ?$timeout)
{
	my ($hostOrIp, $timeout) = @_;
	$timeout ||= 5;
	$hostOrIp =~ s/\.+$//g;

	# TODO: Net::Ping::External
	# https://books.google.de/books?id=daks78g9Pg0C&pg=PA452&lpg=PA452&dq=perl+net+ping+tcp+detect+empty+response&source=bl&ots=MNX2w0OCNN&sig=ACfU3U1o4jSTkLDS9xRzfbu1kuzPjQfZnQ&hl=de&sa=X&ved=2ahUKEwjk1ti2ydnnAhWD26QKHd-SCEEQ6AEwAnoECAgQAQ#v=onepage&q=perl net ping tcp detect empty response&f=false
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
		$isDebug and printf "<!-- child exited with value %d -->\n", $? >> 8;
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
			# TODO: Extract IPv6
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

sub addIpHash #($ip, $fqdn, $hostHash)
{
	my ($ip, $fqdn, $hostHash) = @_;
	my $serviceKey = $ip . ($hostHash->{port} ? ":" . $hostHash->{port} : '');

	$hostHash->{"keyIp"} //= $serviceKey;
	$hostHash->{"ip"}    //= $ip;

	if (exists $serviceHash{"$serviceKey"} && "$ip" ne "none") { # "none" -> No IP
		# TODO: Duplicate service check detected !?!? -> implement filter
		print STDERR "[addIpHash] Duplicate service check detected: ${serviceKey}\n";
	}
	$serviceHash{"$serviceKey"} .= "~~$fqdn~~";
	printf ("<!-- IP check:    	%-38s	%-60s %11s -->\n", $serviceKey, $fqdn, '');

	# Check for duplicate IPs (whitelist with 'CN', which defines CNames)
	if (exists $ipHash{"$ip"} && $ipHash{"$ip"} =~ m/~~($fqdn)~~/i) {
		unless ($hostHash->{"isCname"}) {
			$ipErrorHash{"$ip"}++;
		}
	} else {
		$ipHash{"$ip"} .= "~~$fqdn~~";
	}

	# Check for missing IPs
	if ("$ip" eq "none") {
		$ipErrorHash{"$ip"}++;
	}
}

sub ping #($hostOrIp, ?$port, ?$proto, ?$timeout)
{
	my ($hostOrIp, $port, $proto, $timeout) = @_;
	$proto //= 7; # defaults to "echo" (tcp/udp)
	$proto ||= 'tcp';
	$timeout ||= 2;
	$hostOrIp =~ s/\.+$//g;

	my ($ping, $duration, $ip);

	$pingType //= 0;
	if ($pingType == 0) {
		($ping, $duration, $ip) = socketPing($hostOrIp, $port, $proto, $timeout);

	} elsif ($pingType == 1) {
		eval {
			printf ("<!-- ping (%-4s): %-60s -->\n" , $proto, sprintf ("%s:%s", $hostOrIp, $port));

			my $pp = Net::Ping->new ($proto, 2); # type defaults to TCP
			$pp->{port_num} = $port;
			$pp->{service_check} = 1;
			($ping, $duration, $ip) = $pp->ping ($hostOrIp, $timeout);
			$pp->close ();
			$pp = undef;
		};
		if ($@) {
			print "<!-- ###### ERROR: $@ -->\n";
		}

	} elsif ($pingType == 2) {
		# use external ping
		($ping, $duration, $ip) = sysPing ($hostOrIp, $timeout);
	}

	wantarray and return ($ping, $duration, $ip);
	return $ping;
}

sub doPing #($hostUri, $domain, ?$semPing)
{
	my ($hostUri, $domain, $semPing) = @_;
	my $hostHash = parseHostUri ($hostUri, $domain);
	my $fqdn = $hostHash->{'fqdn'};
	my $key = $hostHash->{'key'};

	my ($ping, $duration, $ip);
	eval {
		if ($hostHash && $fqdn) {
			if ($hostHash->{'port'}) {
				my $port = $hostHash->{'port'};
				eval {
					printf ("<!-- ping (%-4s): %-60s -->\n" , $hostHash->{'proto'}, sprintf ("%s:%s", $fqdn, $port));

					($ping, $duration, $ip) = ping ($fqdn, $port, $hostHash->{'proto'}, $timeout);
				};
				if ($@) {
					print "<!-- ###### ERROR: $@, fallback to sysPing -->\n";
					printf ("<!-- ping (sys ): %-60s -->\n", $fqdn . " (port scan not available)");
					($ping, $duration, $ip) = sysPing ($fqdn, $timeout);
				}
			} else {
				if ($> == 0) {
					# root is allowed to use ICMP
					eval {
						printf("<!-- ping (icmp): %-60s -->\n", $fqdn);

						($ping, $duration, $ip) = ping ($fqdn, undef, "icmp", $timeout);
						#my $p = Net::Ping->new("icmp", 1);
						#my $p = Net::Ping->new ("syn", 1);
						#$p->{port_num} = 7;
						#($ping, $duration, $ip) = $p->ping($fqdn, $timeout);
						#$p->close();
						#$p = undef;
					};
					if ($@) {
						print "<!-- ###### ERROR: $@, fallback to sysPing -->\n";
						printf("<!-- ping (sys ): %-60s -->\n", $fqdn);
						($ping, $duration, $ip) = sysPing($fqdn, $timeout);
					}
				} else {
					printf ("<!-- ping (sys ): %-60s , use root for ICMP -->\n", $fqdn);
					($ping, $duration, $ip) = sysPing ($fqdn, $timeout);
				}
			}
		}
	};
	@! and print "<!-- ###### ERROR: @! -->\n";
	$ip       //= "none";
	$duration //= 0;
	$ping     //= 0;
	printf ("<!-- checked: %-4s	%-32s	%-60s	%5.1f ms -->\n", ($ping ? "OK" : "FAIL"), $ip, $key, $duration);
	if ($useThreads) {
		#$semPing->up ();
		#lock %pingHash;
		#cond_signal (\%pingHash);
	}
	$pingHash{$hostUri} = "$ping~#~$duration~#~$ip";
	$ip and addIpHash ("$ip", "$hostUri", $hostHash);
	if ($useThreads) {
		#$semPing->down ();
		threads->exit (1);
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
			my $domHash = $data->{"$domainKey"};
			my $domain = $domHash->{"-domain"};

			foreach my $type (keys %$types) {
				unless (exists $domHash->{"$type"}) {
					$isDebug and print "<!-- '$domainKey': Skipped type '$type', as there's no host/service to check -->\n";
					next;
				}

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

	my $imgOk   = $cfgHash->{image}{okay};
	my $imgFail = $cfgHash->{image}{fail};
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
				my $hostHash = parseHostUri ($hostUri, $dHash->{-domain});
				my $fqdn = $hostHash->{fqdn};
				my $port = $hostHash->{port};

				$useThreads or printf ("<!--     %-30s:%-5s is ", $fqdn, $port);
				my ($ping, $duration, $ip);
				if ($useThreads) {
					#my $domain = ($host =~ m/^\d+(\.\d+){3}$/) ? "" : ($dHash->{-domain} ? ".$dHash->{-domain}" : "");
					my $retPing = $pingHash{"$hostUri"};
					if ($retPing) {
						($ping, $duration, $ip) = split (/~\#~/, $retPing);
					}
				} else {
					# TODO: Update to new version, see useThreads
					die "Update: See 'useThreads'";
					if ($port) {
						eval {
							my $pp = Net::Ping->new ("tcp", 2);
							$pp->{port_num} = $port;
							($ping, $duration, $ip) = $pp->ping ($fqdn, 2);
							$pp->close ();
						};
						if ($@) {
							($ping, $duration, $ip) = sysPing ($fqdn, $timeout);
						}
					} else {
						if ($p) {
							($ping, $duration, $ip) = $p->ping ($fqdn, 2);
						} else {
							# use external ping
							($ping, $duration, $ip) = sysPing ($fqdn, $timeout);
						}
					}
					#$ipHost or $ip and $pingHash{"$ip"}{"$host$domain"}++;
					$ip and addIpHash ("$ip", "$fqdn", $hostHash);
				}
				unless ($useThreads) {
					print "NOT " unless $ping;
					print "reachable. -->\n";
				}
				
				my $mac   = $hostHash->{mac};
				my $title = $hostHash->{title};
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
					$ipCheck = $q->span ({class => ("$ip" eq "none") ? "ip_warn" : "ip_error", title => "IP counter: $ipCnt ($ipFqdnList)"}, ("$ip" eq "none") ? " [no IP]" : " [IP error]");
				}
				#push @{$cols[$i]}, $q->a ({target => '_blank', title => "IP: $ip", href => "http://$host$domain" . ($port ? ":$port" : '')."/"}, $img . " " . ($name ? $name : $host) . $ipCheck);
				# symbols: http://danthemans.squidoo.com/html-special-characters
				push @{$cols[$i]}, $q->a ({target => '_blank', title => "IP: $ip", href => "http://" . $fqdn . ($port ? ":$port" : '')."/"}, $img . " " . ($title ? $title : $hostHash->{name}) . $ipCheck);
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

# Test calls
if (0) {
	socketPing("nothing", "8081");
	socketPing("www.example.com", "22132");
	socketPing("www.example.com", "8080");
	socketPing("www.example.com", "8081");
	socketPing("www.example.com", "8082");
	doPing("www.example.com:22132|Example - Com");
	doPing("www.example.com:8080|www");
	doPing("www.example.com:8081|Webserver");
	doPing("www.example.com:8082|WWW-Test");
	die;
}

my $id;
if (@ARGV) {
	$id = shift @ARGV;
	if ($id) {
		$id eq "id" or $id = undef;
	}
	my $file = shift @ARGV;
	$file and $id = {id => $file};
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
