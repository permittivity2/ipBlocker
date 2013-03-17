#!/usr/bin/perl -w

# Written by Jeff Gardner over a few years but I'm putting this out as a beta on 8/1/12
# This script is GPL v3 licensed.  You can get this license at http://www.gnu.org/licenses/gpl-3.0.html

#############################################################################
# Author:  	Jeff Gardner <ipblockerscript AT forge name>
# Description:	Continuously looks at various log files for offending IPs
# Version:	12.08 -- Beta
# Version:	13.01-- Beta
#			Complete rewrite.  
# Version:	13.14 -- Beta
#			Added a "sleep".  Most logs only write the "seconds" so really no need to have this run more than 
#				once per second.  Seemed reasonable that some people may want it to run as fast as possible (--sleep 0) 
#				or may want a pause of a few seconds between each run.
# Version:	13.21 -- Beta
#			Added sendmail 
#
# Future improvement suggestions:
#	1)	Use a config file for the various file locations, directories, and
#			various regexp values
#	2) Figure out a faster way to work through the query.log
#  3) Only load a file if it has changed by using "stat"
#############################################################################

use DateTime;
use File::Basename;
use Getopt::Long;
use NetAddr::IP::Util qw(inet_ntoa);
use Net::DNS::Dig;
use File::Lockfile;
use strict;

#Date Time stuff that always needs to be done.  <sigh>
my $sec;		my $mday;		my $wday;
my $min;		my $mon;			my $yday;
my $hour;	my $year;		my $isdst;

my $verbose=0;
my $help;
my $STOP;
my $BASEFILENAME=fileparse($0,".pl");
my $AUTHLOG="/var/log/auth.log";
my $QUERYLOG="/var/log/named/query.log";
my $MAILLOG="/var/log/mail.log";
my $RUNNINGDIR="/var/log/ipBlocker/";
my $LOGFILE="/var/log/ipBlocker/ipBlocker.log";
my $USERNAMES="gardner,salman,nk105784,jiggerboy,nkunkee,emlodz02,frankli,hassan,4x4chuckie,gemalto";
my $BLOCKEDIPS="199.59.148.1,68.71.217.54,66.220.144.154,204.232.250.45,69.171.232.152,66.220.155.146,143.192.4.42,143.192.4.59,207.189.109.125"; 
my $AUTHLOGBADREGEXPs="Failed password for root from,Failed password for invalid user,Did not receive identification string from";
my $QUERYLOGBADREGEXPs="isc.org,VERSION.BIND";
my $ALLOWEDIPS="176.58.89.242,176.58.89.25,64.250.56.204";
my $ALLOWEDFQDNS="home.forge.name,moles-gw.sprint.com,lvl.forge.name";
my $BLOCKEDFQDNS="e2943.e11.akamaiedge.net,e2943.e11.akamaiedge.net,sealinfo.thawte.com,tfr.com";
my $BLOCKEDMAIL="did not issue MAIL/EXPN/VRFY/ETRN";
my $CYCLES=0;
my $SLEEP=0;
my $NICE=19;
my $LOCKDIR="/var/run";
my $LOCKFILENAME="$BASEFILENAME.lock";
my $PROCID ="$$";
my @AUTHLOGarray;
my @AUTHLOGBADREGEXPsarray;
my @USERNAMESarray;
my @QUERYLOGarray;
my @QUERYLOGBADREGEXPsarray;
my @BLOCKEDIPSarray;
my @ALLOWEDIPSarray;
my @ALLOWEDFQDNSarray;
my @BLOCKEDFQDNSarray;
my @BLOCKEDMAILarray;
my @MAILLOGarray;

my $LOCKFILE = File::Lockfile->new(
	$LOCKFILENAME,
	$LOCKDIR );

my %GOODIPS;
my %BADIPS;

GetOptions('verbose+' => \$verbose, 'help' => \$help, 'stop' => \$STOP,
	'logfile=s' => \$LOGFILE, 'runningdir=s' =>\$RUNNINGDIR, 'authlog=s' => \$AUTHLOG, 'querylog=s' => \$QUERYLOG, 'usernames=s' => \$USERNAMES, 
	'allowedips=s' => \$ALLOWEDIPS, 'blockedips=s' => \$BLOCKEDIPS, 'nice:19' => \$NICE, 'cycles:0' => \$CYCLES, 'maillog=s' => \$MAILLOG, 
	'authlogbadregexps=s' => \$AUTHLOGBADREGEXPs, 'querylogbadregexps=s' => \$QUERYLOGBADREGEXPs, 'sleep:0' => \$SLEEP  );

# Re-nice this to $NICE.  This may not be necessary on multi-core/cpu systems 
my @output = `renice +19 $$ > /dev/null 2>&1`;

main();

sub main {
	warn "Running sub main\n" if ($verbose>2);
# Description: Having "main" is kind of a throwback to the ANSI C days.  Just thought having this would be easier to read.  Maybe not
	@BLOCKEDIPSarray = split(',',$BLOCKEDIPS); 
	@ALLOWEDIPSarray = split(',',$ALLOWEDIPS); 
	@AUTHLOGBADREGEXPsarray = split(',',$AUTHLOGBADREGEXPs); 
	@QUERYLOGBADREGEXPsarray = split(',',$QUERYLOGBADREGEXPs); 
	@USERNAMESarray = split(',',$USERNAMES); 
	@ALLOWEDFQDNSarray = split(',',$ALLOWEDFQDNS); 
	@BLOCKEDFQDNSarray = split(',',$BLOCKEDFQDNS); 
	@BLOCKEDMAILarray = split(',',$BLOCKEDMAIL); 

	helpDescribe() if ( $help );
	locked();

	if ( $CYCLES == 0 ) {
		while ( 1 ) {
			stopRunning();
			loadAndAdd();
			sleep $SLEEP;
		}
	}
	else {
		while ( $CYCLES > 0 ) {
			warn "Epoch of this cycle: ".time."\n" if ($verbose > 0);
			stopRunning();
			loadAndAdd();
			$CYCLES--;
			sleep $SLEEP;
		}
	}
	$LOCKFILE->remove;
}

sub stopRunning {
	warn "Running sub stopRunning \n" if ($verbose>2);
#Description: Determines if $LOCKDIR/$LOCKFILENAME.stop contains STOP
#	If it does then we stop the program

	if ( -e "$LOCKDIR/$LOCKFILENAME.stop" ) {
		open FILE, "$LOCKDIR/$LOCKFILENAME.stop";
		my @stopFile=<FILE>;
		close FILE;
		if ( $stopFile[0]  =~ m/stop/i ){
			warn "Caught a stop!!! \n" if ($verbose>0);
			$LOCKFILE->remove;
			unlink "$LOCKDIR/$LOCKFILENAME.stop";
			exit 0;
		}
	}
}

sub locked {
	warn "Running sub locked \n" if ($verbose>2);
#Description: Determines if lockfile is already set with PID for program already running
#		If it is not then the lockfile is set
#		If it is already set and stop has been requested then we set stop and exit.
#Assumes: 
# $LOCKFILENAME is set
#Uses:
#	File::Lockfile

	if ( my $pid = $LOCKFILE->check ) {
		if ( $STOP ) {
			open FILE, ">", "$LOCKDIR/$LOCKFILENAME.stop" or die "Dying in main.  Couldn't load $LOCKDIR/$LOCKFILENAME.stop .  Error: $!";
			print FILE "STOP\n";
			close FILE;
		} else {
	  		warn "Program is already running with PID: $pid";
		}
		exit;
	} 
	$LOCKFILE->write;
}

sub loadAndAdd {
	warn "Running sub loadAndAdd \n" if ($verbose>2);
#Description: Runs the subs that actually do the work.  This was put into a separate sub for threading.
	
	addBLOCKEDIPSBADLIST();
	addALLOWEDIPSGOODLIST();

	loadAUTHLOG();
	addAUTHLOGGOODLIST();
	addAUTHLOGBADLIST();

	loadQUERYLOG();
	addQUERYLOGBADLIST();

	loadMAILLOG();
	addMAILLOGBADLIST();	

	addALLOWEDFQDNSGOODLIST();
	addBLOCKEDFQDNSBADLIST();

	deleteDUPLICATEGOODBADLIST();
	deleteDUPLICATEIPTABLESBADLIST();

	addIPTableEntries();
}

sub helpDescribe {
	warn "Running sub helpDescribe\n" if ( $verbose > 2 );
# Description: Provides info to screen for user
	print "--verbose -> more uses provides more verbosity.  Be carefull.  You may get more than you bargained for.\n";
	print "--help -> uhm, you obvioulsy know what that does. \n";	
	print "\n\n";
	print "--stop -> To have the running program gracefully exit use this switch. \n\t\tExample: --stop \n";
	print "--nice -> Priority level to run this program.  The default is 19, which is the lowest priority.  \n\tI really encourage you to let this run at 19.  The highest priority is -20 (negative 20). \n\t\tExample: --nice ".$NICE."\n"; 
	print "--sleep -> Amount of time in seconds to pause between looking at the logs. \n\t\tExample --sleep ".$SLEEP."\n";
	print "--logfile -> full path of log file for this program to use. \n\t\tExample --logfile ".$LOGFILE."\n";
	print "--runningdir -> path of directory for this program to use. \n\t\tExample --runningdir ".$RUNNINGDIR."\n";
	print "--authlog -> full path of where auth.log is located.  \n\t\tExample: --authlog ".$AUTHLOG."\n";
	print "--querylog -> full path of where query.log is located.  \n\t\tExample: --querylog ".$QUERYLOG."\n";
	print "--maillog -> full path of where mail.log is located.  \n\t\tExample: --maillog ".$MAILLOG."\n";
	print "--usernames -> Comma separated list of allowed usernames for ssh login. \n\t\tExample: --usernames \"".$USERNAMES."\"\n";
	print "--blockedips -> Comma separated list of IPs to block. \n\t\tExample: --blockedips \"".$BLOCKEDIPS."\"\n";
	print "--allowedips -> Comma separated list of IPs to never block. \n\t\tExample: --allowedips \"".$ALLOWEDIPS."\"\n";
	print "--allowedfqdns -> Comma separated list of Fully Qualified Domain Names to always allow. \n\t\tExample: --allowedfqdns \"".$ALLOWEDFQDNS."\"\n";
	print "--blockedfqdns -> Comma separated list of Fully Qualified Domain Names to block. \n\t\tExample: --blockedfqdns \"".$BLOCKEDFQDNS."\"\n";
	print "Careful with the Fully Qualified Domain Names.  It will allow or block all \'A\' list entries.  For example: \n";
	print "\twww.google.com has the following IPs that would be blocked:\n";
	print "\t173.194.34.163,173.194.34.160,173.194.34.162,173.194.34.166,173.194.34.165,173.194.34.168,173.194.34.169,173.194.34.167,173.194.34.174,173.194.34.164,173.194.34.161 \n";
	print "--authlogbadregexps -> Comma separated list of strings to search for in the auth.log to look for IPs to block. \n\t\tExample: --authlogbadregexps \"".$AUTHLOGBADREGEXPs."\"\n";
	print "--querylogbadregexps -> Comma separated list of strings to search for in the query.log to look for IPs to block. \n\t\tExample: --querylogbadregexps \"".$QUERYLOGBADREGEXPs."\"\n";
	exit 0;
}

sub setCurrentLocalDateTimeValues {
	warn "Running setCurrentLocalTimeValues \n" if ($verbose>2);
#Description: Sets various date time values to the current time

	($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
	$mon+=1;		$year += 1900;
	$mday = sprintf("%02d", $mday % 100);		$mon = sprintf("%02d", $mon  % 100);
	$hour = sprintf("%02d", $hour  % 100);		$min  = sprintf("%02d", $min  % 100);		$sec = sprintf("%02d", $sec % 100);
	my @abbr = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );
	#print "$abbr[$mon] $mday";
}

sub loadAUTHLOG {
	warn "Running sub loadAUTHLOG\n" if ($verbose > 2);
#Description: very simple sub.  Opens $AUTHLOG and loads it into an array.
	open FILE, $AUTHLOG or die "Dying in loadAUTHLOG.  Couldn't load $AUTHLOG.  Error: $!";
	@AUTHLOGarray=<FILE>;
	close FILE;
	warn "$AUTHLOG loaded \n" if ($verbose > 1);
	warn "Lines in $AUTHLOG: ".scalar(@AUTHLOGarray)."\n" if ($verbose>1);
	if ($verbose > 3) {
		warn "$AUTHLOG entries: \n";
		foreach (@AUTHLOGarray) {
			warn $_;
		}
	}
}

sub loadQUERYLOG {
	warn "Running sub loadQUERYLOG\n" if ($verbose > 2);
#Description: very simple sub.  Opens $QUERYLOG and loads it into an array.
	open FILE, $QUERYLOG or die "Dying in loadQUERYLOG.  Couldn't load $QUERYLOG.  Error: $!";
	@QUERYLOGarray=<FILE>;
	close FILE;
	warn "$QUERYLOG loaded \n" if ($verbose > 1);
	warn "Lines in $QUERYLOG: ".scalar(@QUERYLOGarray)."\n" if ($verbose>1);
	if ($verbose > 3) {
		warn "$QUERYLOG entries: \n";
		foreach (@QUERYLOGarray) {
			warn $_;
		}
	}
}

sub loadMAILLOG {
	warn "Running sub loadMAILLOG\n" if ($verbose > 2);
#Description: very simple sub.  Opens $MAILLOG and loads it into an array.
	open FILE, $MAILLOG or die "Dying in loadMAILLOG.  Couldn't load $MAILLOG.  Error: $!";
	@MAILLOGarray=<FILE>;
	close FILE;
	warn "$MAILLOG loaded \n" if ($verbose > 1);
	warn "Lines in $MAILLOG: ".scalar(@MAILLOGarray)."\n" if ($verbose>1);
	if ($verbose > 3) {
		warn "$MAILLOG entries: \n";
		foreach (@MAILLOGarray) {
			warn $_;
		}
	}
}

sub addMAILLOGBADLIST {
	warn "Running sub addMAILLOGBADLIST\n" if ($verbose > 2);
#Description: So far only looks for "did not issue MAIL/EXPN/VRFY/ETRN" and gets the IP from that.
#Assumptions:
#	Assumes @MAILLOGarry has been loaded
	warn "BADIPS size before adding from \@MAILLOGarray : ".keys( %BADIPS )."\n" if ($verbose>2);
	foreach my $REGEXP (@BLOCKEDMAILarray) {
		warn "\$REGEXP being checked: $REGEXP \n" if ($verbose>3);
		my @LIST = grep(/$REGEXP/, @MAILLOGarray);
		foreach (@LIST) {
			chomp;
			s/^.*\[//;
			s/\].*$//;
			s/!^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$//;
			$BADIPS{$_} = "$MAILLOG -- $REGEXP" if ( $_ =~ m/^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$/ );
		}
	}
	warn "BADIPS size after adding from \@MAILLOGarray: ".keys( %BADIPS )."\n" if ($verbose>2);
	if ($verbose>3) { 
		warn "\%BADIPS entries: \n";
		foreach my $key (sort keys %BADIPS) {
			warn "$key: ".$BADIPS{$key}." \n";
		}
	}
}

sub addAUTHLOGGOODLIST {
	warn "Running sub addAUTHLOGGOODLIST\n" if ( $verbose > 2 );
# Description opens the auth log and looks for IPs associated with any "good" username.  Those IPs are added to %GOODIPS.
# Assumptions: 
#		Assumes @AUTHLOGarray has already been loaded.
#		Assumes @USERNAMESarray has been setup
	warn "GOODIPS size before adding from \@AUTHLOGarray: ".keys( %GOODIPS )."\n" if ($verbose>2);
	foreach my $REGEXP (@USERNAMESarray) {
		warn "\$REGEXP being checked: $REGEXP \n" if ($verbose>3);
		my @LIST = grep(/$REGEXP/, @AUTHLOGarray);
		foreach (@LIST) {
			chomp;
			s/^.*from //;
			s/ port.*$//;
			s/^\s+//;
			s/\s+$//;
			s/!^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$//;
			$GOODIPS{$_} = "$AUTHLOG -- $REGEXP" if ( $_ =~ m/^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$/ );
		}
	}
	warn "GOODIPS size after adding from \@AUTHLOGarray: ".keys( %GOODIPS )."\n" if ($verbose>2);
	if ($verbose>3) { 
		warn "\%GOODIPS entries: \n";
		foreach my $key (sort keys %GOODIPS) {
			warn "$key: ".$GOODIPS{$key}." \n";
		}
	}
}

sub addAUTHLOGBADLIST {
	warn "Running sub addAUTHLOGBADLIST\n" if ($verbose>2);
#Description: Runs through @AUTHLOGarray and looks for various regular expressions from AUTHLOGBADREGEXPs.  
#						It parses those regular expressions to get IPs.  Those IPs are added to %BADIPS.
# Assumptions: 
#		Assumes @AUTHLOGarray has already been loaded.
#		Assumes $AUTHLOGBADREGEXPsarray has been setup

	warn "BADIPS size before adding from \@AUTHLOGarray: ".keys( %BADIPS )."\n" if ($verbose>2);
	foreach my $REGEXP (@AUTHLOGBADREGEXPsarray) {
		warn "\$REGEXP being checked: $REGEXP \n" if ($verbose>3);
		my @LIST = grep(/$REGEXP/, @AUTHLOGarray);
		foreach (@LIST) {
			chomp;
			s/^.*from //;
			s/ port.*$//; 
			s/^\s+//;
			s/\s+$//;
			s/!^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$//;
			if ( $_ =~ m/^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$/ ) {
				$BADIPS{$_} = "$AUTHLOG -- $REGEXP";
			}
		}
	}
	warn "BADIPS size after adding from \@AUTHLOGarray: ".keys( %BADIPS )."\n" if ($verbose>2);
	if ($verbose>3) { 
		warn "\%BADIPS entries: \n";
		foreach my $key (sort keys %BADIPS) {
			warn "$key: ".$BADIPS{$key}." \n";
		}
	}
}

sub addQUERYLOGBADLIST {
	warn "Running sub addQUERYLOGBADLIST\n" if ($verbose>2);
#Description: Runs through @QUERYLOGarray and looks for various regular expressions from @QUERYLOGBADREGEXPs.  
#						It parses those regular expressions to get IPs.  Those IPs are added to %BADIPS.
# Assumptions: 
#		Assumes @QUERYLOGarray has already been loaded.
#		Assumes $QUERYLOGBADREGEXPsarray has been setup

	warn "BADIPS size before adding from \@QUERYLOGarray: ".keys( %BADIPS )."\n" if ($verbose>2);
	foreach my $REGEXP (@QUERYLOGBADREGEXPsarray) {
		warn "\$REGEXP being checked: $REGEXP \n" if ($verbose>3);
		my @LIST = grep(/$REGEXP/, @QUERYLOGarray);
		foreach (@LIST) {
			chomp;
			s/^.*client //;
			s/#[0-9].*$//;
			s/^\s+//;
			s/\s+$//;
			s/!^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$//;
			$BADIPS{$_} = "$QUERYLOG -- $REGEXP" if ( $_ =~ m/^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$/ );
		}
	}
	warn "BADIPS size after adding from \@QUERYLOGarray: ".keys( %BADIPS )."\n" if ($verbose>2);
	if ($verbose>3) { 
		warn "\%BADIPS entries: \n";
		foreach my $key (sort keys %BADIPS) {
			warn "$key: ".$BADIPS{$key}." \n";
		}
	}
}

sub addBLOCKEDIPSBADLIST {
	warn "Running sub addBLOCKEDIPSBADLIST \n" if ($verbose>2);
#Description: Runs through @BLOCKEDIPSarray and adds each to %BADIPS
# Assumptions: 
#		Assumes @BLOCKEDIPSarray has already been loaded.

	warn "BADIPS size before adding from \@BLOCKEDIPSarray: ".keys( %BADIPS )."\n" if ($verbose>2);
	foreach (@BLOCKEDIPSarray) {
		s/!^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$//;
		warn "$_ being added. \n" if ($verbose>3);
		$BADIPS{$_} = "\@BLOCKEDIPSarray -- $_" if ( $_ =~ m/^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$/ );
	}
	warn "BADIPS size after adding from \@BLOCKEDIPSarray: ".keys( %BADIPS )."\n" if ($verbose>2);
	if ($verbose>3) { 
		warn "\%BADIPS entries: \n";
		foreach my $key (sort keys %BADIPS) {
			warn "$key: ".$BADIPS{$key}." \n";
		}
	}
}

sub addALLOWEDIPSGOODLIST {
	warn "Running sub addALLOWEDIPSGOODLIST \n" if ($verbose>2);
#Description: Runs through @ALLOWEDIPSarray and adds each to %GOODIPS
# Assumptions: 
#		Assumes @ALLOWEDIPSarray has already been loaded.

	warn "GOODIPS size before adding from \@ALLOWEDIPSarray: ".keys( %GOODIPS )."\n" if ($verbose>2);
	foreach (@ALLOWEDIPSarray) {
		s/!^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$//;
		warn "$_ being added. \n" if ($verbose>3);
		$GOODIPS{$_} = "\@ALLOWEDIPSarray -- $_" if ( $_ =~ m/^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$/ );
	}
	warn "GOODIPS size after adding from \@ALLOWEDIPSarray: ".keys( %GOODIPS )."\n" if ($verbose>2);
	if ($verbose>3) { 
		warn "\%GOODIPS entries: \n";
		foreach my $key (sort keys %GOODIPS) {
			warn "$key: ".$GOODIPS{$key}." \n";
		}
	}
}

sub addALLOWEDFQDNSGOODLIST {
	warn "Running sub addALLOWEDFQDNSGOODLIST \n" if ($verbose>2);
#Description: Runs through the @ALLOWEDFQDNSarray, gets the IPs for each FQDN from DNS, adds the IPs to %GOODIPS
#Requires: 
#	NetAddr::IP::Util qw(inet_ntoa)
#	Net::DNS::Dig
#Assumptions:
#	Assumes @ALLOWEDFQDNSarray is set

	warn "GOODIPS size before adding from \@ALLOWEDFQDNSarray: ".keys( %GOODIPS )."\n" if ($verbose>2);
	foreach my $FQDN (@ALLOWEDFQDNSarray) {
		warn "Working on $FQDN \n" if ($verbose>3);
		my @netaddrs = Net::DNS::Dig->new()->for( $FQDN )->rdata();
		foreach ( @netaddrs ) {
			 my $IP = inet_ntoa( $_ );
			 $GOODIPS{$IP} = "\@ALLOWEDFQDNS -- $FQDN";
		}
	}
	warn "GOODIPS size after adding from \@ALLOWEDFQDNSarray: ".keys( %GOODIPS )."\n" if ($verbose>2);
	if ($verbose>3) { 
		warn "\%GOODIPS entries: \n";
		foreach my $key (sort keys %GOODIPS) {
			warn "$key: ".$GOODIPS{$key}." \n";
		}
	}
}

sub addBLOCKEDFQDNSBADLIST {
	warn "Running sub addBLOCKEDFQDNSBADLIST \n" if ($verbose>2);
#Description: Runs through the @BLOCKEDFQDNSarray, gets the IPs for each FQDN from DNS, adds the IPs to %BADIPS
#Requires: 
#	NetAddr::IP::Util qw(inet_ntoa)
#	Net::DNS::Dig
#Assumptions:
#	Assumes @BLOCKEDFQDNSarray is set

	warn "BADIPS size before adding from \@BLOCKEDFQDNSarray: ".keys( %BADIPS )."\n" if ($verbose>2);
	foreach my $FQDN (@BLOCKEDFQDNSarray) {
		warn "Working on $FQDN \n" if ($verbose>3);
		my @netaddrs = Net::DNS::Dig->new()->for( $FQDN )->rdata();
		foreach ( @netaddrs ) {
			 my $IP = inet_ntoa( $_ );
			 $BADIPS{$IP} = "\@BLOCKEDFQDNS -- $FQDN";
		}
	}
	warn "BADIPS size after adding from \@BLOCKEDFQDNSarray: ".keys( %BADIPS )."\n" if ($verbose>2);
	if ($verbose>3) { 
		warn "\%BADIPS entries: \n";
		foreach my $key (sort keys %BADIPS) {
			warn "$key: ".$BADIPS{$key}." \n";
		}
	}
}

sub deleteDUPLICATEGOODBADLIST {
	warn "Running sub deleteDUPLICATEGOODBADLIST \n" if ($verbose>2);
#Description: Deletes IPs from %BADLIST that are in %GOODLIST

	warn "BADIPS size before deleting duplicates from \%GOODIPS: ".keys( %BADIPS )."\n" if ($verbose>2);
	foreach my $key (keys %GOODIPS) {
		delete $BADIPS{ $key };
	}
	warn "BADIPS size after deleteing duplicates from \%GOODIPS: ".keys( %BADIPS )."\n" if ($verbose>2);
	if ($verbose>3) { 
		warn "\%BADIPS entries: \n";
		foreach my $key (sort keys %BADIPS) {
			warn "$key: ".$BADIPS{$key}." \n";
		}
	}
}

sub deleteDUPLICATEIPTABLESBADLIST {
	warn "Running sub deleteDUPLICATEIPTABLESBADLIST \n" if ($verbose>2);
#Description: Deletes IPs from %BADLIST that are in \@IPTABLES
#Assumptions:  
#		Ablity to run /sbin/iptables

	my @IPTABLES=`/sbin/iptables -n -L DROPLIST`;
	warn "BADIPS size before deleting duplicates from \@IPTABLES: ".keys( %BADIPS )."\n" if ($verbose>2);
	my @LIST = grep(/^DROP/,@IPTABLES);
	foreach (@LIST) {
		chomp;
		s/^.*--//;
		s/0\.0\.0\.0.*$//;
		s/^\s+//;
		s/\s+$//;
		s/!^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$//;
		if ( $_ =~ m/^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$/ ) {
			delete $BADIPS{$_};
		}
	}
	warn "BADIPS size after deleteing duplicates from \@IPTABLES: ".keys( %BADIPS )."\n" if ($verbose>2);
	if ($verbose>3) { 
		warn "\%BADIPS entries: \n";
		foreach my $key (sort keys %BADIPS) {
			warn "$key: ".$BADIPS{$key}." \n";
		}
	}
}

sub addIPTableEntries {
	warn "Running addIPTableEntries \n" if ($verbose>2);
#Description: Adds the keys from %BADIPS to be blocked in iptables
#Uses:
#	sub setCurrentLocalDateTimeValues
#Assumptions:
#	Ability to run iptables
#	"DROPLIST" is a chain that exists in iptables
#	iptables runs from /sbin/iptables

	setCurrentLocalDateTimeValues();
	my $subLOGFILE = "$LOGFILE.$year$mon$mday";
	my $dt = "$year-$mon-$mday $hour:$min:$sec";
	open FILE, ">>", $subLOGFILE or die $!;
	foreach (keys %BADIPS) {
		my @output = `/sbin/iptables -I DROPLIST 1 -s $_ -j LOG --log-level 1 --log-prefix "LOGDROP $_ :"`;
		@output = `/sbin/iptables -I DROPLIST 2 -s $_ -j DROP`;
		printf FILE "%-20s", $dt; 
		printf FILE "%-20s", $_; 
		printf FILE "%-35s", $BADIPS{$_};
		printf FILE " -- added to iptables \n";
	}
	close FILE;
#
#	my @output = `/sbin/iptables-save -c`;
#	open FILEa, ">", "/root/iptables-save.out" or die $!;
#	open FILEb, ">", "/root/iptables-save.out.$year-$mon-$mday" or die $!;
#	foreach (@output) { 
#		print FILEa $_;
#		print FILEb $_; 
#	}
#	close FILEa;
##	foreach (@output) { print FILE $_ };
#	close FILEb;
}
