#!/usr/bin/perl

# The work represented by this source file is partially or entirely funded
# by the EGI-InSPIRE project through the European Commission's 7th Framework
# Programme (contract # INFSO-RI-261323)
#
# Copyright 2014 IASA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at [http://www.apache.org/licenses/LICENSE-2.0| Apache License 2.0]
#
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#################################################################################
# Version: 1.0.0 (initial)
# Date: 2014-06-16
# Author: mhaggel@iasa.gr
# Description: Nagios probe for AppDB workflow.
#################################################################################


use strict;
use warnings;

use LWP::UserAgent;
use JSON;
use DateTime;
use DateTime::Format::Strptime;
use DateTime::TimeZone;
use Getopt::Std;
use vars qw(%options $opt_c $opt_w $opt_u %exit_codes);

$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0 ;
%exit_codes   = ('UNKNOWN' ,-1,
                 'OK'      , 0,
                 'WARNING' , 1,
                 'CRITICAL', 2,);

sub usage{
  print "\nappdb-cloud-probe.pl v1.0 - Nagios Plugin\n\n";
  print "usage:\n";
  print " appdb-cloud-probe.pl -u <IMAGE LIST URI> -w <warnlevel> -c <critlevel>\n\n";
  print "options:\n";
  print " -u           Image list URI\n";
  print " -w (hours)   Number of hours when to warn\n";
  print " -c (hours)   Number of hours when critical\n";
  exit $exit_codes{'UNKNOWN'};
}


sub dateDiff{

        my $date_created = shift;
        my $tz = DateTime::TimeZone->new( name => 'UTC');
        my $dt_now = DateTime->now( time_zone => $tz );

        my $format = DateTime::Format::Strptime->new(
                pattern   => '%FT%TZ',
                time_zone => 'UTC',
                on_error  => 'croak',
                );
        my $dt_created = $format->parse_datetime($date_created);
        my $dt_diff = $dt_now->epoch() - $dt_created->epoch();
        #print $dt_now->epoch()." - ".$dt_created->epoch()."/n";
        #print $date_created;
        return $dt_diff;

}

sub check {
        my $WARNING_THERSHOLD_IN_HOURS=shift;
        my $ERROR_THERSHOLD_IN_HOURS=shift;
        my $VA_URI=shift;
        my $json_start = '{';
        my $json_end = '}';
        my $date_created="";
        my $date_diff=0;



        my $ua = LWP::UserAgent->new;
                $ua->timeout(10);
                $ua->env_proxy;


#        my $response = $ua->get("https://vmcaster.appdb.egi.eu/store/vappliance/fedcloud.monitoring.va/image.list");
        my $response = $ua->get($VA_URI);

        if ($response->is_success) {

                my $start = index($response->decoded_content, $json_start);
                my $end = rindex($response->decoded_content, $json_end) +1;
                my $json_data=substr($response->decoded_content, $start, $end-$start);

                my $json = JSON->new->allow_nonref;
                my $perl_scalar = $json->decode( $json_data );

                if( not exists($perl_scalar->{'egiappdb'}) ){
                        $date_created = $perl_scalar->{'hv:imagelist'}->{'dc:date:created'};
                        $date_diff = dateDiff($date_created);

                        if($date_diff > (60 * 60 * $WARNING_THERSHOLD_IN_HOURS) and $date_diff < (60 * 60 * $ERROR_THERSHOLD_IN_HOURS)) {
                                print "WARNING: last updated ".$date_diff." sec a go";
                                exit $exit_codes{'WARNING'};
                        } elsif ($date_diff <= (60 * 60 * $WARNING_THERSHOLD_IN_HOURS)){
                                print "OK: last updated ".$date_diff." sec a go";
                                exit $exit_codes{'OK'};
                        }
                }else{
                        print "CRITICAL: Image List does non exist in AppDB";
                        exit $exit_codes{'CRITICAL'};
                }
        } else {
#                print $response->status_line;
                print "CRITICAL: HTTP server error";
                exit $exit_codes{'CRITICAL'};
        }

        print "CRITICAL: General critical error occurred";
        exit $exit_codes{'CRITICAL'};
}

#################################################################################
### MAIN
#################################################################################
if ($#ARGV le 0)
{
        &usage;
}
else
{
        getopts('c:w:u:');
}
if (!$opt_w or $opt_w == 0 or !$opt_c or $opt_c == 0)
{
        print "*** You must define WARN and CRITICAL levels!";
        &usage;
}

if ($opt_w >= $opt_c)
{
        print "*** WARN level must not be greater than CRITICAL";
        &usage;
}

if(!$opt_u)
{
        print "*** Image list URI must be specified";
        &usage;
}

check($opt_w, $opt_c, $opt_u);
#################################################################################

