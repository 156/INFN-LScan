#!/usr/bin/perl

use File::Find;
no warnings 'File::Find';

use Getopt::Long;

require INFN::LScan;

my $lscan = new INFN::LScan;

my ($dir, $help, $check, $setup, $ok, $sqlite_file, $rootkits);

my $opt = GetOptions(	"directory=s" => \$dir,
					"file=s" => \$sqlite_file,
					"setup" => \$setup,
					"check" => \$check,
					"ok" => \$ok,
					"rootkits=s" => \$rootkits,
					"help" => \$help);
					
$sqlite_file |= 'lscan.sqlite';
$ok |= 0;

$lscan->open_database("$sqlite_file");

my @vuln = (
	'\.\.\.',
	'\/\.ssh',
	'\.ssh\/',
	'\.kinetic',
	'worm\/',
	'\/\-sh',
	'arobia',
	'\/lkm',
	'bktools',
	'\/bex',
	'wted',
	'xfss',
	'dsx',
	'dika',
	'fuckit',
	'ivtype',
	'lports',
	'toolz',
	'gaskit',
	'funces',
	'\/ixinit',
	'h4x',
	'kbeast',
	'knark',
	'\/xsf\/',
	'xchk',
	'\/ph1',
	'uNF',
	'\/unf\/',
	'rkit',
	'zup',
	'tk02',
	'lpstree',
	'lkill',
	'\/ldu',
	'lnetstat',
	'vadim',
	'scannah',
	'ttyo',
	'bugtraq',
	'cinik',
	'chrps',
	'linsniff',
	'charbd',
	'initsk',
	'initxr',
	'sk12',
	'S23kmdac',
	'tehdrak',
	'\/MG\/',
	'backsh',
	'izbtrag',
	'sksniff',
	'TeleKiT',
	'hda06',
	'lsniff',
	't0rn',
	'lib\/lib\/',
	'buloc',
	'tcpshell',
	'libtcs',
	'wold',
	'whoold',
	'backdoors',
	'sshd2_config',
	'xxxxxx',
	'tulz',
	'lulz',
	'ras2\/',
	'sourcemas',
	'xmx',
	'kdx',
	'\/psr',
	'\/ice\/'
);
	
if ($dir)
{
	$lscan->add_files($dir);
	$lscan->f_to_database();
}

if ($check)
{
	$lscan->check_database($ok);
}

if ($rootkits)
{
	find({wanted=> \&file_callback, follow => 0}, $rootkits);
}

if ($help)
{
	print "Using module " . $lscan->get_name() . " " . $lscan->get_version() . "\n";
	print "-s setup or for new database creation\n";
	print "-d <directory> add directory and recursive sub dirs\n";
	print "-f <filename> sqlite database filename to use. lscan.sqlite will be used if none is specified\n";
	print "-c check\n";
	print "-o print ok file with md5 match\n";
	print "-r <directory> scans a directory for rootkits and related malicious files";
	print "-h this help output\n";
	
	die;
}

if ($setup)
{
	$lscan->dbc("CREATE TABLE files (id INTEGER PRIMARY KEY, filename)");
	$lscan->dbc("CREATE TABLE md5 (id INTEGER PRIMARY KEY, hash)");
}

sub file_callback
{
	-l && !-e && next;
	my $file = $File::Find::name;

	if ($file) { foreach my $v(@vuln) { print (localtime() . " *warning* /" . $v . "/ found " . $file . "\n") if ($file =~ /$v/); } }

}