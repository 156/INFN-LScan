package INFN::LScan;

use 5.018001;
use strict;
use warnings;

use DBI;
use File::Find;

use Digest::MD5;

require Exporter;

our @ISA = qw(Exporter);
our %EXPORT_TAGS = ( 'all' => [ qw() ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

our $VERSION = '0.1';
our $NAME = 'INFN::LScan';

our $dbh;

our @files;


sub new {  bless {}, shift; }

sub get_name
{
	my $self = shift;
	return ($NAME);
}

sub get_version
{
	my $self = shift;
	return ($VERSION);
}

sub dbc
{
	my $self = shift;
	my $cmd = shift;
	
	eval {
		$dbh->do($cmd);
	};
	return $@;
}

sub open_database
{
	my $self = shift;
	my $sfile = shift;
	
	$dbh = DBI->connect(
		"dbi:SQLite:dbname=$sfile",
		"",
		"",
		{ RaiseError => 1, AutoCommit => 1},
		) or die $DBI::errstr;
}

sub check_database
{
	my $self = shift;
	my $mode = shift;
	
	my $a = $dbh->selectall_arrayref("SELECT id, filename FROM files");
	
	foreach my $b(@$a)
	{
		my ($file_id, $file_name) = @$b;
		
		my $fd;
		my $md5;
		my $md5_old;
		
		my $digest = Digest::MD5->new;

		open $fd, "$file_name";
		
		$digest->addfile($fd);
		
		$md5 = $digest->hexdigest;
		$md5_old = old_md5($file_id);
		
		if ($mode == 1) { print "$file_name -> $md5 - $md5_old ok\n" if ($md5 eq $md5_old); }
		print "$file_name -> $md5 - $md5_old corrupt\n" if ($md5 ne $md5_old);
		
		close ($fd);
	}
}

sub old_md5
{	my $id = shift;
	
	my $md5;

	my @row = $dbh->selectall_arrayref("SELECT id, hash FROM md5 WHERE id='$id'");
	
	foreach my $r(@row)
	{
		my ($n, $d) = @$r;
		my ($n_id, $n_md5) = @$n;
		
		if ($n_id == $id) { $md5 = $n_md5; }
	}
	
	return($md5);
}

sub f_to_database
{
	my $self = shift;
	foreach my $f(@files)
	{
		my $digest = Digest::MD5->new;
		if (!-d $f)
		{
			my $FD;
			open $FD, "$f";
			
			$digest->addfile($FD);
			
			$self->dbc("INSERT INTO files  VALUES (NULL, '$f')");
			$self->dbc("INSERT INTO md5  VALUES (NULL, '" . $digest->hexdigest . "')");

			print $f . " ok\n";
			close $FD;
		}
	}
}

sub add_files
{
	my $self = shift;
	my $dir = shift;
	
	find(\&file_callback, $dir);
}

sub file_callback
{
	my $file = $_;
	push @files, $File::Find::name;
}
	
sub intr {int(sprintf("%.0f",shift))}

1;
__END__

=head1 NAME

INFN::LScan - Perl extension for md5 file integrity based intrusion detection

=head1 SYNOPSIS

  use INFN::LScan;
  
  my $lscan = new INFN::LScan;
  #etc
=head1 DESCRIPTION

This is the documentation for INFN::LScan md5 file based intrusion detection system that uses sqlite

=head2 EXPORT

None by default.



=head1 SEE ALSO

This will require a couple of modules.

=head1 AUTHOR

The Infinity Network (http://theinfinitynetwork.org/)

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 by The Infinity Network (http://theinfinitynetwork.org/)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.18.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
