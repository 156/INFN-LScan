use 5.018001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'INFN::LScan',
    VERSION_FROM      => 'lib/INFN/LScan.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/INFN/LScan.pm', # retrieve abstract from module
       AUTHOR         => 'am toor <chao@>') : ()),
);
