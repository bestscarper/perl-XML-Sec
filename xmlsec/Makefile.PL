use ExtUtils::MakeMaker;
my $my_inc = `xmlsec-config --ccflags`;
my $my_libs = `xmlsec-config --libs`;

$Verbose = 1;
WriteMakefile(
	NAME   => 'Mytest2::xmlsec',
	LIBS   => [$mylib], # e.g., '-lm'
    	DEFINE => '', # e.g., '-DHAVE_SOMETHING'
    	INC    => '-I. ' . $myinc, # e.g., '-I. -I/usr/include/other'

	SKIP   => [qw(all static static_lib dynamic dynamic_lib)],
	clean  => {'FILES' => 'libxmlsec$(LIBEEXT)'},
);

sub MY::top_targets {
'
all :: static

pure_all :: static

static ::       libxmlsec$(LIB_EXT)

libxmlsec$(LIB_EXT): $(O_FILES)
	$(AR) cr libxmlsec$(LIB_EXT) $(O_FILES)
	$(RANLIB) libxmlsec$(LIB_EXT)

';
}  
