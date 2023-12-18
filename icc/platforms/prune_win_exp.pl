#
# When we tried to shrink the size of the openssl libs
# we shipped on Windows we hit a problem in that the 
# exports file ... libeay32.def now contains symbols
# which don't exist in the linked objects, so
# we need to strip out the unused symbols.
#
$prefix = shift;
chomp($prefix);
$excludes = shift;
#print "Prefix = $prefix , Excludes = $excludes\n";

open ( $fd, "<", $excludes) or die "Could not open exluded symbol file $excludes";

my @exlist = readline($fd);

chomp(@exlist);
#print "Exlist = @exlist\n";

close($fd);

my $found = 0;
my $line = "";
my $cmp = "";
  while ($line = <STDIN>) {
    chomp ($line);
#    print "Line - \"$line\"\n";
    @lines = split / /, $line;
#    print "\"@lines\"\n";
    $cmp = @lines[4];
#    printf "cmp \"$cmp\"\n";
    $found = 0;
    foreach $tag (@exlist) {
      $tmp = $prefix.$tag;
#      	print "\"$cmp\" \"$tmp\"\n";
      if ( $cmp eq $tmp || $cmp eq $tag ) {
#	print "matched \"$cmp\" \"$tmp\"\n";
	$found = 1;
	last;
      }
    }
    if( 0 == $found ) {  print "$line\n" ; }
  }
