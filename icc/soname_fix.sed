#
# It's insanely difficult tio escape the $$ characters from within make
#   so the Makefile edits this sed script to set the soname 
#   (by replacing "SONAME") to the one make knows about then uses the edited 
#   script to drive sed to do the actual edit.
# Amazingly complex, but at least it achieves the result which is to set 
#   the soname to that of the final library name.
#
s/\-soname\=\$\$SHLIB\$\$SHLIB_SOVER\$\$SHLIB_SUFFIX/\-soname\=SONAME/
s/\-soname\,\$\$SHLIB\$\$SHLIB_SOVER\$\$SHLIB_SUFFIX/\-soname\,SONAME/
