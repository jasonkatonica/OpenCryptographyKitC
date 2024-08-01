#!/bin/sh
VERBOSE=0
if [ $1 ] ; then
    if [ $1 = "verbose" ]; then
      VERBOSE=1
    fi
fi
                
#
# Print output, only if VERBOSE=1
#
function verbose {
# $1 $2 $3 etc input text
   if [ ${VERBOSE} = 1 ] ; then
      echo $*
   fi
}
                          
function run_test {
# $1 the error number to trigger
# $2 Set/Unset ICC_IGNRE_FIPS
   verbose "Test $1 - ICC_IGNORE_FIPS = $2"
   export ICC_INDUCED_FAILURE=$1;export ICC_IGNORE_FIPS=$2;./icctest
}

function run_tests {
# $2 ICC_IGNORE_FIPS setting
   for x in 0 1 3 10 11 24 25 51 53 71 72 73 91 92 93 94 95 96 97
   do
      run_test $x $1
   done
}

run_tests "no"
run_tests "yes"
 