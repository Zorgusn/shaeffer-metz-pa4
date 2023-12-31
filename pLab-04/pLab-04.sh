#!/bin/bash
echo
echo "Script to test pLab-04"
echo "By: Mohamed Aboutabl, Hudson Shaeffer, & Zane Metz"

rm -f dispatcher   kdc/kdc             kdc/logKDC.txt    
rm -f amal/amal    amal/logAmal.txt  
rm -f basim/basim  basim/logBasim.txt

# make sure Aboutabl executable have the 'x' flag
chmod +x  *Dispatched_aboutabl*

echo "***************************************"
echo "Testing STUDENT's Dispatcher"  
echo "   with ABOUTABL'S amal, basim, and kdc"
echo "***************************************"

	cp  kdcDispatched_aboutabl   kdc/kdc             
	cp  amalDispatched_aboutabl  amal/amal             
	cp  basimDispatched_aboutabl basim/basim
	gcc wrappers.c     dispatcher.c -o dispatcher

    ./dispatcher

	echo "======  KDC    LOG  ========="
    cat kdc/logKDC.txt

    echo
    echo "======  Amal   LOG  ========="
    cat amal/logAmal.txt

    echo
    echo "======  Basim  LOG  ========="
    cat basim/logBasim.txt
    echo
