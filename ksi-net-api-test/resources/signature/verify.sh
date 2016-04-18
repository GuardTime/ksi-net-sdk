#!/bin/bash
DIRS="integration-test-signatures"
CONF="--conf /shared_folder/TestFiles/conf.cfg"
for FILE in ./$DIRS/*; do
#        echo "Command: ksi verify --ver-int -i ${FILE:2} $CONF -d --dump"
#	ksi verify --ver-int -i ${FILE:2} $CONF -d --dump
#        echo $?
#	echo ""
#        echo "Command: ksi verify --ver-cal -i ${FILE:2} $CONF -d --dump"
#        ksi verify --ver-cal -i ${FILE:2} $CONF -d --dump
#        echo $?
#        echo ""
#        echo "Command: ksi verify --ver-key -i ${FILE:2} $CONF -d --dump"
#        ksi verify --ver-key -i ${FILE:2} $CONF -d --dump
#        echo $?
#        echo ""
#        echo "Command: ksi verify --ver-pub -i ${FILE:2} $CONF -d --dump"
#        ksi verify --ver-pub -i ${FILE:2} $CONF -d --dump
#        echo $?
#        echo ""
#        echo "Command: ksi verify -i ${FILE:2} $CONF -d --dump"
#        ksi verify -i ${FILE:2} $CONF -d --dump
#        echo $?
        echo "Command Pub file Online: ksi verify --ver-pub -P http://verify.guardtime.com/ksi-publications.bin --cnstr email=publications@guardtime.com -x -i ${FILE:2} $CONF -d --dump"
        ksi verify --ver-pub -P http://verify.guardtime.com/ksi-publications.bin --cnstr email=publications@guardtime.com -x -i ${FILE:2} $CONF -d --dump
        echo $?
        echo ""
        echo "####################################################################################################################################################################################"
        echo ""
        echo "Command String Online: ksi verify --ver-pub --pub-str "AAAAAA-CWYEKQ-AAIYPA-UJ4GRT-HXMFBE-OTB4AB-XH3PT3-KNIKGV-PYCJXU-HL2TN4-RG6SCC-3ZGSBM" -x -i ${FILE:2} $CONF -d --dump"
        ksi verify --ver-pub --pub-str "AAAAAA-CWYEKQ-AAIYPA-UJ4GRT-HXMFBE-OTB4AB-XH3PT3-KNIKGV-PYCJXU-HL2TN4-RG6SCC-3ZGSBM" -x -i ${FILE:2} $CONF -d --dump
        echo $?
        echo ""
        echo "####################################################################################################################################################################################"
        echo ""
        echo "Command String Not Online: ksi verify --ver-pub --pub-str "AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K" -i ${FILE:2} $CONF -d --dump"
        ksi verify --ver-pub --pub-str "AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K" -i ${FILE:2} $CONF -d --dump
        echo $?
        echo ""
        echo "####################################################################################################################################################################################"
        echo ""
        echo "Command Old String: ksi verify --ver-pub --pub-str "AAAAAA-CS2XHY-AAJCBE-DDAFMR-R3RKMY-GMAQDZ-FSAE7B-ZO64CT-QPNC3B-RQ6UGY-67QORK-6STDTS" -x -i ${FILE:2} $CONF -d --dump"
        ksi verify --ver-pub --pub-str "AAAAAA-CS2XHY-AAJCBE-DDAFMR-R3RKMY-GMAQDZ-FSAE7B-ZO64CT-QPNC3B-RQ6UGY-67QORK-6STDTS" -x -i ${FILE:2} $CONF -d --dump
        echo $?
        echo ""
	echo "####################################################################################################################################################################################"
	echo ""
done
