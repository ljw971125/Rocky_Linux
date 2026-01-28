OUTPUT_FILE="Test_Result.txt"
REPORT_FILE="Test_Report.csv"
printf "\xEF\xBB\xBF" > "$REPORT_FILE"

echo "===================================" >> $OUTPUT_FILE
echo "           보 안 점 검             " >> $OUTPUT_FILE
echo "===================================" >> $OUTPUT_FILE

echo -e "\n[0]OS 버전 정보 확인" >> $OUTPUT_FILE
cat /etc/rocky-release >> $OUTPUT_FILE


echo -e "\n[1]root 계정 원격 로그인 가능 여부 확인" >> $OUTPUT_FILE
SSH_CONF="/etc/ssh/sshd_config.d/01-permitrootlogin.conf"

if [ -f "$SSH_CONF" ]; then
	ROOT_LOGIN_VAL=$(grep -i "^PermitRootLogin" $SSH_CONF | awk '{print $2}')
	
	if [ "$ROOT_LOGIN_VAL" == "no" ]; then
	    echo -e "[양호] Root 원격 접속이 차단되어 있습니다. (설정값: $ROOT_LOGIN_VAL)" >> $OUTPUT_FILE
	    echo -e "[1], 원격 접속 차단되어 있음, 양호" >> $REPORT_FILE
	else
	    echo -e "[취약] Root 원격 접속이 허용되어 있거나 설정이 미흡합니다." >> $OUTPUT_FILE
	    echo -e "권장 설정값: no (현재 설정값(PermitRootLogin) : $ROOT_LOGIN_VAL)" >> $OUTPUT_FILE
	    echo -e "[2], 원격 접속 차단되어 있지 않음, 취약" >> $REPORT_FILE
	fi
fi

echo -e "\n[1-2]Telnet 서비스 실행 여부 확인" >> $OUTPUT_FILE

if rpm -qa | grep -q "telnet-server"; then
	echo "[취약] Telnet-server 패키지가 설치되어 있습니다." >> $OUTPUT_FILE

	if systemctl is-active --quiet telnet.socket; then
	    echo "[취약] Telnet 서비스가 실행 중입니다." >> $OUTPUT_FILE 
	else
	    echo "[양호] 패키지는 설치되어 있으나 서비스가 중지되어 있습니다." >> $OUTPUT_FILE
	fi
else
    echo "[양호] Telnet-server 패키지가 설치되어 있지 않습니다." >> $OUTPUT_FILE
fi


echo -e "\n[2]비밀번호 최소 사용,변경 기간 점검" >> $OUTPUT_FILE
LOGIN_DEFS="/etc/login.defs"

if [ -f "$LOGIN_DEFS" ]; then
	PASS_CHANGE_MAX_VAL=$(grep -i "^PASS_MAX_DAYS" $LOGIN_DEFS | awk '{print $2}')
	PASS_CHANGE_MIN_VAL=$(grep -i "^PASS_MIN_DAYS" $LOGIN_DEFS | awk '{print $2}')
	if [ "$PASS_CHANGE_MAX_VAL" -ge 90 ] && [ "$PASS_CHANGE_MIN_VAL" -ge 3 ]; then
	    echo -e "[양호] 비밀번호 최소 사용,변경 기간이 설정되어 있습니다." >> $OUTPUT_FILE
	else
	    echo -e "[취약] 비밀번호 최소 사용,변경 기간이 설정되어있지 않습니다." >> $OUTPUT_FILE
	    echo -e "비밀번호 최소 변경 기간 : 90일 이상(현재 설정값(PASS_CHANGE_MAX_VAL) : $PASS_CHANGE_MAX_VAL)" >> $OUTPUT_FILE
	    echo -e "비밀번호 최소 사용 기간 : 3일 이상(현재 설정값(PASS_CHANGE_MIN_VAL) : $PASS_CHANGE_MIN_VAL)" >> $OUTPUT_FILE
	fi
fi


echo -e "\n[3]비밀번호 정책 점검" >> $OUTPUT_FILE
PWQ_CONF="/etc/security/pwquality.conf"

if [ -f "$PWQ_CONF" ]; then
	MIN_LEN_VAL=$(grep -i "^minlen" $PWQ_CONF | awk '{print $3}')
	DCREDIT_VAL=$(grep -i "^dcredit" $PWQ_CONF | awk '{print $3}')
	UCREDIT_VAL=$(grep -i "^ucredit" $PWQ_CONF | awk '{print $3}')
	LCREDIT_VAL=$(grep -i "^lcredit" $PWQ_CONF | awk '{print $3}')
	OCREDIT_VAL=$(grep -i "^ocredit" $PWQ_CONF | awk '{print $3}')
	if [ "$MIN_LEN_VAL" -ge 8 ] && [ "$DCREDIT_VAL" == -1 ] && [ "$UCREDIT_VAL" == -1 ] && [ "$LCREDIT_VAL" == -1 ] && [ "$OCREDIT_VAL" == -1 ] && [ "$ENFORCE_FOR_ROOT_VAL" ]; then
	    echo "[양호] 비밀번호 정책이 보안정책에 맞게 설정되어 있습니다." >> $OUTPUT_FILE
	else
	    echo "[취약] 비밀번호 정책이 보안정책에 위반됩니다." >> $OUTPUT_FILE
	    echo -e "최소 비밀번호 개수 : 8자리 이상(현재 설정값(minlen) : $MIN_LEN_VAL)" >> $OUTPUT_FILE
	    echo -e "최소 숫자(decredit)  필수 입력값 : -1 (현재 설정값(dcredit) : $DCREDIT_VAL)" >> $OUTPUT_FILE
	    echo -e "최소 대문자(ucredit) 필수 입력값 : -1 (현재 설정값(ucredit) : $UCREDIT_VAL)" >> $OUTPUT_FILE
	    echo -e "최소 소문자(lcredit) 필수 입력값 : -1 (현재 설정값(lcredit) : $LCREDIT_VAL)" >> $OUTPUT_FILE
	    echo -e "최소 특수문자(ocredit) 필수 입력값 : -1 (현재 설정값(ocredit) : $OCREDIT_VAL)" >> $OUTPUT_FILE
	fi
	
	ENFORCE_FOR_ROOT_VAL=$(grep "^enforce_for_root" $PWQ_CONF)

	echo -e "\n[3-1]비밀번호 정책 점검(root)" >>$OUTPUT_FILE
	if [ "$ENFORCE_FOR_ROOT_VAL" ]; then
	    echo "[양호] root 계정 비밀번호 정책이 적용되어 있습니다." >> $OUTPUT_FILE
	else
	    echo "[취약] root 계정 비밀번호 정책이 적용되어 있지 않습니다.(enforce_for_root 적용 필요)" >> $OUTPUT_FILE
	fi	
fi
