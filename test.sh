OUTPUT_FILE="Test_Result.txt"
#REPORT_FILE="Test_Report.csv"
#printf "\xEF\xBB\xBF" > "$REPORT_FILE"

echo "===================================" >> $OUTPUT_FILE
echo "           보 안 점 검             " >> $OUTPUT_FILE
echo "===================================" >> $OUTPUT_FILE

echo -e "\nU00.OS 버전 정보 확인" >> $OUTPUT_FILE
cat /etc/rocky-release >> $OUTPUT_FILE
echo "U00 점검 완료"

U01_SSH_CONF="/etc/ssh/sshd_config.d/01-permitrootlogin.conf"
echo -e "\n====================================================" >> $OUTPUT_FILE
echo "U01.root 계정 원격 로그인 가능 여부 확인" >> $OUTPUT_FILE
echo ""==================================================== >> $OUTPUT_FILE

echo -e "\n-------------------------------------------------------------" >> $OUTPUT_FILE
echo "점검 진행 파일 : $U01_SSH_CONF" >> $OUTPUT_FILE
echo "-------------------------------------------------------------" >> $OUTPUT_FILE

if [ -f "$U01_SSH_CONF" ]; then
	U01_ROOT_LOGIN_VAL=$(grep -i "^\s*PermitRootLogin" $U01_SSH_CONF | awk '{print $2}')

	echo -e "\nU01_1.SSH root계정 원격 접속 가능 여부 확인" >> $OUTPUT_FILE
	if [ "$U01_ROOT_LOGIN_VAL" ]; then
	    if [ "$U01_ROOT_LOGIN_VAL" == "no" ]; then
	        echo "[양호] Root 원격 접속이 차단되어 있습니다. (설정값: $U01_ROOT_LOGIN_VAL)" >> $OUTPUT_FILE
	        # echo "[1], 원격 접속 차단되어 있음, 양호" >> $REPORT_FILE
	    else
	        echo "[취약] Root 원격 접속이 허용되어 있습니다." >> $OUTPUT_FILE
	        echo "확인 값 : PermitRootLogin" >> $OUTPUT_FILE
	        echo "필수 설정값: no" >> $OUTPUT_FILE
	        echo "현재 설정값: $U01_ROOT_LOGIN_VAL" >> $OUTPUT_FILE
	        # echo -e "[2], 원격 접속 차단되어 있지 않음, 취약" >> $REPORT_FILE
	    fi
        else
	    echo "확인 값 : PermitRootLogin" >> $OUTPUT_FILE
	    echo "[취약] Root 원격 접속이 허용되어 있습니다." >> $OUTPUT_FILE
	    echo "현재 설정값 : 주석" >> $OUTPUT_FILE
	fi
fi

echo -e "\nU01_2.Telnet 서비스 실행 여부 확인" >> $OUTPUT_FILE

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
echo "U01 점검 완료"


echo -e "\n====================================================" >> $OUTPUT_FILE
echo "U02.비밀번호 관리 정책 점검" >> $OUTPUT_FILE
echo "====================================================" >> $OUTPUT_FILE

U02_LOGIN_DEFS="/etc/login.defs"
echo -e "\n---------------------------------" >> $OUTPUT_FILE
echo "점검 진행 파일 : $U02_LOGIN_DEFS" >> $OUTPUT_FILE
echo "---------------------------------" >> $OUTPUT_FILE

if [ -f "$U02_LOGIN_DEFS" ]; then
	U02_PASS_CHANGE_MAX_VAL=$(grep -i "^\s*PASS_MAX_DAYS" $U02_LOGIN_DEFS | awk '{print $2}')
	U02_PASS_CHANGE_MIN_VAL=$(grep -i "^\s*PASS_MIN_DAYS" $U02_LOGIN_DEFS | awk '{print $2}')
	echo -e "\nU02_1.비밀번호 최소 변경 기간 점검" >> $OUTPUT_FILE
	if [ "$U02_PASS_CHANGE_MAX_VAL" ]; then
	    if [ "$U02_PASS_CHANGE_MAX_VAL" -le 90 ]; then
	        echo "[양호] 비밀번호 최소 변경 기간이 설정되어 있습니다." >> $OUTPUT_FILE
	    else
	        echo "[취약] 비밀번호 최소 변경 기간이 설정되어 있지 않습니다." >> $OUTPUT_FILE
	        echo "확인 값 : PASS_MAX_DAYS" >> $OUTPUT_FILE
	        echo "권장 설정 값 : 90일 이상" >> $OUTPUT_FILE
	        echo "현재 설정 값 : $U02_PASS_CHANGE_MAX_VAL" >> $OUTPUT_FILE
	    fi
        else
	    echo "확인 값 : PASS_MAX_DAYS" >> $OUTPUT_FILE
	    echo "[취약] 비밀번호 최소 변경 기간이 설정되어 있지 않습니다." >> $OUTPUT_FILE
	    echo "현재 설정 값 : 주석" >> $OUTPUT_FILE
	fi    
	
	echo -e "\nU02_2.비밀번호 최소 사용 기간 점검" >> $OUTPUT_FILE
	if [ "$U02_PASS_CHANGE_MIN_VAL" ]; then
 	    if [ "$U02_PASS_CHANGE_MIN_VAL" -ge 3 ]; then
	        echo "[양호] 비밀번호 최소 사용 기간이 설정되어 있습니다." >> $OUTPUT_FILE
	    else
	        echo "[취약] 비밀번호 최소 사용 기간이 설정되어 있지 않습니다." >> $OUTPUT_FILE
	        echo "확인 값 : PASS_MIN_DAYS" >> $OUTPUT_FILE
	        echo "권장 설정 값 : 3일 이하" >> $OUTPUT_FILE
	        echo "현재 설정 값 : $U02_PASS_CHANGE_MIN_VAL" >> $OUTPUT_FILE
	    fi
	else
	    echo "확인 값 : PASS_MIN_DAYS" >> $OUTPUT_FILE
	    echo "[취약] 비밀번호 최소 사용 기간이 설정되어 있지 않습니다." >> $OUTPUT_FILE
	    echo "현재 설정 값 : 주석" >> $OUTPUT_FILE
	fi
	
fi

U02_1_PWQ_CONF="/etc/security/pwquality.conf"
echo -e "\n-----------------------------------------------" >> $OUTPUT_FILE
echo "점검 진행 파일 : $U02_1_PWQ_CONF" >> $OUTPUT_FILE
echo "-----------------------------------------------" >> $OUTPUT_FILE

if [ -f "$U02_1_PWQ_CONF" ]; then
	U02_1_MIN_LEN_VAL=$(grep -i "^\s*minlen" $U02_1_PWQ_CONF | awk '{print $3}')
	U02_1_DCREDIT_VAL=$(grep -i "^\s*dcredit" $U02_1_PWQ_CONF | awk '{print $3}')
	U02_1_UCREDIT_VAL=$(grep -i "^\s*ucredit" $U02_1_PWQ_CONF | awk '{print $3}')
	U02_1_LCREDIT_VAL=$(grep -i "^\s*lcredit" $U02_1_PWQ_CONF | awk '{print $3}')
	U02_1_OCREDIT_VAL=$(grep -i "^\s*ocredit" $U02_1_PWQ_CONF | awk '{print $3}')
	U02_1_ENFORCE_FOR_ROOT_VAL=$(grep "^enforce_for_root" $U02_1_PWQ_CONF)
	
	echo -e "\nU02_3.비밀번호 최소 길이" >> $OUTPUT_FILE
	if [ "$U02_1_MIN_LEN_VAL" ]; then
	    if [ "$U02_1_MIN_LEN_VAL" -ge 8 ]; then
	        echo "[양호] 비밀번호 최소 길이 요구값이 보안정책에 맞게 설정되어 있습니다." >> $OUTPUT_FILE
	    else
	        echo "[취약] 비밀번호 최소 길이 요구값이 보안정책에 위반됩니다." >> $OUTPUT_FILE
		echo "확인 값 : minlen" >> $OUTPUT_FILE
	        echo "권장 설정 값 : 8이상" >> $OUTPUT_FILE
	        echo "현재 설정 값 : $U02_1_MIN_LEN_VAL" >> $OUTPUT_FILE
	    fi
        else
	    echo "확인 값 : minlen" >> $OUTPUT_FILE
	    echo "[취약] 비밀번호 최소 길이 요구값이 보안정책에 위반됩니다." >> $OUTPUT_FILE
	    echo "현재 설정 값 : 주석" >> $OUTPUT_FILE
	fi

	echo -e "\nU02_4.비밀번호 최소 숫자 개수" >> $OUTPUT_FILE
	if [ "$U02_1_DCREDIT_VAL" ]; then
	    if [ "$U02_1_DCREDIT_VAL" == -1 ]; then
	        echo "[양호] 비밀번호 최소 숫자 요구값이 보안정책에 맞게 설정되어 있습니다." >> $OUTPUT_FILE
	    else
	        echo "[취약] 비밀번호 최소 숫자 요구값이 보안정책에 위반됩니다." >> $OUTPUT_FILE
		echo "확인 값 : dcredit" >> $OUTPUT_FILE
	        echo "필수 설정 값 : -1" >> $OUTPUT_FILE
	        echo "현재 설정 값 : $U02_1_DCREDIT_VAL" >> $OUTPUT_FILE
	    fi
	else
	    echo "확인 값 : dcredit" >> $OUTPUT_FILE
	    echo "[취약] 비밀번호 최소 숫자 요구값이 보안정책에 위반됩니다." >> $OUTPUT_FILE
	    echo "현재 설정 값 : 주석" >> $OUTPUT_FILE
	fi
	    
	
	echo -e "\nU02_5.비밀번호 최소 대문자 개수" >> $OUTPUT_FILE
	if [ "$U02_1_UCREDIT_VAL" ]; then
	    if [ "$U02_1_UCREDIT_VAL" == -1 ]; then
	        echo "[양호] 비밀번호 최소 대문자 요구값이 보안정책에 맞게 설정되어 있습니다." >> $OUTPUT_FILE
	    else
	        echo "[취약] 비밀번호 최소 대문자 요구값이 보안정책에 위반됩니다." >> $OUTPUT_FILE
		echo "확인 값 : ucredit" >> $OUTPUT_FILE
	        echo "필수 설정 값 : -1" >> $OUTPUT_FILE
	        echo "현재 설정 값 : $U02_1_UCREDIT_VAL" >> $OUTPUT_FILE
	    fi
	else 
	    echo "확인 값 : ucredit" >> $OUTPUT_FILE
	    echo "[취약] 비밀번호 최소 대문자 요구값이 보안정책에 위반됩니다." >> $OUTPUT_FILE
	    echo "현재 설정 값 : 주석" >> $OUTPUT_FILE
	fi

	echo -e "\nU02_6.root 계정 비밀번호 정책 적용 여부" >> $OUTPUT_FILE
	if [ "$U02_1_ENFORCE_FOR_ROOT_VAL" ]; then
	    echo "[양호] root 계정 비밀번호 정책이 적용되어 있습니다." >> $OUTPUT_FILE
	else
	    echo "[취약] root 계정 비밀번호 정책이 적용되어 있지 않습니다." >> $OUTPUT_FILE
	    echo "확인 값 : enforce_for_root" >> $OUTPUT_FILE
	    echo "주석 해제 또는 작성 필요"  >> $OUTPUT_FILE
	fi	
	
fi

U02_2_PWHISTORY_CONF="/etc/security/pwhistory.conf"
echo -e "\n----------------------------------------------" >> $OUTPUT_FILE
echo "점검 진행 파일 : $U02_2_PWHISTORY_CONF" >> $OUTPUT_FILE
echo "----------------------------------------------" >> $OUTPUT_FILE
if [ -f "$U02_2_PWHISTORY_CONF" ]; then
	U02_2_ENFORCE_FOR_ROOT_VAL=$(grep "^\s*enforce_for_root" $U02_2_PWHISTORY_CONF)
	U02_2_REMEMBER_VAL=$(grep "^\s*remember" $U02_2_PWHISTORY_CONF | awk '{print $3}')

	echo -e "\nU02_7.root 계정 비밀번호 유효기간 정책 적용 여부" >> $OUTPUT_FILE
	if [ "$U02_2_ENFORCE_FOR_ROOT_VAL" ]; then
            echo "[양호] root 계정 비밀번호 정책이 적용되어 있습니다." >> $OUTPUT_FILE
        else
            echo "enforce_for_root 주석 해제 또는 작성 필요"  >>$OUTPUT_FILE
        fi

	echo -e "\nU02_8.최근 비밀번호 기억 점검" >> $OUTPUT_FILE
	if [ "$U02_2_REMEMBER_VAL" ]; then
	    if [ "$U02_2_REMEMBER_VAL" -ge 4 ]; then
	        echo "[양호] 최근 비밀번호 기억 유효기간이 보안정책에 맞게 적용되어 있습니다." >> $OUTPUT_FILE
	    else
	        echo "[취약] 최근 비밀번호 기억 유효기간이 보안정책에 위반됩니다." >> $OUTPUT_FILE
		echo "확인 값 : remember" >> $OUTPUT_FILE
	        echo "필수 설정 값 : 4이상" >> $OUTPUT_FILE
	        echo "현재 설정 값 : $U02_2_REMEMBER_VAL" >> $OUTPUT_FILE
	    fi
	else
	    echo "[취약] 최근 비밀번호 기억 유효기간이 보안정책에 위반됩니다." >> $OUTPUT_FILE
	    echo "확인 값 : remember" >> $OUTPUT_FILE
	    echo "현재 설정 값 : 주석" >> $OUTPUT_FILE
	fi

fi
echo "U02 점검 완료"

echo -e "\n==============================================================" >> $OUTPUT_FILE
echo "U03.사용자 계정 로그인 실패 시 계정 잠금 임계값 설정 여부 점검" >> $OUTPUT_FILE
echo "==============================================================" >> $OUTPUT_FILE

U03_FAILLOCK_CONF="/etc/security/faillock.conf"
echo -e "\n----------------------------------------------" >> $OUTPUT_FILE
echo "점검 진행 파일 : $U03_FAILLOCK_CONF" >> $OUTPUT_FILE
echo "----------------------------------------------" >> $OUTPUT_FILE

if [ -f "$U03_FAILLOCK_CONF" ]; then
	U03_1_SILENT_VAL=$(grep "^\s*silent" $U03_FAILLOCK_CONF)
	U03_1_DENY_VAL=$(grep "^\s*deny" $U03_FAILLOCK_CONF | awk '{print $3}')
	U03_1_UNLOCK_TIME_VAL=$(grep "^\s*unlock_time" $U03_FAILLOCK_CONF | awk '{print $3}')
	
	echo -e "\nU03_1.비밀번호 오류 메시지 출력 여부 점검" >> $OUTPUT_FILE
	if [ "$U03_1_SILENT_VAL" ]; then
	    echo "[양호] 비밀번호 오류 메시지 출력을 하지 않습니다." >> $OUTPUT_FILE
	else
	    echo "[취약] 비밀번호 오류 메시지가 사용자에게 출력됩니다." >> $OUTPUT_FILE
	    echo "확인 값 : silent" >> $OUTPUT_FILE
	    echo "현재 설정 값 : 주석" >> $OUTPUT_FILE
	fi
	
	echo -e "\nU03_2.비밀번호 실패 횟수에 따른 계정 잠금" >> $OUTPUT_FILE
	if [ "$U03_1_DENY_VAL" ]; then
	    if [ "$U03_1_DENY_VAL" -ge 3 ]; then
		echo "[양호] 비밀번호 실패 횟수가 권장 보안정책에 맞게 적용되어 있습니다." >> $OUTPUT_FILE
	    else
		echo "[취약] 비밀번호 실패 횟수가 권장 보안정책에 맞지 않습니다." >> $OUTPUT_FILE
		echo "확인 값 : deny" >> $OUTPUT_FILE
		echo "권장 설정 값 : 3회 이상" >> $OUTPUT_FILE
		echo "현재 설정 값 : $U03_1_DENY_VAL" >> $OUTPUT_FILE
	    fi
	else
	    echo "[취약] 비밀번호 실패 횟수가 권장 보안정책에 맞지 않습니다." >> $OUTPUT_FILE
	    echo "확인 값 : deny" >> $OUTPUT_FILE
	    echo "현재 설정 값 : 주석" >> $OUTPUT_FILE
	fi  
	echo -e "\nU03_3.비밀번호 실패 횟수로 인한 계정잠금 시간 점검" >> $OUTPUT_FILE
	if [ "$U03_1_UNLOCK_TIME_VAL" ]; then
	    if [ "$U03_1_UNLOCK_TIME_VAL" -ge 120 ]; then
		echo "[양호] 계정잠금 시간이 권장 보안정책에 맞게 적용되어 있습니다." >> $OUTPUT_FILE
	    else
		echo "[취약] 계정잠금 시간이 권장 보안정책에 맞지 않습니다." >> $OUTPUT_FILE
		echo "확인 값 : UNLOCK_TIME" >> $OUTPUT_FILE
		echo "권장 설정 값 : 120초 이상" >> $OUTPUT_FILE
		echo "현재 설정 값 : $U03_1_UNLOCK_TIME_VAL" >> $OUTPUT_FILE
	    fi
	else
	    echo "[취약] 계정잠금 시간이 권장 보안정책에 맞지 않습니다." >> $OUTPUT_FILE
	    echo "확인 값 : UNLOCK_TIME" >> $OUTPUT_FILE
	    echo "현재 설정 값 : 주석" >> $OUTPUT_FILE
	fi
fi
echo "U03 점검 완료"

echo -e "\n==============================================================" >> $OUTPUT_FILE
echo "U04.사용자 계정 비밀번호 암호화 저장 여부 점검" >> $OUTPUT_FILE
echo "==============================================================" >> $OUTPUT_FILE

U04_PASSWD="/etc/passwd"

echo -e "\n----------------------------------------------" >> $OUTPUT_FILE
echo "점검 진행 파일 : $U04_PASSWD" >> $OUTPUT_FILE
echo "----------------------------------------------" >> $OUTPUT_FILE

echo -e "\nU04_1.쉐도우 비밀번호 적용 확인" >> $OUTPUT_FILE
if [ -f "$U04_PASSWD" ]; then
	U04_PASSWD_VAL=$(awk -F: '$2 != "x" {print $1}' $U04_PASSWD)
	if [ "$U04_PASSWD_VAL" ]; then
	    echo "[취약] 비밀번호가 암호화 되어 있지 않습니다." >> $OUTPUT_FILE
	    echo "필수 설정 값 : x" >> $OUTPUT_FILE
            echo -e "설정 누락 값 : \n$U04_PASSWD_VAL" >> $OUTPUT_FILE
	else
	    echo "[양호] 비밀번호가 암호화 되어 있습니다." >> $OUTPUT_FILE
	fi

fi
echo "U04 점검 완료"

echo -e "\n==============================================================" >> $OUTPUT_FILE
echo "U05.root 계정 중복 UID 유무 점검" >> $OUTPUT_FILE
echo "==============================================================" >> $OUTPUT_FILE

U05_PASSWD="/etc/passwd"

echo -e "\n----------------------------------------------" >> $OUTPUT_FILE
echo "점검 진행 파일 : $U05_PASSWD" >> $OUTPUT_FILE
echo "----------------------------------------------" >> $OUTPUT_FILE

echo -e "\nU05_1.root UID값 중복 확인" >> $OUTPUT_FILE
if [ -f "$U05_PASSWD" ]; then
	U05_ROOT_UID_VAL=$(awk -F: '$3 == 0 {print $1}' $U05_PASSWD | grep -v "^root$" | wc -l)
	U05_ROOT_DUP_UID_VAL=$(awk -F: '$3 == 0 {print $1}' $U05_PASSWD | grep -v "^root$")
	if [ "$U05_ROOT_UID_VAL" -eq 0 ]; then
	    echo "[양호]root와 중복되는 UID값을 가진 개체가 없습니다." >> $OUTPUT_FILE
	else
	    echo "[취약]root와 중복되는 UID값을 가진 개체가 $U05_ROOT_UID_VAL개 존재합니다." >> $OUTPUT_FILE
	    echo "중복 UID값 : $U05_ROOT_DUP_UID_VAL" >> $OUTPUT_FILE
	fi
fi
echo "U05 점검 완료"

