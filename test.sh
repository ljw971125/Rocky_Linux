echo "==================================="
echo "           보 안 점 검             "
echo "==================================="

echo -e "\n[0]OS 버전 정보 확인"
cat /etc/rocky-release


echo -e "\n[1]root 계정 원격 로그인 가능 여부 확인"
SSH_CONF="/etc/ssh/sshd_config.d/01-permitrootlogin.conf"

if [ -f "$SSH_CONF" ]; then
	ROOT_LOGIN_VAL=$(grep -i "^PermitRootLogin" $SSH_CONF | awk '{print $2}')
	
	if [ "$ROOT_LOGIN_VAL" == "no" ]; then
	    echo -e "[양호] Root 원격 접속이 차단되어 있습니다. (설정값: $ROOT_LOGIN_VAL)"
	else
	    echo -e "[취약] Root 원격 접속이 허용되어 있거나 설정이 미흡합니다."
	    echo -e "현재 설정값: ${ROOT_LOGIN_VAL} (권장: no)"
	fi
fi



echo -e "\n[2]비밀번호 최소 사용,변경 기간 점검"
LOGIN_DEFS="/etc/login.defs"

if [ -f "$LOGIN_DEFS" ]; then
	PASS_CHANGE_MAX=$(grep -i "^PASS_MAX_DAYS" $LOGIN_DEFS | awk '{print $2}')
	PASS_CHANGE_MIN=$(grep -i "^PASS_MIN_DAYS" $LOGIN_DEFS | awk '{print $2}')
	if [ "$PASS_CHANGE_MAX" -ge 90 ] && [ "$PASS_CHANGE_MIN" -ge 3 ]; then
	    echo -e "[양호] 비밀번호 최소 사용,변경 기간이 설정되어 있습니다."
	else
	    echo -e "[취약] 비밀번호 최소 사용,변경 기간이 설정되어있지 않습니다."
	    echo -e "비밀번호 최소 변경 기간 : 90일 이상(현재 설정값 : $PASS_CHANGE_MAX)"
	    echo -e "비밀번호 최소 사용 기간 : 3일 이상(현재 설정값 : $PASS_CHANGE_MIN)"
	fi
fi
