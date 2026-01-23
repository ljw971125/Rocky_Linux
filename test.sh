echo "==================================="
echo "           보 안 점 검             "
echo "==================================="

echo -e "\nOS 버전 정보 확인"
cat /etc/rocky-release


echo -e "\nroot 계정 원격 로그인 가능 여부 확인"
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
