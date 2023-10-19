#!/bin/bash

set -e

clear

BLACK='\e[30m'
RED='\e[31m'
GREEN='\e[92m'
YELLOW='\e[33m'
ORANGE='\e[93m'
BLUE='\e[34m'
PURPLE='\e[35m'
CYAN='\e[96m'
WHITE='\e[37m'
NC='\e[0m'
purpal='\033[35m'


clear

counter=0
(

while :
do
cat <<EOF
XXX
$counter
Loading FINDCLUE INSTALLER ....( $counter%):
XXX
EOF

(( counter+=20 ))
[ $counter -eq 100 ] && break

sleep 1
done
) |
whiptail --title " FINDCLUE " --gauge "Cargando..." 7 70 0



clear

echo -e "${RED} "
echo ""                                                                         
echo "      ██████ ██ ███    ██ ██████  ██████ ██     ██   ██ ██████        ";
echo "      ██        ████   ██ ██   ██ ██     ██     ██   ██ ██            ";
echo "      █████  ██ ██ ██  ██ ██   ██ ██     ██     ██   ██ █████         ";
echo "      ██     ██ ██  ██ ██ ██   ██ ██     ██     ██   ██ ██            ";
echo "      ██     ██ ██   ████ ██████  ██████ ██████ ███████ ██████  V1.1  ";
echo "                                                                             ";
echo "                   Bienvenido al instalador FINDCLUE                         ";
echo -e "${GREEN}===================================================================${NC} "
echo -e "${RED}                   [!] Esta herramienta debe ejecutarse como ROOT [!]${NC}\n"
echo ""
echo -e "${CYAN}[>] Presione ENTER para instalar FINDCLUE, CTRL+C para cancelar.${NC}"
read INPUT
echo ""

if [ "$PREFIX" = "/data/data/com.termux/files/usr" ]; then
    INSTALL_DIR="$PREFIX/usr/share/doc/FINDCLUE"
    BIN_DIR="$PREFIX/usr/bin/"
    pkg install -y git python3
else
    INSTALL_DIR="/usr/share/doc/FINDCLUE"
    BIN_DIR="/usr/bin/"
fi

echo "[✔] Comprobando directorios...";
if [ -d "$INSTALL_DIR" ]; then
    echo "[!] Se encontró un directorio FINDCLUE... ¿Quieres reemplazarlo? [y/n]:" ;
    read mama
    if [ "$mama" = "y" ]; then
        rm -R "$INSTALL_DIR"
    else
        exit
    fi
fi

echo "[✔] Instalando ...";
echo "";
git clone https://github.com/D4RK-4RMY/DARKARMY.git "$INSTALL_DIR";
echo "#!/bin/bash
python3 $INSTALL_DIR/findclue.py" '${1+"$@"}' > FINDCLUE;
chmod +x FINDCLUE;
sudo cp FINDCLUE /usr/bin/;
rm FINDCLUE;


if [ -d "$INSTALL_DIR" ] ;
then
    echo "";
        echo "[✔] Instalación realizada de forma exitosa !!! \n\n";
        echo -e $GREEN "       [+]+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[+]"
        echo            "       [+]                                                             [+]"
        echo -e $GREEN "       [+]     ✔✔✔ Ahora simplemente escriba en la Terminal (FINDCLUE) ✔✔✔         [+]"
        echo            "       [+]                                                             [+]"
        echo -e $GREEN "       [+]+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[+]"
else
    echo "[✘] Algo salió mal en la instalación. Vuelva a intentarlo !!! [✘]";
    exit
fi
