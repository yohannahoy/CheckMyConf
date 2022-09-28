
####################################################################################################################
# L'objectif de ce script est de vous aider à vérifier les recommandations de l'ANSSI sur votre systèmes GNU/linux #
####################################################################################################################
# Dev (un peu...)


####################################################################################################################
# Obj : Ajout de la couleur pour les résultats                                                                     #
####################################################################################################################

#normal=$(tput sgr0)                      # normal text
normal=$'\e[0m'                           # (works better sometimes)
bold=$(tput bold)                         # make colors bold/bright
red="$bold$(tput setaf 1)"                # bright red text
green=$(tput setaf 2)                     # dim green text
fawn=$(tput setaf 3); beige="$fawn"       # dark yellow text
yellow="$bold$fawn"                       # bright yellow text
darkblue=$(tput setaf 4)                  # dim blue text
blue="$bold$darkblue"                     # bright blue text
purple=$(tput setaf 5); magenta="$purple" # magenta text
pink="$bold$purple"                       # bright magenta text
darkcyan=$(tput setaf 6)                  # dim cyan text
cyan="$bold$darkcyan"                     # bright cyan text
gray=$(tput setaf 7)                      # dim white text
darkgray="$bold"$(tput setaf 0)           # bold black = dark gray text
white="$bold$gray"                        # bright white text


####################################################################################################################
# Obj : vérifier que le script est executé par root                                                                #
####################################################################################################################
res_root=$(id -u)

if [ $res_root -ne 0 ]
 then
  	echo "Ce script doit être executé avec des droits root."
  	exit
fi

####################################################################################################################
# Obj : vérifier que le script est executé par bash                                                                #
####################################################################################################################
if readlink /proc/$$/exe | grep -qs "dash"; then
        echo "Utilisez bash, pas sh..."
        exit 1
fi

fonct_uname () {
clear
echo -e "\n####################################################################################################################"
echo "# Obj : informations uname                                                                                         #"
echo "####################################################################################################################"
res_nom=$(uname -a| cut -d" " -f2)
res_ver=$(uname -a| cut -d" " -f3)

echo -e "\rHostname : $res_nom \r"



if [ -f /etc/redhat-release ]
then
	nb=$(grep -c "CentOS" /etc/redhat-release)
	if [ $nb -eq 1 ]
		then 
			cat /etc/redhat-release
		fi
fi

date
echo -e "version $res_ver \n"
}


fonct_disq () {

clear
echo -e "\n####################################################################################################################"
echo "# Obj : utilisation de l'espace disque                                                                             #"
echo "####################################################################################################################"
echo -e "\nUtilisation de l'espace disque :\n"
df -h
####################################################################################################################
#Obj : récupération des numéros de série des disques                                                               #
####################################################################################################################
#hdparm
}

fonct_res () {
clear
echo -e "\n####################################################################################################################"
echo "# Obj : informations réseau du serveur                                                                             #"
echo "####################################################################################################################"
echo -e "\nAdressage IP du serveur :"
ip a |grep -e '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'

echo -e "\nRoute disponible :"
route -n

}

fonct_ecoute () {
echo -e "\n###################################################################################################################"
echo "# Obj : process en écoute sur le serveur                                                                        #"
echo "###################################################################################################################"
echo -e "\nProcess en écoute sur le serveur :\n"
netstat -teaoplon

echo -e "\n"
nb=$(netstat -ntaup | grep LISTEN | grep -c tcp6)
echo -e "Vous avez ${red}$nb${normal} ports ouverts en tcp sur ipv6"
nb=$(netstat -ntaup | grep -c udp6)
echo -e "Vous avez ${red}$nb${normal} ports ouverts en udp sur ipv6"

nb=$(netstat -ntaup | grep LISTEN | grep -c tcp)
echo -e "Vous avez ${red}$nb${normal} ports ouverts en en tcp sur ipv4"
nb=$(netstat -ntaup | grep -c udp)
echo -e "Vous avez ${red}$nb${normal} ports ouverts en en udp sur ipv4"

echo -e "\n####################################################################################################################"
echo "# Obj : quelques services classiques sur un serveur installé par défaut                                            #"
echo "####################################################################################################################"
nb=$(netstat -ntaup | grep -c :111)
if [ $nb -ne 0 ]
 then   
        echo "Le service rpc est actif sur ce serveur"
fi

nb=$(netstat -ntaup | grep -c :25)
if [ $nb -ne 0 ]
 then   
        echo "Le service de messagerie est actif sur ce serveur"
fi

nb=$(netstat -ntaup | grep -c :5353)
if [ $nb -ne 0 ]
 then   
        echo "Le service avahi est actif sur ce serveur"
fi

nb=$(netstat -ntaup | grep -c :631)
if [ $nb -ne 0 ]
 then   
        echo "Le service d'impression est actif sur ce serveur"
fi

nb=$(netstat -ntaup | grep -c :1900)
if [ $nb -ne 0 ]
 then   
        echo "Le service de diffusion de contenu est actif sur ce serveur"
fi
}

fonct_fw () {
clear
echo "####################################################################################################################"
echo "# Obj : configuration du Parefeu                                                                                   #"
echo "####################################################################################################################"
echo -e "\nConfiguration du parefeu local :\n"
iptables -nvL

}
fonct_sshd () {
clear
echo "####################################################################################################################"
echo "# Obj : vérification des bons usages sshd                                                                          #"
echo "####################################################################################################################"
echo -e "\nEvaluation non-exhaustive de la configuration du serveur ssh (/etc/ssh/sshd_config) : \n"

if grep -q "Protocol 2" /etc/ssh/sshd_config 
     then
echo -e "Limiter au Protocol 2 : \t\t\t\t${green}ok${normal}";
    else
echo -e "Limiter au Protocol 2 : \t\t\t\t${red}ko${normal}";
fi


if grep -q "StrictHostKeyChecking  ask" /etc/ssh/ssh_config 
     then
echo -e "Validation explicite par l’utilisateur de la clé hôte : ${green}ok${normal}";
    else
echo -e "Validation explicite par l’utilisateur de la clé hôte : ${red}ko${normal} (à modifier si le poste contrôlé est client)";
fi


if grep -q "StrictModes yes" /etc/ssh/sshd_config
     then
echo -e "Rectitude des modes et droits : \t\t\t${green}ok${normal} ";
    else
echo -e "Rectitude des modes et droits : \t\t\t${red}ko${normal}";
fi



if grep -q "UsePrivilegeSeparation yes" /etc/ssh/sshd_config
     then
echo -e "Séparation des privilèges  : \t\t\t\t${green}ok${normal}";
    else
echo -e "Séparation de privilèges  : \t\t\t\t${red}ko${normal}";
fi


if grep -q "PermitEmptyPasswords no" /etc/ssh/sshd_config
     then
echo -e "Interdire les mots de passe vide : \t\t\t${green}ok${normal}";
    else
echo -e "Interdire les mots de passe vide : \t\t\t${red}ko${normal}";
fi


if grep -q "MaxAuthTries 2" /etc/ssh/sshd_config
     then
echo -e "Nombre de tentative d'authentification : \t\t${green}ok${normal}";
    else
echo -e "Nombre de tentative d'authentification : \t\t${red}ko${normal}";
fi


if grep -q "LoginGraceTime 30" /etc/ssh/sshd_config
     then
echo -e "Limite de la durée d'authentification : \t\t${green}ok${normal}";
    else
echo -e "Limite de la durée d'authentification : \t\t${red}ko${normal}";
fi


if grep -q "PermitRootLogin no" /etc/ssh/sshd_config
     then
echo -e "Connexion de root interdite : \t\t\t\t${green}ok${normal}";
    else
echo -e "Connexion de root interdite : \t\t\t\t${red}ko${normal}";
fi


if grep -q "PrintLastLog yes" /etc/ssh/sshd_config
     then
echo -e "Affichage de la dernière connexion : \t\t\t${green}ok${normal}";
    else
echo -e "Affichage de la dernière connexion : \t\t\t${red}ko${normal}";
fi


if grep -q "AllowUsers" /etc/ssh/sshd_config
     then
echo -e "Limiter les utilisateurs autorisés : \t\t\t${green}ok${normal}";
    else
echo -e "Limiter les utilisateurs autorisés : \t\t\t${red}ko${normal}";
fi

if grep -q "AllowGroups" /etc/ssh/sshd_config
     then
echo -e "Limiter les groupes autorisés : \t\t\t${green}ok${normal}";
    else
echo -e "Limiter les groupes autorisés : \t\t\t${red}ko${normal}";
fi

if grep -q "PermitUserEnvironment no" /etc/ssh/sshd_config
     then
echo -e "Bloquer la modification de l’environnement : \t\t${green}ok${normal}";
    else
echo -e "Bloquer la modification de l’environnement : \t\t${red}ko${normal}";
fi

if grep -q "\#ListenAddress" /etc/ssh/sshd_config
     then
echo -e "Limiter les interfaces : \t\t\t\t${red}ko${normal}";
    else
echo -e "Limiter les interfaces : \t\t\t\t${green}ok${normal}";
fi


if grep -q "AllowTcpForwarding no" /etc/ssh/sshd_config
     then
echo -e "Désactiver les redirections côté serveur : \t\t${green}ok${normal}";
    else
echo -e "Désactiver les redirections côté serveur : \t\t${red}ko${normal}";
fi


if grep -q "X11Forwarding no" /etc/ssh/sshd_config
     then
echo -e "Désactivation de la redirection X11 : \t\t\t${green}ok${normal}";
    else
echo -e "Désactivation de la redirection X11 : \t\t\t${red}ko${normal}";
fi
}

fonct_anssi () {
clear
echo "####################################################################################################################"
echo "# Obj : vérification non-exhautive des recommandations de configuration                                            #"
echo "####################################################################################################################"

echo "Recommandations issues du Guide ANSSI-BP-028 du 22 février 2019"

echo "----------------------------------------------------------------------------------------------------------"
#R1  Minimisation des services installés
echo -e "\n#R1 Liste des services installés sur le serveur"
service --status-all 

echo "----------------------------------------------------------------------------------------"
#R2  Minimisation de la configuration
echo -e "\n#R2 Minimisation de la configuration : ${blue}Non évaluée${normal}"
echo -e "Les fonctionnalités configurées au niveau des services démarrés doivent être limitées au
strict nécessaire."


echo "----------------------------------------------------------------------------------------"
#R3  Principe de moindre privilège
echo -e "\n#R3 Principe de moindre privilège :${blue} Non évaluée${normal}"
echo -e "Les services et exécutables disponibles sur le système doivent faire l’objet d’une analyse
afin de connaître les privilèges qui leurs sont associés, et doivent ensuite être configurés
et intégrés en vue d’en utiliser le strict nécessaire."

echo "----------------------------------------------------------------------------------------"
#R4  Utilisation des fonctionnalités de contrôle d’accès

echo -e "\n#R4 Utilisation des fonctionnalités de contrôle d'accès :${blue} Non évaluée${normal}"
echo -e "Utilisation des fonctionnalités de contrôle d’accès. Il est recommandé d’utiliser les 
fonctionnalités de contrôle d’accès obligatoire (MAC) en plus du traditionnel modèle utilisateur
 Unix (DAC), voire éventuellement de les combiner avec des mécanismes de cloisonnement."

echo "----------------------------------------------------------------------------------------"
#R5  Principe de défense en profondeur

echo -e "\n#R5 Principe de défense en profondeur :${blue} Non évaluée${normal}"
echo -e "Sous Unix et dérivés, la défense en profondeur doit reposer sur une combinaison de
barrières qu’il faut garder indépendantes les unes des autres. Par exemple :
– authentification nécessaire avant d’effectuer des opérations, notamment quand elles
sont privilégiées ;
– journalisation centralisée d’évènements au niveau systèmes et services ;
– priorité à l’usage de services qui implémentent des mécanismes de cloisonnement et/ou
de séparation de privilèges ;
– utilisation de mécanismes de prévention d’exploitation."


echo "----------------------------------------------------------------------------------------"
#R6  Cloisonnement des services réseau
echo -e "\n#R6  Cloisonnement des services réseau :${blue} Non évaluée${normal}"
echo -e "Les services réseau doivent autant que possible être hébergés sur des environnements
distincts. Cela évite d’avoir d’autres services potentiellement affectés si l’un d’eux se
retrouve compromis sous le même environnement."

echo "----------------------------------------------------------------------------------------"
#R7  Journalisation de l’activité des services
echo -e "\n#R7  Journalisation de l’activité des services${blue} Non évaluée${normal}"
echo -e "Les activités du système et des services en cours d’exécution doivent être journalisées et
archivées sur un système externe, non local."

echo "----------------------------------------------------------------------------------------"
#R8  Mises à jour régulières
nb=$(uname -a |grep -c "Debian")
if [ $nb -eq 1 ]
then 
	echo -e "\n#R8 Simmulation de mise à jour :"
	apt-get update && apt-get upgrade -s
fi

if [ -f /etc/redhat-release ]
then 
	nb=$(grep -c "CentOS" /etc/redhat-release)
	if [ $nb -eq 1 ]
	then 
		echo -e "\nR8 Simmulation de mise à jour :"
		yum check-update
	fi
fi


echo "----------------------------------------------------------------------------------------"
#R9  Configuration matérielle
echo -e "\n#R9 Configuration matérielle :${blue} Non évaluée${normal}"
echo -e "Il est conseillé d’appliquer les recommandations de configuration mentionnées dans
la note technique « Recommandations de configuration matérielle de postes clients et
serveurs x86_4»"

echo "----------------------------------------------------------------------------------------"
#R10 Architecture 32 et 64 bits
nb=$(arch | grep -c x86_64)
if [ $nb -ne 1 ]
 then   
        echo -e "\n#R10 ${red}Vous devez privilégier une installation 64bits de votre système${normal}"
else 

        echo -e "\n#R10 ${green}Vous avez privilégié une installation 64bits de votre système${normal}"
fi

echo "----------------------------------------------------------------------------------------"
#R11 Directive de configuration de l’IOMMU
nb=$(grep -c "iommu=force"  /etc/default/grub)
if [ $nb -eq 0 ]
 then   
        echo -e "\n#R11 ${red}L’activation du service d’IOMMU permet de protéger la mémoire du système${normal}"
	echo -e "Ajoutez la variable iommu=force  dans /etc/default/grub"
 else
        echo -e "\n#R11 ${green}L’activation du service d’IOMMU permet de protéger la mémoire du système${normal}"
fi

#R12 Partitionnement type 
echo -e "\n"
echo "----------------------------------------------------------------------------------------"
echo -e "#R12 Partitionnement type${blue} Non évaluée${normal}"
echo -e "#-----------------------------------------------------------------------------------------------------#"
echo -e "# Point de montage |       Options              | Description                                         #"
echo -e "#-----------------------------------------------------------------------------------------------------#"
echo -e "#      /           |     <sans option>          |Partition racine, contient le reste del’arborescence #"
echo -e "#-----------------------------------------------------------------------------------------------------#"
echo -e "#       /boot      | nosuid,nodev,noexec        | Contient le noyau et le chargeur dedémarrage.       #"
echo -e "#                  |       (noauto optionnel)   |  nécessaire une fois le boot terminé                #"
echo -e "#                  |                            |          (sauf mise à jour)                         #"
echo -e "#-----------------------------------------------------------------------------------------------------#"
echo -e "#       /opt       | nosuid,nodev(ro optionnel) | Packages  additionnels  au  système.                #"
echo -e "#                  |                            | Montage en lecture seule si non utilisé             #"
echo -e "#-----------------------------------------------------------------------------------------------------#"
echo -e "#     /tmp         |                            |   Fichiers temporaires. Ne doit contenir            #"
echo -e "#                  |    nosuid,nodev,noexec     | que des éléments non exécutables.                   #"
echo -e "#                  |                            | Nettoyé après redémarrage                           #"
echo -e "#-----------------------------------------------------------------------------------------------------#"
echo -e "#     /srv         |nosuid,nodev                | Contient des fichiers servis par un                 #"
echo -e "#                  |(noexec,ro optionnels)      |  service type web, ftp, etc.                        #"
echo -e "#-----------------------------------------------------------------------------------------------------#"
echo -e "#      /home       |      nosuid,nodev,noexec   |Contient  les HOME utilisateurs.                     #"
echo -e "#                  |                            |Montage  en  lecture  seule  si  non utilisé         #"
echo -e "#-----------------------------------------------------------------------------------------------------#"
echo -e "#     /proc        |       hidepid=1            |Contient des informations sur les processus          #"
echo -e "#                  |                            |et le système                                        #"
echo -e "#-----------------------------------------------------------------------------------------------------#"
echo -e "#      /usr        |      nodev                 |Contient la majorité des utilitaires et              #"
echo -e "#                  |                            |fichiers système                                     #"
echo -e "#-----------------------------------------------------------------------------------------------------#"
echo -e "#       /var       | nosuid,nodev,noexec        |Partition contenant des fichiers variables           #"
echo -e "#                  |                            |pendant  la  vie  du  système                        #"
echo -e "#                  |                            |(mails, fichiers PID, bases de données d’un service) #"
echo -e "#-----------------------------------------------------------------------------------------------------#"
echo -e "#    /var/log      |  nosuid,nodev,noexec       |Contient les logs du système                         #"
echo -e "#-----------------------------------------------------------------------------------------------------#"
echo -e "#    /var/tmp      |  nosuid,nodev,noexec       |Fichiers temporaires conservés après extinction      #"
echo -e "#-----------------------------------------------------------------------------------------------------#"

echo "#R13 Restrictions d’accès sur le dossier boot${blue} Non évaluées${normal}"
echo "#R14 Installation de paquets réduite au strict nécessaire${blue} Non évaluée${normal}"

echo "#R15 Choix des dépôts de paquets"
echo "Préconisation: Seul les dépôts connus et offciels doivent etre utilisés"
cat /etc/apt/sources.list

echo "#R16 Dépôts de paquets durcis${blue} Non évaluée${normal}"
echo "#R17 Mot de passe du chargeur de démarrage${blue} Non évaluée${normal}"
echo "#R18 Robustesse du mot de passe administrateur${blue} Non évaluée${normal}"
echo "#R19 Imputabilité des opérations d’administration${blue} Non évaluée${normal}"
echo "#R20 Installation d’éléments secrets ou de confiance${blue} Non évaluée${normal}"
echo "#R21 Durcissement et surveillance des services soumis à des flux arbitraires${blue} Non évaluée${normal}"

echo "----------------------------------------------------------------------------------------"
echo -e "\n#R22 Paramétrage des sysctl réseau"
echo -e "Préconisation : Pas de  routage  entre  les  interfaces"
val=$(sysctl net.ipv4.ip_forward | tail -c2)
a=1
if [ $val = $a ]
 then
        echo -e "${red}Le routage est actif entre vos interfaces, est-ce normal ?${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.ip_forward=0"
else
        echo "${green}Le routage est désactivé entre vos interfaces${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nFiltrage  par  chemin  inverse"
echo -e "Préconisation : Pas de routage des flux étrangés (all)"
a=0
val=$(sysctl net.ipv4.conf.all.rp_filter | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le routage des paquets étrangers est activé${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.all.rp_filter=1"
else
        echo "${green}Le routage des paquets étrangers est désactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nFiltrage  par  chemin  inverse"
echo "Préconisation : Pas de  routage  de flux étrangés (default)"
a=0
val=$(sysctl net.ipv4.conf.default.rp_filter | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le routage des paquets étrangers est activé${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.default.rp_filter=1"
else
        echo "${green}Le routage des paquets étrangers est désactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nNe pas  envoyer  de  redirections  ICMP"
echo -e "Préconisation : Pas de  redirection ICMP (all)"
a=1
val=$(sysctl net.ipv4.conf.all.send_redirects | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}La redirection ICMP est activée${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv4.conf.all.send_redirects=0"
else
        echo -e "${green}La redirection ICMP est déactivée${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nNe pas  envoyer  de  redirections  ICMP"
echo -e "Préconisation : Pas de  redirection ICMP (default)"
a=1
val=$(sysctl net.ipv4.conf.default.send_redirects | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}La redirection ICMP est activée${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv4.conf.default.send_redirects=0"
else
        echo -e "${green}La redirection ICMP est déactivée${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nRefuser  les  paquets  de  source  routing"
echo -e "Préconisation : Refuser  les  paquets  de  source  routing (all)"
a=1
val=$(sysctl net.ipv4.conf.all.accept_source_route | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le source  routing est activé${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv4.conf.all.accept_source_route=0"
else
        echo -e "${green}Le source  routing est déactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nRefuser  les  paquets  de  source  routing"
echo -e "Préconisation : Refuser  les  paquets  de  source  routing (default)"
a=1
val=$(sysctl net.ipv4.conf.default.accept_source_route | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le source  routing est activé${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv4.conf.default.accept_source_route=0"
else
        echo -e "${green}Le source  routing est déactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nNe pas  accepter  les  ICMP de type  accept redirect"
echo -e "Préconisation : Refuser  les  ICMP de type redirect (all)"
a=1
val=$(sysctl net.ipv4.conf.all.accept_redirects | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le serveur accepte les flux de type ICMP redirect${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv4.conf.all.accept_redirects=0"
else
        echo -e "${green}Le serveur n'accepte pas les flux de type ICMP redirect${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nNe pas  accepter  les  ICMP de type  secure redirect"
echo -e "Préconisation : Refuser  les  ICMP de type redirect (all)"
a=1
val=$(sysctl net.ipv4.conf.all.secure_redirects | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le serveur accepte les flux de type ICMP redirect${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv4.conf.all.secure_redirects=0"
else
        echo -e "${green}Le serveur n'accepte pas les flux de type ICMP redirect${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nNe pas  accepter  les  ICMP de type  accept redirect"
echo -e "Préconisation : Refuser  les  ICMP de type redirect (default)"
a=1
val=$(sysctl net.ipv4.conf.default.accept_redirects | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le serveur accepte les flux de type ICMP redirect${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv4.conf.default.accept_redirects=0"
else
        echo -e "${green}Le serveur n'accepte pas les flux de type ICMP redirect${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nNe pas  accepter  les  ICMP de type  accept redirect"
echo -e "Préconisation : Refuser  les  ICMP de type redirect (default)"
a=1
val=$(sysctl net.ipv4.conf.default.secure_redirects | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le serveur accepte les flux de type ICMP redirect${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv4.conf.default.secure_redirects=0"
else
        echo -e "${green}Le serveur n'accepte pas les flux de type ICMP redirect${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nLoguer  les  paquets  ayant  des IPs  anormales"
echo -e "Préconisation : Loguer  les  paquets  ayant  des IPs  anormales (default)"
a=1
val=$(sysctl net.ipv4.conf.all.log_martians | tail -c2)
if [ $val = $a ]
 then
        echo "${green}les paquets sont loggés${normal}"
else
        echo "${red}les paquets  ne sont pas loggé${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.all.log_martians=1"
fi

echo "----------------------------------------------------------------------------------------"
# RFC  1337
echo -e "\nRFC 1337"
echo -e "Préconisation : TIME-WAIT Assassination Hazards in TCP"
a=1
val=$(sysctl net.ipv4.tcp_rfc1337 | tail -c2)
if [ $val = $a ]
 then
        echo -e "${green}Problème tcp traité${normal}"
else
        echo -e "${red}Problème tcp non-traité${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv4.tcp_rfc1337=1"
fi

echo "----------------------------------------------------------------------------------------"
# Ignorer  les réponses  non  conformes à la RFC  1122
echo -e "\nIgnorer  les réponses  non  conformes à la RFC 1122"
echo -e "Préconisation : Ignorer  les réponses  non  conformes"
a=1
val=$(sysctl net.ipv4.icmp_ignore_bogus_error_responses | tail -c2)
if [ $val = $a ]
 then
        echo -e "${green}Réponses ignorées${normal}"
else
        echo -e "${red}Réponses ICMP traitées${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"
fi


echo "----------------------------------------------------------------------------------------"
# Augmenter  la plage  pour  les  ports éphémères
echo -e "\nAugmenter  la plage  pour  les  ports éphémères"
a=$(sysctl net.ipv4.ip_local_port_range |cut -f 2)
b=65535
if [ "$a" -ne "$b" ]
then
        echo -e "${red}La plage de ports éphèmères est à augmenter${normal}"
else
        echo -e "${green}La plage de ports éphèmères est conforme${normal}"
fi
echo -e "si besoin : sysctl -w net.ipv4.ip_local_port_range=\"32768 65535\""


echo "----------------------------------------------------------------------------------------"
# Utiliser  les SYN cookies
echo -e "\nUtiliser  les SYN  cookies"
a=1
val=$(sysctl net.ipv4.tcp_syncookies | tail -c2)
if [ $val = $a ]
 then
        echo -e "${green}SYN cookies utilisés${normal}"
else
        echo -e "${red}SYN cookies ignorés${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv4.tcp_syncookies=1"
fi


echo "----------------------------------------------------------------------------------------"
echo "-e \nDésactiver  le  support  des "router  solicitations" (all)"
a=1
val=$(sysctl net.ipv6.conf.all.router_solicitations  | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le support est activé${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.all.router_solicitations=0"
else
        echo -e "${green}Le support est désactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nDésactiver  le  support  des "router  solicitations" (default)"
a=1
val=$(sysctl net.ipv6.conf.default.router_solicitations | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le support est activé${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.default.router_solicitations=0"
else
        echo -e "${green}Le support est désactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nNe pas  accepter  les "routers  preferences" par "router  advertisements"(all)"
a=1
val=$(sysctl net.ipv6.conf.all.accept_ra_rtr_pref | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le support est activé ${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.all.accept_ra_rtr_pref=0"
else
        echo -e "${green}Le support est désactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nNe pas  accepter  les "router  preferences" par "router  advertisements"(default)"
a=1
val=$(sysctl net.ipv6.conf.default.accept_ra_rtr_pref | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le support est activé ${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.default.accept_ra_rtr_pref=0"
else
        echo -e "${green}Le support est désactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nPas de  configuration  auto  des  prefix  par "router  advertisements"(all)"
a=1
val=$(sysctl net.ipv6.conf.all.accept_ra_pinfo | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le support est activé ${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.all.accept_ra_pinfo=0"
else
        echo -e "${green}Le support est désactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo "Pas de  configuration  auto  des  prefix  par "router  advertisements"(default)"
a=1
val=$(sysctl net.ipv6.conf.default.accept_ra_pinfo | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le support est activé ${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.default.accept_ra_pinfo=0"
else
        echo -e "${green}Le support est désactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nPas d’apprentissage  du  routeur  par défaut  par "router  advertisements"(all)"
a=1
val=$(sysctl net.ipv6.conf.all.accept_ra_defrtr | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le support est activé ${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.all.accept_ra_defrtr=0"
else
        echo -e "${green}Le support est désactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "Pas d’apprentissage  du  routeur  par défaut  par "router  advertisements"(default)"
a=1
val=$(sysctl net.ipv6.conf.default.accept_ra_defrtr | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le support est activé ${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.default.accept_ra_defrtr=0"
else
        echo -e "${green}Le support est désactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nPas de  configuration  auto  des  adresses à partir  des "router advertisements"(all)"
a=1
val=$(sysctl net.ipv6.conf.all.autoconf| tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le support est activé ${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.all.autoconf=0"
else
        echo -e "${green}Le support est désactivé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "Pas de configuration auto des adresses à partir des "router advertisements"(default)"
a=1
val=$(sysctl net.ipv6.conf.default.autoconf | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Le support est activé ${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.default.autoconf=0"
else
        echo -e "${green}Le support est désactivé${normal}"
fi
echo "----------------------------------------------------------------------------------------"
echo -e "\nNe pas accepter les ICMP de type redirect (all)"
a=1
val=$(sysctl net.ipv6.conf.all.accept_redirects | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Les ICMP redirect sont acceptées${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.all.accept_redirects=0"
else
        echo -e "${green}Les ICMP redirect sont refusées${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "Ne pas  accepter  les  ICMP de type  redirect (default)"
a=1
val=$(sysctl net.ipv6.conf.default.accept_redirects | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Les ICMP redirect sont acceptées${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.default.accept_redirects=0"
else
        echo -e "${green}Les ICMP redirect sont refusées${normal}"
fi


echo "----------------------------------------------------------------------------------------"
echo -e "\nRefuser  les  packets  de  source  routing (all)"
a=1
val=$(sysctl net.ipv6.conf.all.accept_source_route | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Les packets de source routing sont acceptés${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.all.accept_source_route=0"
else
        echo -e "${green}Les packets de source routing sont refusés${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo "Refuser  les  packets  de  source  routing(default)"
a=1
val=$(sysctl net.ipv6.conf.default.accept_source_route | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Les packets de source routing sont acceptés${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.default.accept_source_route=0"
else
        echo -e "${green}Les packets de source routing sont refusés${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo "Nombre  maximal d’adresses  autoconfigurées par  interface (all)"
a=0
val=$(sysctl net.ipv6.conf.all.max_addresses | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Les packets de source routing sont acceptés${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.all.max_addresses=1"
else
        echo -e "${green}Les packets de source routing sont refusés${normal}"
fi
echo "----------------------------------------------------------------------------------------"
echo "Nombre  maximal d’adresses  autoconfigurées par  interface (default)"
a=0
val=$(sysctl net.ipv6.conf.default.max_addresses | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Les packets de source routing sont acceptés${normal}"
	echo -e "Pour mise en place : sysctl -w net.ipv6.conf.default.max_addresses=1"
else
        echo -e "${green}Les packets de source routing sont refusés${normal}"
fi

echo -e "\n#R23 Paramétrage des sysctl système"
echo -e "Désactivation  des  SysReq"
a=1
val=$(sysctl kernel.sysrq | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Les requètes systèmes sont activées${normal}"
	echo -e "Pour mise en place : sysctl -w kernel.sysrq=0"
else
        echo -e "${green}Les requètes systèmes sont activées${normal}"
fi


echo "----------------------------------------------------------------------------------------"
echo "Pas de core  dump  des exécutables  setuid"
a=1
val=$(sysctl fs.suid_dumpable | tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Les core dump sont possibles${normal}"
	echo -e "Pour mise en place : sysctl -w fs.suid_dumpable=0"
else
        echo -e "${green}Les core dump sont désactivés${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo "Interdiction de déréférencer des liens (symlinks) vers des fichiers dont l’utilisateur courant n’est pas le propriétaire"
a=0
val=$(sysctl fs.protected_symlinks| tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Les déréférencements sont possibles${normal}"
	echo -e "Pour mise en place : sysctl -w fs.protected_symlinks=1"
else
        echo -e "${green}Le déréférencement des liens symboliques est désactivé${normal}"
fi
echo "----------------------------------------------------------------------------------------"
echo "Interdiction de déréférencer des liens (hardlinks) vers des fichiers dont l’utilisateur courant n’est pas le  propriétaire"
a=0
val=$(sysctl fs.protected_hardlinks| tail -c2)
if [ $val = $a ]
 then
        echo -e "${red}Les déréférencements sont possibles${normal}"
	echo -e "Pour mise en place : sysctl -w fs.protected_hardlinks=1"
else
        echo -e "${green}Le déréférencement des liens symboliques est désactivé${normal}"
fi


echo "----------------------------------------------------------------------------------------"
echo "Activation de l'ASLR"
a=2
val=$(sysctl kernel.randomize_va_space| tail -c2)
if [ $val = $a ]
 then
        echo -e "${green}L'ASLR est activée${normal}"
 else
	echo -e "${red}L'ASLR n'est pas activée${normal}"
	echo -e "Pour mise en place : sysctl -w kernel.randomize_va_space=2"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nInterdiction  de  mapper  de la mémoire  dans  les  adresses  basses  "
a=$(sysctl vm.mmap_min_addr |cut -d" " -f 3)
b=65536
if [ "$a" -ne "$b" ]
then
        echo -e "${red}Il est possible de mapper la mémoire dans les adresses basses${normal}"
	echo -e "Pour mise en place : sysctl -w vm.mmap_min_addr=65536"
else
        echo -e "${green}La plage de mémoire adressable est conforme${normal}"
fi
# Espace  de choix  plus  grand  pour  les  valeurs  de PID
echo "----------------------------------------------------------------------------------------"
echo -e "\nEspace  de choix  plus  grand  pour  les  valeurs  de PID"
a=$(sysctl kernel.pid_max |cut -d" " -f 3)
b=65536
if [ "$a" -ne "$b" ]
then
        echo -e "${red}Il'espace de choix pour les valeurs de PID doit être augementé${normal}"
	echo -e "Pour mise en place : sysctl -w kernel.pid_max=65536"
else
        echo -e "${green}L'espace de chois PID est conforme${normal}"
fi
echo "----------------------------------------------------------------------------------------"
echo -e "\nObfuscation  des  adresses mémoire  kernel"
a=1
val=$(sysctl kernel.kptr_restrict | tail -c2)
if [ $val = $a ]
 then
        echo -e "${green}Obfuscation  des  adresses mémoire  kernel activé${normal}"
else
        echo -e "${red}Obfuscation  des  adresses mémoire  kernel désactivé${normal}"
	echo -e "Pour mise en place : sysctl -w kernel.kptr_restrict=1"
fi
echo "----------------------------------------------------------------------------------------"
echo -e "\nRestriction d’accès au  buffer  dmesg"
a=1
val=$(sysctl kernel.dmesg_restrict | tail -c2)
if [ $val = $a ]
 then
        echo -e "${green}Accès au buffer dmesg restreint${normal}"
else
        echo -e "${red}L'accès au buffer dmesg n'est pas restreint${normal}"
	echo -e "Pour mise en place : sysctl -w kernel.dmesg_restrict=1"
fi


# Restreint l’utilisation du sous système perf
echo "----------------------------------------------------------------------------------------"
echo -e "\nRestriction de l’utilisation du sous système perf : paranoid"
a=2
val=$(sysctl kernel.perf_event_paranoid | tail -c2)
if [ $val = $a ]
 then
        echo -e "${green}Accès au sous systeme perf restreint${normal}"
else
        echo -e "${red}L'accès au sous systeme perf n'est pas restreint${normal}"
	echo -e "Pour mise en place : sysctl -w kernel.perf_event_paranoid=2"
fi


echo "----------------------------------------------------------------------------------------"
echo -e "\nRestriction de l’utilisation du sous système perf : max sample rate"
a=1
val=$(sysctl kernel.perf_event_max_sample_rate | tail -c2)
if [ $val = $a ]
 then
        echo -e "${green}Accès au sous systeme perf max sample rate ${normal}"
else
        echo -e "${red}L'accès au sous systeme perf n'est pas restreint${normal}"
	echo -e "Pour mise en place : sysctl -w kernel.perf_event_max_sample_rate=1"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\nRestriction de l’utilisation du sous système perf : cpu time max"
a=1
val=$(sysctl kernel.perf_cpu_time_max_percent | tail -c2)
if [ $val = $a ]
 then
        echo -e "${green}Accès au sous systeme perf max sample rate ${normal}"
else
        echo -e "${red}L'accès au sous systeme perf n'est pas restreint${normal}"
	echo -e "Pour mise en place : sysctl -w kernel.perf_cpu_time_max_percent=1"
fi


echo "----------------------------------------------------------------------------------------"
echo -e "\n#R24 Désactivation du chargement des modules noyau"
a=1
val=$(sysctl kernel.modules_disabled | tail -c2)
if [ $val = $a ]
 then
        echo -e "${green}Le chargement des modules noyau est désactivé${normal}"
else
        echo -e "${red}Le chargement des modules noyau est activé${normal}"
	echo -e "Pour mise en place : sysctl -w kernel.modules_disabled=1"
	echo -e "Il est conseillé de mettre directement à jour votre fichier /etc/sysctl.conf"
	echo -e "en ajoutant la ligne suivante : kernel.modules_disabled = 1"
fi


echo -e "\n#R25 Configuration sysctl du module Yama"
a=0
val=$(sysctl kernel.yama.ptrace_scope | tail -c2)
if [ $val = $a ]
 then
	echo -e "${red}Il est recommandé de charger le module de sécurité Yama lors du démarrage${normal}"
	echo -e "Vous pouvez par exemple passer l'argument security=yama au noyau"
	echo -e "et configurer la sysctl kernel.yama.ptrace_scope à une valeur au moins égale à 1"
else
	echo -e "${green}Le module Yama est chargé${normal}"
fi


echo "#R26 Désactivation des comptes utilisateurs inutilisés${blue} Non évaluée${normal}"
echo "#R27 Désactivation des comptes de services${blue} Non évaluée${normal}"
echo "#R28 Unicité et exclusivité des comptes de services système${blue} Non évaluée${normal}"
echo "#R29 Délai d’expiration de sessions utilisateurs${blue} Non évaluée${normal}"
echo "#R30 Applications utilisant PAM${blue} Non évaluée${normal}"
echo "#R31 Sécurisation des services réseau d’authentification PAM${blue} Non évaluée${normal}"
echo "#R32 Protection des mots de passe stockés${blue} Non évaluée${normal}"
#remarque : ANSSI recommande sha512 mais maintenant yescrypt est pris par défaut car meilleur.
#ANSSI pas mis à jour - étonnant ?
echo "#R33 Sécurisation des accès aux bases utilisateurs distantes${blue} Non évaluée${normal}"
echo "#R34 Séparation des comptes système et d’administrateur de l’annuaire${blue} Non évaluée${normal}"
echo "#R35 Valeur de umask${blue} Non évaluée${normal}"
echo "#R36 Droits d’accès aux fichiers de contenu sensible${blue} Non évaluée${normal}"
echo "#R37 Exécutables avec bits setuid et setgid${blue} Non évaluée${normal}"
echo "#R38 Exécutables setuid root${blue} Non évaluée${normal}"
echo "#R39 Répertoires temporaires dédiés aux comptes${blue} Non évaluée${normal}"
echo "#R40 Sticky bit et droits d’accès en écriture${blue} Non évaluée${normal}"
echo "#R41 Sécurisation des accès pour les sockets et pipes nommées${blue} Non évaluée${normal}"
echo "#R42 Services et daemons résidents en mémoire${blue} Non évaluée${normal}"
echo "#R43 Durcissement et configuration du service syslog${blue} Non évaluée${normal}"
echo "#R44 Cloisonnement du service syslog par chroot${blue} Non évaluée${normal}"
echo "#R45 Cloisonnement du service syslog par container${blue} Non évaluée${normal}"
echo "#R46 Journaux d’activité de service${blue} Non évaluée${normal}"
echo "#R47 Partition dédiée pour les journaux${blue} Non évaluée${normal}"
echo "#R48 Configuration du service local de messagerie${blue} Non évaluée${normal}"
echo "#R49 Alias de messagerie des comptes de service${blue} Non évaluée${normal}"
echo "#R50 Journalisation de l’activité par auditd${blue} Non évaluée${normal}"
echo "#R51 Scellement et intégrité des fichiers${blue} Non évaluée${normal}"
echo "#R52 Protection de la base de données des scellés${blue} Non évaluée${normal}"
echo "#R53 Restriction des accès des services déployés${blue} Non évaluée${normal}"
echo "#R54 Durcissement des composants de virtualisation${blue} Non évaluée${normal}"
echo "#R55 Cage chroot et privilèges d’accès du service cloisonné${blue} Non évaluée${normal}"
echo "#R56 Activation et utilisation de chroot par un service${blue} Non évaluée${normal}"
echo "#R57 Groupe dédié à l’usage de sudo${blue} Non évaluée${normal}"
echo "#R58 Directives de configuration sudo${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n#R58 Directives de configuration sudo"
        nb=$(grep -c "noexec" /etc/sudoers)
        if [ $nb -eq 1 ]
        then
        echo "${green}L'execution des subsystem est interdite${normal}"
else
        echo -e "${red}L'execution des subsystem est autorisé${normal}"
	echo "Ajouter les lignes suivants à votre sudoers :"
	echo "         Defaults noexec,requiretty,use_pty,umask=0027"
	echo "         Defaults ignore_dot,env_reset,passwd_timeout=1"
fi
echo "#R59 Authentification des utilisateurs exécutant sudo"
echo "#R60 Privilèges des utilisateurs cible pour une commande sudo "
echo "#R61 Limitation du nombre de commandes nécessitant l’option EXEC"
echo "Recommandations évaluées dans la #R58"
echo "----------------------------------------------------------------------------------------"

echo "#R62 Du bon usage de la négation dans une spécification sudo"
        nb=$(grep -c "!/" /etc/sudoers)
        if [ $nb -eq 0 ]
        then
        echo "${green}Pas de négation dans votre fichier sudoers${normal}"
else
        echo -e "${red}L'utilisation des négations est déconseillée${normal}"
	echo "Exemple :"
	echo "        User ALL=ALL, !/bin/sh"
	echo "         un cp de /bin/sh sous un autre nom suffit à le rendre utilisable"
fi
echo "#R63 Arguments explicites dans les spécifications sudo"
	#pas de * caractère jocker dans le sudoers
        nb=$(grep -c "\*" /etc/sudoers)
        if [ $nb -eq 0 ]
        then
        echo "${green}Pas de /* dans votre fichier sudoers${normal}"
else
        echo -e "${red}L'utilisation des carat est déconseillée${normal}"
	echo "Toutes les commandes du fichier sudoers doivent préciser strictement les arguments autorisés à être utilisés pour un utilisateur donné.
L’usage de ( \* wildcard) dans les règles doit être autant que possible évité. L’absence d’arguments auprès d’une commande doit être spécifiée par la présence d’une chaînevide (\"\")."
fi

echo "#R64 Du bon usage de sudoedit${blue} Non évaluée${normal}"
echo "#R65 Activation des profils de sécurité AppArmor${blue} Non évaluée${normal}"
echo "#R66 Activation de la politique targeted avec SELinux${blue} Non évaluée${normal}"
echo "#R67 Paramétrage des booléens SELinux${blue} Non évaluée${normal}"
# setsebool  -P allow_execheap=off"
# setsebool  -P allow_execmem=off
# setsebool  -P allow_execstack=off
# setsebool  -P secure_mode_insmod=off
# setsebool  -P ssh_sysadm_login=off
echo "#R68 Désinstallation des outils de débogage de politique SELinux${blue} Non évaluée${normal}"
echo "#R69 Confinement des utilisateurs interactifs non privilégiés${blue} Non évaluées${normal}"

}
fonct_fail () {
clear
echo "####################################################################################################################"
echo "# Obj : vérification de la présence du service fail2ban                                                            #"
echo "####################################################################################################################"


a=$(service --status-all |grep fail |wc -l)
if [ $a -ne 0 ]
then
	echo "${green}Fail2ban est installé sur le serveur${normal}"
else
        echo "${red}Votre système ne dispose pas de Fail2ban${normal}"
fi


}

fonct_rap () {

#date du jour
DATE=`date +"%d-%m-%d_%H-%M"`
  fonct_uname > Rapport_du_$DATE.txt
  fonct_res >> Rapport_du_$DATE.txt
  fonct_ecoute >> Rapport_du_$DATE.txt
  fonct_fw >> Rapport_du_$DATE.txt
  fonct_disq >> Rapport_du_$DATE.txt
  fonct_sshd >> Rapport_du_$DATE.txt
  fonct_anssi >> Rapport_du_$DATE.txt
  fonct_fail >> Rapport_du_$DATE.txt
}

###################################################################################################################
#                               Menu                                                                              #
###################################################################################################################
PS3="${blue} Que souhaitez vous faire ( Enter pour afficher les opérations possibles ) ? ${normal}"
select choix in \
   "Informations diverses sur le serveur" \
   "Information réseau"  \
   "Information sur les ports en écoute"  \
   "Afficher les informations sur le parefeu"  \
   "Afficher les informations sur les disques"  \
   "Véririer le paramétrage du serveur SSH"  \
   "Vérifier les critères de l'ANSSI "  \
   "Vérifier fail2ban"\
   "Génèrer un fichier rapport de toutes les options ci-dessus"  \
   "Abandon"
do
   clear
   echo "Vous avez choisi l'item $REPLY : $item"
   case $REPLY in
      1) fonct_uname exit ;;
      2) fonct_res exit ;;
      3) fonct_ecoute exit ;;
      4) fonct_fw exit ;;
      5) fonct_disq exit ;;
      6) fonct_sshd exit ;;
      7) fonct_anssi exit ;;
      8) fonct_fail exit ;;
      9) fonct_rap exit ;;
      10) echo "Fin"
         exit 0 ;;
      *) echo "Fonction non implémentée"  ;;
   esac
done



