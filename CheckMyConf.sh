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
# Obj : On fixe le nom du rapport et de l'annexe pour la vérification des critères de l'ANSSI                      #
####################################################################################################################
Nom_Rapport="Rapport_"$(date '+%d-%m-%y-%H%M')
Nom_Annexe="Annexe_"$(date '+%d-%m-%y-%H%M')

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
if readlink /proc/$$/exe | grep -qs "dash";
 then
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
	 then cat /etc/redhat-release
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
echo "Vous avez ${red}$nb${normal} ports ouverts en tcp sur ipv6"
nb=$(netstat -ntaup | grep -c udp6)
echo "Vous avez ${red}$nb${normal} ports ouverts en udp sur ipv6"

nb=$(netstat -ntaup | grep LISTEN | grep -c tcp)
echo "Vous avez ${red}$nb${normal} ports ouverts en en tcp sur ipv4"
nb=$(netstat -ntaup | grep -c udp)
echo "Vous avez ${red}$nb${normal} ports ouverts en en udp sur ipv4"

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
        echo "Validation explicite par l’utilisateur de la clé hôte : ${green}ok${normal}";
 else
        echo "Validation explicite par l’utilisateur de la clé hôte : ${red}ko${normal} (à modifier si le poste contrôlé est client)";
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

####################################################################################################################
#Obj : Outils pour création de l'annexe                                                                            #
####################################################################################################################
function Ecrire_Annexe()
{
  P_Contenu_Annexe=$1

  echo -e $P_Contenu_Annexe >> $Nom_Annexe
}

function Ecrire_Entete()
{
  P_Nom_Entete=$1

  Ecrire_Annexe "----------------------------------------------------------------------------"
  Ecrire_Annexe " $P_Nom_Entete"
  Ecrire_Annexe "----------------------------------------------------------------------------"
  Ecrire_Annexe
}

function Ecrire_Separation()
{
  Ecrire_Annexe
  Ecrire_Annexe "----------------------------------------------------------------------------"
  Ecrire_Annexe
}

function Ecrire_ligneTableauR12()
{
  Ecrire_Annexe "#--------------------------------------------------------------------------------------------------------------------------------#"
}

function Ecrire_ligneTableauR38()
{
  Ecrire_Annexe "#----------------------------------------------------------------------------------------------------------------------------------------------------------------#"
}

####################################################################################################################
#Obj : Recommandations ANSSI                                                                                       #
####################################################################################################################
fonct_anssi () {
clear
echo "####################################################################################################################"
echo "# Obj : vérification non-exhautive des recommandations de configuration                                            #"
echo "####################################################################################################################"

echo "Recommandations issues du Guide ANSSI-BP-028 du 22 février 2019"

echo "----------------------------------------------------------------------------------------------------------"
#R1 Minimisation des services installés
echo -e "\n${purple}#R1 Minimisation des services installés${normal}"
echo "La liste des services installés a été écrite dans l'annexe."
        Ecrire_Entete "#R1 - Minimisation des services installés"
        Ecrire_Annexe "Liste des services installés :"
        service --status-all >> $Nom_Annexe
        Ecrire_Separation

echo "----------------------------------------------------------------------------------------"
#R2 Minimisation de la configuration
echo -e "\n${purple}#R2 Minimisation de la configuration : ${blue}évaluée partiellement${normal}"
echo "Les fonctionnalités configurées au niveau des services démarrés doivent être limitées au strict nécessaire."
nb=$(ss -ltupn | grep -c exim)
if [ $nb -ne 0 ]
 then 
	echo "${red}Exim4 ne devrait pas être installé${normal}"
        echo "Pour le désinstaller : apt-get --purge remove exim4 exim4-base exim4-config exim4-daemon-heavy"
 else
        echo "${green}Exim4 n'est pas installé${normal}"
fi

echo "----------------------------------------------------------------------------------------"
#R3 Principe de moindre privilège
echo -e "\n${purple}#R3 Principe de moindre privilège :${blue} Non évaluée${normal}"
echo "Les services et exécutables disponibles sur le système doivent faire l’objet d’une analyse
afin de connaître les privilèges qui leurs sont associés, et doivent ensuite être configurés
et intégrés en vue d’en utiliser le strict nécessaire."

echo "----------------------------------------------------------------------------------------"
#R4 Utilisation des fonctionnalités de contrôle d’accès
echo -e "\n${purple}#R4 Utilisation des fonctionnalités de contrôle d'accès :${blue} Non évaluée${normal}"
echo "Utilisation des fonctionnalités de contrôle d’accès. Il est recommandé d’utiliser les 
fonctionnalités de contrôle d’accès obligatoire (MAC) en plus du traditionnel modèle utilisateur
 Unix (DAC), voire éventuellement de les combiner avec des mécanismes de cloisonnement."

echo "----------------------------------------------------------------------------------------"
#R5 Principe de défense en profondeur
echo -e "\n${purple}#R5 Principe de défense en profondeur :${blue} Non évaluée${normal}"
echo "Sous Unix et dérivés, la défense en profondeur doit reposer sur une combinaison de
barrières qu’il faut garder indépendantes les unes des autres. Par exemple :
– authentification nécessaire avant d’effectuer des opérations, notamment quand elles
sont privilégiées ;
– journalisation centralisée d’évènements au niveau systèmes et services ;
– priorité à l’usage de services qui implémentent des mécanismes de cloisonnement et/ou
de séparation de privilèges ;
– utilisation de mécanismes de prévention d’exploitation."

echo "----------------------------------------------------------------------------------------"
#R6 Cloisonnement des services réseau
echo -e "\n${purple}#R6 Cloisonnement des services réseau :${blue} Non évaluée${normal}"
echo "Les services réseau doivent autant que possible être hébergés sur des environnements
distincts. Cela évite d’avoir d’autres services potentiellement affectés si l’un d’eux se
retrouve compromis sous le même environnement."

echo "----------------------------------------------------------------------------------------"
#R7 Journalisation de l’activité des services
echo -e "\n${purple}#R7 Journalisation de l’activité des services${blue} Non évaluée${normal}"
echo "Les activités du système et des services en cours d’exécution doivent être journalisées et
archivées sur un système externe, non local."

echo "----------------------------------------------------------------------------------------"
#R8 Mises à jour régulières
nb=$(uname -a |grep -c "Debian")
echo -e "\n${purple}#R8 Mises à jour régulières${normal}"
if [ $nb -eq 1 ]
 then 
        echo "Une simulation de mise à jour a été écrite dans l'annexe."
        Ecrire_Entete "#R8 - Simulation de mise à jour (apt-get)"
        apt-get update && apt-get upgrade -s >> $Nom_Annexe
        Ecrire_Separation
fi
if [ -f /etc/redhat-release ]
 then 
	nb=$(grep -c "CentOS" /etc/redhat-release)
	if [ $nb -eq 1 ]
	 then 
                echo "Une simulation de mise à jour a été écrite dans l'annexe."
                Ecrire_Entete "#R8 - Simulation de mise à jour (yum)"
                yum check-update >> $Nom_Annexe
                Ecrire_Separation
	fi
fi

echo "----------------------------------------------------------------------------------------"
#R9 Configuration matérielle
echo -e "\n${purple}#R9 Configuration matérielle :${blue} Non évaluée${normal}"
echo "Il est conseillé d’appliquer les recommandations de configuration mentionnées dans
la note technique « Recommandations de configuration matérielle de postes clients et
serveurs x86_4»"

echo "----------------------------------------------------------------------------------------"
#R10 Architecture 32 et 64 bits
echo -e "\n${purple}#R10 Architecture 32 et 64 bits${normal}"
nb=$(arch | grep -c x86_64)
if [ $nb -ne 1 ]
 then   
        echo "${red}Vous devez privilégier une installation 64bits de votre système${normal}"
 else 
        echo "${green}Vous avez privilégié une installation 64bits de votre système${normal}"
fi

echo "----------------------------------------------------------------------------------------"
#R11 Directive de configuration de l’IOMMU
echo -e "\n${purple}#R11 Directive de configuration de l’IOMMU${normal}"
nb=$(grep -c "iommu=force"  /etc/default/grub)
if [ $nb -eq 0 ]
 then   
        echo "${red}L’activation du service d’IOMMU permet de protéger la mémoire du système${normal}"
	echo "Ajoutez la variable iommu=force  dans /etc/default/grub"
 else
        echo "${green}L’activation du service d’IOMMU permet de protéger la mémoire du système${normal}"
fi

echo "----------------------------------------------------------------------------------------"
#R12 Partitionnement type
echo -e "\n${purple}#R12 Partitionnement type${blue} Non évaluée${normal}"
echo "Un partitionnement type a été écrit dans l'annexe."
Ecrire_Entete "#R12 - Partitionnement type"
Ecrire_ligneTableauR12
Ecrire_Annexe "# \tPoint de montage\t | \tOptions\t\t\t | \tDescription\t\t\t\t\t\t #"
Ecrire_ligneTableauR12
Ecrire_Annexe "# \t/\t\t\t | <sans option>\t\t | Partition racine, contient le reste de l’arborescence\t #"
Ecrire_ligneTableauR12
Ecrire_Annexe "# \t/boot\t\t\t | nosuid,nodev,noexec\t\t | Contient le noyau et le chargeur de démarrage.\t\t #"
Ecrire_Annexe "# \t\t\t\t | (noauto optionnel)\t\t | nécessaire une fois le boot terminé\t\t\t\t #"
Ecrire_Annexe "# \t\t\t\t | \t\t\t\t | (sauf mise à jour)\t\t\t\t\t\t #"
Ecrire_ligneTableauR12
Ecrire_Annexe "# \t/opt\t\t\t | nosuid,nodev(ro optionnel)\t | Packages  additionnels  au  système.\t\t\t\t  #"
Ecrire_Annexe "# \t\t\t\t | \t\t\t\t | Montage en lecture seule si non utilisé\t\t\t #"
Ecrire_ligneTableauR12
Ecrire_Annexe "# \t/tmp\t\t\t | nosuid,nodev,noexec\t\t | Fichiers temporaires. Ne doit contenir\t\t\t #"
Ecrire_Annexe "# \t\t\t\t | \t\t\t\t | que des éléments non exécutables.\t\t\t\t #"
Ecrire_Annexe "# \t\t\t\t | \t\t\t\t | Nettoyé après redémarrage\t\t\t\t\t #"
Ecrire_ligneTableauR12
Ecrire_Annexe "# \t/srv\t\t\t | nosuid,nodev\t\t\t | Contient des fichiers servis par un\t\t\t\t #"
Ecrire_Annexe "# \t\t\t\t | (noexec,ro optionnels)\t | service type web, ftp, etc.\t\t\t\t\t #"
Ecrire_ligneTableauR12
Ecrire_Annexe "#  \t/home\t\t\t | nosuid,nodev,noexec\t\t | Contient  les HOME utilisateurs.\t\t\t\t #"
Ecrire_Annexe "#  \t\t\t\t | \t\t\t\t | Montage  en  lecture  seule  si  non utilisé\t\t\t #"
Ecrire_ligneTableauR12
Ecrire_Annexe "#  \t/proc\t\t\t | hidepid=1\t\t\t | Contient des informations sur les processus\t\t\t #"
Ecrire_Annexe "# \t\t\t\t | \t\t\t\t | et le système\t\t\t\t\t\t #"
Ecrire_ligneTableauR12
Ecrire_Annexe "# \t/usr\t\t\t | nodev\t\t\t | Contient la majorité des utilitaires et\t\t\t #"
Ecrire_Annexe "# \t\t\t\t | \t\t\t\t | fichiers système\t\t\t\t\t\t #"
Ecrire_ligneTableauR12
Ecrire_Annexe "# \t/var\t\t\t | nosuid,nodev,noexec\t\t | Partition contenant des fichiers variables\t\t\t #"
Ecrire_Annexe "# \t\t\t\t | \t\t\t\t | pendant  la  vie  du  système\t\t\t\t\t #"
Ecrire_Annexe "# \t\t\t\t | \t\t\t\t | (mails, fichiers PID, bases de données d’un service)\t\t #"
Ecrire_ligneTableauR12
Ecrire_Annexe "# \t/var/log\t\t | nosuid,nodev,noexec\t\t | Contient les logs du système\t\t\t\t\t #"
Ecrire_ligneTableauR12
Ecrire_Annexe "# \t/var/tmp\t\t | nosuid,nodev,noexec\t\t | Fichiers temporaires conservés après extinction\t\t #"
Ecrire_ligneTableauR12
Ecrire_Separation

echo "----------------------------------------------------------------------------------------"
#R13 Restrictions d’accès sur le dossier boot
echo -e "\n${purple}#R13 Restrictions d’accès sur le dossier boot${normal}"
nb=$(mount | grep -v boot/ | grep -c boot)
if [ $nb -ne 0 ]
 then 
	echo "${red}La partition /boot ne devrait pas être accessible${normal}"
 else
        echo "${green}le dossier boot n'est pas accessible${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R14 Installation de paquets réduite au strict nécessaire${blue} Non évaluée${normal}"

echo "----------------------------------------------------------------------------------------"
#R15 Choix des dépôts de paquets
echo -e "\n${purple}#R15 Choix des dépôts de paquets${normal}"
echo "Préconisation: Seul les dépôts connus et offciels doivent etre utilisés"
echo "Les dépôts utilisés ont été écrit dans l'annexe."
Ecrire_Entete "#R15 - Liste des dépôts utilisés"
cat /etc/apt/sources.list >> $Nom_Annexe
Ecrire_Separation

echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R16 Dépôts de paquets durcis${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R17 Mot de passe du chargeur de démarrage${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R18 Robustesse du mot de passe administrateur${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R19 Imputabilité des opérations d’administration${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R20 Installation d’éléments secrets ou de confiance${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R21 Durcissement et surveillance des services soumis à des flux arbitraires${blue} Non évaluée${normal}"

echo "----------------------------------------------------------------------------------------"
#R22 Paramétrage des sysctl réseau
echo -e "\n${purple}#R22 Paramétrage des sysctl réseau${normal}"
echo "Préconisation : Pas de  routage  entre  les  interfaces"
val=$(sysctl net.ipv4.ip_forward | tail -c2)
a=1
if [ $val = $a ]
 then
        echo "${red}Le routage est actif entre vos interfaces, est-ce normal ?${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.ip_forward=0"
 else
        echo "${green}Le routage est désactivé entre vos interfaces${normal}"
fi

echo -e "\nFiltrage  par  chemin  inverse"
echo "Préconisation : Pas de routage des flux étrangés (all)"
a=0
val=$(sysctl net.ipv4.conf.all.rp_filter | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le routage des paquets étrangers est activé${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.all.rp_filter=1"
 else
        echo "${green}Le routage des paquets étrangers est désactivé${normal}"
fi

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

echo -e "\nNe pas  envoyer  de  redirections  ICMP"
echo "Préconisation : Pas de  redirection ICMP (all)"
a=1
val=$(sysctl net.ipv4.conf.all.send_redirects | tail -c2)
if [ $val = $a ]
 then
        echo "${red}La redirection ICMP est activée${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.all.send_redirects=0"
 else
        echo "${green}La redirection ICMP est déactivée${normal}"
fi

echo -e "\nNe pas  envoyer  de  redirections  ICMP"
echo "Préconisation : Pas de  redirection ICMP (default)"
a=1
val=$(sysctl net.ipv4.conf.default.send_redirects | tail -c2)
if [ $val = $a ]
 then
        echo "${red}La redirection ICMP est activée${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.default.send_redirects=0"
 else
        echo "${green}La redirection ICMP est déactivée${normal}"
fi

echo -e "\nRefuser  les  paquets  de  source  routing"
echo "Préconisation : Refuser  les  paquets  de  source  routing (all)"
a=1
val=$(sysctl net.ipv4.conf.all.accept_source_route | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le source  routing est activé${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.all.accept_source_route=0"
 else
        echo "${green}Le source  routing est déactivé${normal}"
fi

echo -e "\nRefuser  les  paquets  de  source  routing"
echo "Préconisation : Refuser  les  paquets  de  source  routing (default)"
a=1
val=$(sysctl net.ipv4.conf.default.accept_source_route | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le source  routing est activé${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.default.accept_source_route=0"
 else
        echo "${green}Le source  routing est déactivé${normal}"
fi

echo -e "\nNe pas  accepter  les  ICMP de type  accept redirect"
echo "Préconisation : Refuser  les  ICMP de type redirect (all)"
a=1
val=$(sysctl net.ipv4.conf.all.accept_redirects | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le serveur accepte les flux de type ICMP redirect${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.all.accept_redirects=0"
 else
        echo "${green}Le serveur n'accepte pas les flux de type ICMP redirect${normal}"
fi

echo -e "\nNe pas  accepter  les  ICMP de type  secure redirect"
echo "Préconisation : Refuser  les  ICMP de type redirect (all)"
a=1
val=$(sysctl net.ipv4.conf.all.secure_redirects | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le serveur accepte les flux de type ICMP redirect${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.all.secure_redirects=0"
 else
        echo "${green}Le serveur n'accepte pas les flux de type ICMP redirect${normal}"
fi

echo -e "\nNe pas  accepter  les  ICMP de type  accept redirect"
echo "Préconisation : Refuser  les  ICMP de type redirect (default)"
a=1
val=$(sysctl net.ipv4.conf.default.accept_redirects | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le serveur accepte les flux de type ICMP redirect${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.default.accept_redirects=0"
 else
        echo "${green}Le serveur n'accepte pas les flux de type ICMP redirect${normal}"
fi

echo -e "\nNe pas  accepter  les  ICMP de type  accept redirect"
echo "Préconisation : Refuser  les  ICMP de type redirect (default)"
a=1
val=$(sysctl net.ipv4.conf.default.secure_redirects | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le serveur accepte les flux de type ICMP redirect${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.default.secure_redirects=0"
 else
        echo "${green}Le serveur n'accepte pas les flux de type ICMP redirect${normal}"
fi

echo -e "\nLogger  les  paquets  ayant  des IPs  anormales"
echo "Préconisation : Logger  les  paquets  ayant  des IPs  anormales (default)"
a=1
val=$(sysctl net.ipv4.conf.all.log_martians | tail -c2)
if [ $val = $a ]
 then
        echo "${green}les paquets sont loggés${normal}"
 else
        echo "${red}les paquets  ne sont pas loggés${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.conf.all.log_martians=1"
fi

# RFC  1337
echo -e "\nRFC 1337"
echo "Préconisation : TIME-WAIT Assassination Hazards in TCP"
a=1
val=$(sysctl net.ipv4.tcp_rfc1337 | tail -c2)
if [ $val = $a ]
 then
        echo "${green}Problème tcp traité${normal}"
 else
        echo "${red}Problème tcp non-traité${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.tcp_rfc1337=1"
fi

# Ignorer  les réponses  non  conformes à la RFC  1122
echo -e "\nIgnorer  les réponses  non  conformes à la RFC 1122"
echo "Préconisation : Ignorer  les réponses  non  conformes"
a=1
val=$(sysctl net.ipv4.icmp_ignore_bogus_error_responses | tail -c2)
if [ $val = $a ]
 then
        echo "${green}Réponses ignorées${normal}"
 else
        echo "${red}Réponses ICMP traitées${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"
fi

# Augmenter  la plage  pour  les  ports éphémères
echo -e "\nAugmenter  la plage  pour  les  ports éphémères"
a=$(sysctl net.ipv4.ip_local_port_range |cut -f 2)
b=65535
if [ "$a" -ne "$b" ]
 then
        echo "${red}La plage de ports éphèmères est à augmenter${normal}"
 else
        echo  "${green}La plage de ports éphèmères est conforme${normal}"
fi
echo -e "si besoin : sysctl -w net.ipv4.ip_local_port_range=\"32768 65535\""

# Utiliser  les SYN cookies
echo "Utiliser  les SYN  cookies"
a=1
val=$(sysctl net.ipv4.tcp_syncookies | tail -c2)
if [ $val = $a ]
 then
        echo "${green}SYN cookies utilisés${normal}"
 else
        echo "${red}SYN cookies ignorés${normal}"
	echo "Pour mise en place : sysctl -w net.ipv4.tcp_syncookies=1"
fi

echo "-e \nDésactiver  le  support  des "router  solicitations" (all)"
a=1
val=$(sysctl net.ipv6.conf.all.router_solicitations  | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le support est activé${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.all.router_solicitations=0"
 else
        echo "${green}Le support est désactivé${normal}"
fi

echo -e "\nDésactiver  le  support  des "router  solicitations" (default)"
a=1
val=$(sysctl net.ipv6.conf.default.router_solicitations | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le support est activé${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.default.router_solicitations=0"
 else
        echo "${green}Le support est désactivé${normal}"
fi

echo -e "\nNe pas  accepter  les "routers  preferences" par "router  advertisements"(all)"
a=1
val=$(sysctl net.ipv6.conf.all.accept_ra_rtr_pref | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le support est activé ${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.all.accept_ra_rtr_pref=0"
 else
        echo "${green}Le support est désactivé${normal}"
fi

echo -e "\nNe pas  accepter  les "router  preferences" par "router  advertisements"(default)"
a=1
val=$(sysctl net.ipv6.conf.default.accept_ra_rtr_pref | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le support est activé ${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.default.accept_ra_rtr_pref=0"
 else
        echo "${green}Le support est désactivé${normal}"
fi

echo -e "\nPas de  configuration  auto  des  prefix  par "router  advertisements"(all)"
a=1
val=$(sysctl net.ipv6.conf.all.accept_ra_pinfo | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le support est activé ${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.all.accept_ra_pinfo=0"
 else
        echo "${green}Le support est désactivé${normal}"
fi

echo "Pas de  configuration  auto  des  prefix  par "router  advertisements"(default)"
a=1
val=$(sysctl net.ipv6.conf.default.accept_ra_pinfo | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le support est activé ${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.default.accept_ra_pinfo=0"
 else
        echo "${green}Le support est désactivé${normal}"
fi

echo -e "\nPas d’apprentissage  du  routeur  par défaut  par "router  advertisements"(all)"
a=1
val=$(sysctl net.ipv6.conf.all.accept_ra_defrtr | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le support est activé ${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.all.accept_ra_defrtr=0"
 else
        echo "${green}Le support est désactivé${normal}"
fi

echo "Pas d’apprentissage  du  routeur  par défaut  par "router  advertisements"(default)"
a=1
val=$(sysctl net.ipv6.conf.default.accept_ra_defrtr | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le support est activé ${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.default.accept_ra_defrtr=0"
 else
        echo "${green}Le support est désactivé${normal}"
fi

echo -e "\nPas de  configuration  auto  des  adresses à partir  des "router advertisements"(all)"
a=1
val=$(sysctl net.ipv6.conf.all.autoconf| tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le support est activé ${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.all.autoconf=0"
 else
        echo "${green}Le support est désactivé${normal}"
fi

echo "Pas de configuration auto des adresses à partir des "router advertisements"(default)"
a=1
val=$(sysctl net.ipv6.conf.default.autoconf | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Le support est activé ${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.default.autoconf=0"
 else
        echo "${green}Le support est désactivé${normal}"
fi

echo -e "\nNe pas accepter les ICMP de type redirect (all)"
a=1
val=$(sysctl net.ipv6.conf.all.accept_redirects | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Les ICMP redirect sont acceptées${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.all.accept_redirects=0"
 else
        echo "${green}Les ICMP redirect sont refusées${normal}"
fi

echo "Ne pas  accepter  les  ICMP de type  redirect (default)"
a=1
val=$(sysctl net.ipv6.conf.default.accept_redirects | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Les ICMP redirect sont acceptées${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.default.accept_redirects=0"
 else
        echo "${green}Les ICMP redirect sont refusées${normal}"
fi

echo -e "\nRefuser  les  packets  de  source  routing (all)"
a=1
val=$(sysctl net.ipv6.conf.all.accept_source_route | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Les packets de source routing sont acceptés${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.all.accept_source_route=0"
 else
        echo "${green}Les packets de source routing sont refusés${normal}"
fi

echo "Refuser  les  packets  de  source  routing(default)"
a=1
val=$(sysctl net.ipv6.conf.default.accept_source_route | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Les packets de source routing sont acceptés${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.default.accept_source_route=0"
 else
        echo "${green}Les packets de source routing sont refusés${normal}"
fi

echo -e "\nNombre  maximal d’adresses  autoconfigurées par  interface (all)"
a=0
val=$(sysctl net.ipv6.conf.all.max_addresses | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Les packets de source routing sont acceptés${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.all.max_addresses=1"
 else
        echo "${green}Les packets de source routing sont refusés${normal}"
fi

echo "Nombre  maximal d’adresses  autoconfigurées par  interface (default)"
a=0
val=$(sysctl net.ipv6.conf.default.max_addresses | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Les packets de source routing sont acceptés${normal}"
	echo "Pour mise en place : sysctl -w net.ipv6.conf.default.max_addresses=1"
 else
        echo "${green}Les packets de source routing sont refusés${normal}"
fi

#R23 Paramétrage des sysctl système
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R23 Paramétrage des sysctl système${normal}"
echo "Désactivation  des  SysReq"
a=1
val=$(sysctl kernel.sysrq | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Les requètes systèmes sont activées${normal}"
	echo "Pour mise en place : sysctl -w kernel.sysrq=0"
 else
        echo "${green}Les requètes systèmes sont activées${normal}"
fi


echo -e "\nPas de core  dump  des exécutables  setuid"
a=1
val=$(sysctl fs.suid_dumpable | tail -c2)
if [ $val = $a ]
 then
        echo "${red}Les core dump sont possibles${normal}"
	echo "Pour mise en place : sysctl -w fs.suid_dumpable=0"
 else
        echo "${green}Les core dump sont désactivés${normal}"
fi

echo -e "\nInterdiction de déréférencer des liens (symlinks) vers des fichiers dont l’utilisateur courant n’est pas le propriétaire"
a=0
val=$(sysctl fs.protected_symlinks| tail -c2)
if [ $val = $a ]
 then
        echo "${red}Les déréférencements sont possibles${normal}"
	echo "Pour mise en place : sysctl -w fs.protected_symlinks=1"
 else
        echo "${green}Le déréférencement des liens symboliques est désactivé${normal}"
fi

echo "Interdiction de déréférencer des liens (hardlinks) vers des fichiers dont l’utilisateur courant n’est pas le  propriétaire"
a=0
val=$(sysctl fs.protected_hardlinks| tail -c2)
if [ $val = $a ]
 then
        echo "${red}Les déréférencements sont possibles${normal}"
	echo "Pour mise en place : sysctl -w fs.protected_hardlinks=1"
 else
        echo "${green}Le déréférencement des liens symboliques est désactivé${normal}"
fi

echo -e "\nActivation de l'ASLR"
a=2
val=$(sysctl kernel.randomize_va_space| tail -c2)
if [ $val = $a ]
 then
        echo "${green}L'ASLR est activée${normal}"
 else
	echo "${red}L'ASLR n'est pas activée${normal}"
	echo "Pour mise en place : sysctl -w kernel.randomize_va_space=2"
fi

echo -e "\nInterdiction  de  mapper  de la mémoire  dans  les  adresses  basses  "
a=$(sysctl vm.mmap_min_addr |cut -d" " -f 3)
b=65536
if [ "$a" -ne "$b" ]
then
        echo "${red}Il est possible de mapper la mémoire dans les adresses basses${normal}"
	echo "Pour mise en place : sysctl -w vm.mmap_min_addr=65536"
 else
        echo "${green}La plage de mémoire adressable est conforme${normal}"
fi

# Espace  de choix  plus  grand  pour  les  valeurs  de PID
echo -e "\nEspace  de choix  plus  grand  pour  les  valeurs  de PID"
a=$(sysctl kernel.pid_max |cut -d" " -f 3)
b=65536
if [ "$a" -ne "$b" ]
 then
        echo "${red}Il'espace de choix pour les valeurs de PID doit être augementé${normal}"
	echo "Pour mise en place : sysctl -w kernel.pid_max=65536"
 else
        echo "${green}L'espace de chois PID est conforme${normal}"
fi

echo -e "\nObfuscation  des  adresses mémoire  kernel"
a=1
val=$(sysctl kernel.kptr_restrict | tail -c2)
if [ $val = $a ]
 then
        echo "${green}Obfuscation  des  adresses mémoire  kernel activé${normal}"
 else
        echo "${red}Obfuscation  des  adresses mémoire  kernel désactivé${normal}"
	echo "Pour mise en place : sysctl -w kernel.kptr_restrict=1"
fi

echo -e "\nRestriction d’accès au  buffer  dmesg"
a=1
val=$(sysctl kernel.dmesg_restrict | tail -c2)
if [ $val = $a ]
 then
        echo "${green}Accès au buffer dmesg restreint${normal}"
 else
        echo "${red}L'accès au buffer dmesg n'est pas restreint${normal}"
	echo "Pour mise en place : sysctl -w kernel.dmesg_restrict=1"
fi

# Restreint l’utilisation du sous système perf
echo -e "\nRestriction de l’utilisation du sous système perf : paranoid"
a=2
val=$(sysctl kernel.perf_event_paranoid | tail -c2)
if [ $val = $a ]
 then
        echo "${green}Accès au sous systeme perf restreint${normal}"
 else
        echo "${red}L'accès au sous systeme perf n'est pas restreint${normal}"
	echo "Pour mise en place : sysctl -w kernel.perf_event_paranoid=2"
fi

echo -e "\nRestriction de l’utilisation du sous système perf : max sample rate"
a=1
val=$(sysctl kernel.perf_event_max_sample_rate | tail -c2)
if [ $val = $a ]
 then
        echo "${green}Accès au sous systeme perf max sample rate ${normal}"
 else
        echo "${red}L'accès au sous systeme perf n'est pas restreint${normal}"
	echo "Pour mise en place : sysctl -w kernel.perf_event_max_sample_rate=1"
fi

echo -e "\nRestriction de l’utilisation du sous système perf : cpu time max"
a=1
val=$(sysctl kernel.perf_cpu_time_max_percent | tail -c2)
if [ $val = $a ]
 then
        echo "${green}Accès au sous systeme perf max sample rate ${normal}"
 else
        echo "${red}L'accès au sous systeme perf n'est pas restreint${normal}"
	echo "Pour mise en place : sysctl -w kernel.perf_cpu_time_max_percent=1"
fi

#R24 Désactivation du chargement des modules noyau
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R24 Désactivation du chargement des modules noyau${normal}"
a=1
val=$(sysctl kernel.modules_disabled | tail -c2)
if [ $val = $a ]
 then
        echo "${green}Le chargement des modules noyau est désactivé${normal}"
 else
        echo "${red}Le chargement des modules noyau est activé${normal}"
	echo "Pour mise en place : sysctl -w kernel.modules_disabled=1"
	echo "Il est conseillé de mettre directement à jour votre fichier /etc/sysctl.conf"
	echo "en ajoutant la ligne suivante : kernel.modules_disabled = 1"
fi

#R25 Configuration sysctl du module Yama"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R25 Configuration sysctl du module Yama${normal}"
a=0
val=$(sysctl kernel.yama.ptrace_scope | tail -c2)
if [ $val = $a ]
 then
	echo "${red}Il est recommandé de charger le module de sécurité Yama lors du démarrage${normal}"
	echo "Vous pouvez par exemple passer l'argument security=yama au noyau"
	echo "et configurer la sysctl kernel.yama.ptrace_scope à une valeur au moins égale à 1"
 else
	echo "${green}Le module Yama est chargé${normal}"
fi

#R26 Désactivation des comptes utilisateurs inutilisés
#R27 Désactivation des comptes de services
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R26 Désactivation des comptes utilisateurs inutilisés${normal}"
echo "Les comptes utilisateurs inutilisés doivent être désactivés au niveau du système."
echo "Cette désactivation passe par l’invalidation du compte au niveau de son mot de passe"
echo "(suppression du champ pw_passwd dans le shadow et shell de login à /bin/false)."
echo -e "\n${purple}#R27 Désactivation des comptes de services${normal}"
echo "Les comptes de service doivent être désactivés."
echo -e "\nLa liste des comptes existants a été écrite dans l'annexe."
Ecrire_Entete "#R26 Désactivation des comptes utilisateurs inutilisés / #R27 Désactivation des comptes de services"
Ecrire_Annexe "Liste des comptes présents sur le système:"
cat /etc/passwd >> $Nom_Annexe
Ecrire_Annexe ""
Ecrire_Annexe "Vous pouvez vérouiller un compte avc la commande suivante: usermod -L <compte>"
Ecrire_Annexe "Vous pouvez désactiver son shell de login avec la commande suivante: usermod -s /bin/false <compte>"
Ecrire_Annexe "Vous pouvez désactiver un compte avec la commande suivante: usermod --expiredate 1 <compte>"
Ecrire_Separation

echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R28 Unicité et exclusivité des comptes de services système${blue} Non évaluée${normal}"

#R29 Délai d’expiration de sessions utilisateurs
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R29 Délai d’expiration de sessions utilisateurs${normal}"
Timeout=$(printenv TMOUT)
if (test ! $Timeout)
 then
        echo "${red}Vous n'avez pas défini de timeout pour la session.${normal}"
        echo "Vous pouvez le définir avec cette commande: echo TMOUT=120 >> /etc/environment"
        echo "Vous pouvez mettre la valeur que vous désirez en secondes."
 elif (test $Timeout -eq 0)
  then
        echo "${red}Vous avez désactivé le timeout pour la session, vous devriez le réactiver.${normal}"
        echo "Vous pouvez le définir avec cette commande: echo TMOUT=120 >> /etc/environment"
        echo "Vous pouvez mettre la valeur que vous désirez en secondes."
 elif (test $Timeout -gt 1000)
  then
        echo "${red}Le timeout de votre session est supérieur à 1000 secondes. Vous devriez le réduire.${normal}"
        echo "Vous pouvez le définir avec cette commande: echo TMOUT=120 >> /etc/environment"
        echo "Vous pouvez mettre la valeur que vous désirez en secondes."
 else
        echo "${green}Le timeout de votre session est de $Timeout secondes, c'est une valeur correcte.${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R30 Applications utilisant PAM${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R31 Sécurisation des services réseau d’authentification PAM${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R32 Protection des mots de passe stockés${blue} Non évaluée${normal}"
#remarque : ANSSI recommande sha512 mais maintenant yescrypt est pris par défaut car meilleur.
#ANSSI pas mis à jour - étonnant ?
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R33 Sécurisation des accès aux bases utilisateurs distantes${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R34 Séparation des comptes système et d’administrateur de l’annuaire${blue} Non évaluée${normal}"

#R35 Valeur de umask
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R35 Valeur de umask${normal}"
User_Umask_recommande=0077
User_Umask=$(umask)
if test $User_Umask_recommande != $User_Umask
 then
      echo "${red}L'umask est $User_Umask.${normal}"
      echo "Le umask système doit être positionné à 0027"
      echo "(par défaut, tout ﬁchier créé n’est lisible que par l’utilisateur et son groupe, et modiﬁable uniquement par son propriétaire)."
      echo "Le umask pour les utilisateurs doit être positionné à 0077"
      echo "(tout ﬁchier créé par un utilisateur n’est lisible et modiﬁable que par lui)."
 else
      echo  "${green}l'umask est 0077. C'est la valeur recommandée.${normal}"
fi

#R36 Droits d’accès aux fichiers de contenu sensible
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R36 Droits d’accès aux fichiers de contenu sensible${normal}"
echo "Les ﬁchiers à contenu sensible ne doivent être lisibles que par les utilisateurs ayant le strict besoin d’en connaître."
echo "Quand ces ﬁchiers contiennent des mots de passe (ou des empreintes de mots de passe) ils ne doivent être lisibles que par root."
echo "En revanche, les ﬁchiers publics qui contiennent la liste des utilisateurs sont lisibles par tout le monde, mais sont éditables uniquement par root."
echo "La liste des fichiers qui ne devrait être en lecture uniquement pour root a été écrit dans l'annexe avec les droits actuels."
Ecrire_Entete "#R36 Droits d’accès aux fichiers de contenu sensible"
Ecrire_Annexe "Liste des fichiers qui ne devrait être en lecture uniquement pour root:"
ls -l /etc/gshadow >> $Nom_Annexe
ls -l /etc/shadow >> $Nom_Annexe
Ecrire_Separation

#R37 Exécutables avec bits setuid et setgid
#R38 Exécutables setuid root
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R37 Exécutables avec bits setuid et setgid${normal}"
echo "Seuls les programmes spéciﬁquement conçus pour être utilisés avec les bits setuid (ou setgid) peuvent avoir ces bits de privilèges positionnés."
echo -e "\n${purple}#R38 Exécutables setuid root${normal}"
echo "Les exécutables setuid doivent être le moins nombreux possible."
echo "Lorsqu’il est attendu que seuls les administrateurs de la machine les exécutent, il faut leur retirer"
echo "le bit set-uid et leur préférer des commandes comme su ou sudo, qui peuvent être surveillées."
echo -e "\nLa liste des fichiers setuid/setgid présents sur le système a été écrite dans l'annexe."
Ecrire_Entete "#R37 Exécutables avec bits setuid et setgid / #R38 Exécutables setuid root"
Ecrire_Annexe "Voici une liste non exhaustive de ﬁchiers setuid root pouvant être rencontrés."
Ecrire_Annexe "Tout exécutable non mentionné dans cette liste devrait être examiné avec une attention particulière."
Ecrire_Annexe ""
Ecrire_ligneTableauR38
Ecrire_Annexe "#  \t\tExécutable\t\t\t | \t\tCommentaire\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /bin/mount\t\t\t\t\t | À désactiver, sauf si absolument nécessaire pour les utilisateurs.\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /bin/netreport\t\t\t\t | À désactiver.\t\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /bin/ping6\t\t\t\t\t | (IPv6) Idem ping.\t\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /bin/ping\t\t\t\t\t | (IPv4) Retirer droit setuid, sauf si un programme le requiert pour du monitoring.\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /bin/su\t\t\t\t\t | Changement d’utilisateur. Ne pas désactiver.\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /bin/umount\t\t\t\t\t | À désactiver, sauf si absolument nécessaire pour les utilisateurs.\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /sbin/mount.nfs4\t\t\t\t | À désactiver si NFSv4 est inutilisé.\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /sbin/mount.nfs\t\t\t\t | À désactiver si NFSv2/3 est inutilisé.\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /sbin/umount.nfs4\t\t\t\t | À désactiver si NFSv4 est inutilisé.\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /sbin/umount.nfs\t\t\t\t | À désactiver si NFSv2/3 est inutilisé.\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /sbin/unix_chkpwd\t\t\t\t | Permet de vériﬁer le mot de passe utilisateur pour des programmes non root. À désactiver si inutilisé.\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/at\t\t\t\t\t | À désactiver si atd n’est pas utilisé.\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/chage\t\t\t\t | À désactiver.\t\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/chfn\t\t\t\t\t | À désactiver.\t\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/chsh\t\t\t\t\t | À désactiver.\t\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/crontab\t\t\t\t | À désactiver si cron n’est pas requis.\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/fusermount\t\t\t\t | À désactiver sauf si des utilisateurs doivent monter des partitions FUSE.\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/gpasswd\t\t\t\t | À désactiver si pas d’authentiﬁcation de groupe.\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/locate\t\t\t\t | À désactiver. Remplacer par mlocate et slocate.\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/mail\t\t\t\t\t | À désactiver. Utiliser un mailer local comme ssmtp.\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/newgrp\t\t\t\t | À désactiver si pas d’authentiﬁcation de groupe.\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/passwd\t\t\t\t | À désactiver, sauf si des utilisateurs non root doivent pouvoir changer leur mot de passe.\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/pkexec\t\t\t\t | À désactiver si PolicyKit n’est pas utilisé.\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/procmail\t\t\t\t | À désactiver sauf si procmail est requis.\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/rcp\t\t\t\t\t | Obsolète. À désactiver.\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/rlogin\t\t\t\t | Obsolète. À désactiver.\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/rsh\t\t\t\t\t | Obsolète. À désactiver.\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/screen\t\t\t\t | À désactiver.\t\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/sudo\t\t\t\t\t | Changement d’utilisateur. Ne pas désactiver.\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/sudoedit\t\t\t\t | Idem sudo.\t\t\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/wall\t\t\t\t\t | À désactiver.\t\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/bin/X\t\t\t\t\t | À désactiver sauf si le serveur X est requis.\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/lib/dbus-1.0/dbus-daemon-launch-helper\t | À désactiver quand D-BUS n’est pas utilisé.\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/lib/openssh/ssh-keysign\t\t\t | À désactiver.\t\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/lib/pt_chown\t\t\t\t | À désactiver (permet de changer le propriétaire des PTY avant l’existence de devfs).\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/libexec/utempter/utempter\t\t | À désactiver si le proﬁl utempter SELinux n’est pas utilisé.\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/sbin/exim4\t\t\t\t | À désactiver si Exim n’est pas utilisé.\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/sbin/suexec\t\t\t\t | À désactiver si le suexec Apache n’est pas utilisé.\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/sbin/traceroute\t\t\t\t | (IPv4) Idem ping.\t\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe "# /usr/sbin/traceroute6\t\t\t\t | (IPv6) Idem ping.\t\t\t\t\t\t\t\t\t\t\t\t #"
Ecrire_ligneTableauR38
Ecrire_Annexe ""
Ecrire_Annexe "Liste des fichiers setuid/setgid présents sur le système"
find / -type f -perm /6000 -ls 2>/dev/null >> $Nom_Annexe
Ecrire_Separation
echo "Retirer les droits setuid ou setgid se fait au travers de la commande chmod :"
echo "chmod u-s <fichier > (Retire le bit setuid)"
echo "chmod g-s <fichier >  (Retire le bit setgid)"

echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R39 Répertoires temporaires dédiés aux comptes${blue} Non évaluée${normal}"

#R40 Sticky bit et droits d’accès en écriture
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R40 Sticky bit et droits d’accès en écriture${normal}"
nb=$(find / -type d -perm -0002 -a \! -uid 0 -ls 2>/dev/null | grep "" -c)
if [ $nb -ne 0 ]
 then 
	echo "${red}Des répertoires sont accessibles en écriture par tous.${normal}"
        echo "La liste des $nb répertoires concernés a été écrite dans l'annexe."
        echo "root devrait être le propriétaire de ces répertoires."
        echo "Tous les répertoires accessibles en écriture par tous doivent avoir le sticky bit armé."
        Ecrire_Entete "#R40 - Liste répertoires accessibles en écriture par tous"
        find / -type d -perm -0002 -a \! -uid 0 -ls 2>/dev/null  >> $Nom_Annexe
        Ecrire_Separation
 else
        echo "${green}Il n'y a pas de répertoire accessible en écriture par tous${normal}"
fi
nb=$(find / -type f -perm -0002 -ls 2>/dev/null | grep "" -c)
if [ $nb -ne 0 ]
then 
	echo "${red}Aucun ﬁchier régulier ne nécessite d’être modiﬁable par tous.${normal}"
        echo "La liste des $nb fichiers concernés a a été écrite dans l'annexe."
        echo "Quand un ﬁchier doit être modiﬁable par plusieurs utilisateurs ou programmes en même temps,"
        echo "un groupe doit être créé et seul ce groupe devra avoir des droits d’écriture sur ledit ﬁchier."
        Ecrire_Entete "#R40 - Liste fichiers modifiables par tous"
        find / -type f -perm -0002 -ls 2>/dev/null >> $Nom_Annexe
        Ecrire_Separation
else
        echo "${green}Il n'y a pas de fichier accessible en écriture par tous${normal}"
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R41 Sécurisation des accès pour les sockets et pipes nommées${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R42 Services et daemons résidents en mémoire${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R43 Durcissement et configuration du service syslog${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R44 Cloisonnement du service syslog par chroot${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R45 Cloisonnement du service syslog par container${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R46 Journaux d’activité de service${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R47 Partition dédiée pour les journaux${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R48 Configuration du service local de messagerie${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R49 Alias de messagerie des comptes de service${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R50 Journalisation de l’activité par auditd${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R51 Scellement et intégrité des fichiers${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R52 Protection de la base de données des scellés${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R53 Restriction des accès des services déployés${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R54 Durcissement des composants de virtualisation${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R55 Cage chroot et privilèges d’accès du service cloisonné${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R56 Activation et utilisation de chroot par un service${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R57 Groupe dédié à l’usage de sudo${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"

#R58 Directives de configuration sudo
#R59 Authentification des utilisateurs exécutant sudo
#R60 Privilèges des utilisateurs cible pour une commande sudo
#R61 Limitation du nombre de commandes nécessitant l’option EXEC
echo -e "\n${purple}#R58 Directives de configuration sudo${blue} Evaluée partiellement${normal}"
nb=$(grep -c "noexec" /etc/sudoers)
if [ $nb -eq 1 ]
 then
        echo "${green}L'execution des subsystem est interdite${normal}"
 else
        echo "${red}L'execution des subsystem est autorisé${normal}"
	echo "Ajouter les lignes suivants à votre sudoers :"
	echo "         Defaults noexec,requiretty,use_pty,umask=0027"
	echo "         Defaults ignore_dot,env_reset,passwd_timeout=1"
fi
echo -e "\n${purple}#R59 Authentification des utilisateurs exécutant sudo"
echo "#R60 Privilèges des utilisateurs cible pour une commande sudo"
echo "#R61 Limitation du nombre de commandes nécessitant l’option EXEC${normal}"
echo "Recommandations évaluées dans la #R58"

#R62 Du bon usage de la négation dans une spécification sudo
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R62 Du bon usage de la négation dans une spécification sudo${normal}"
nb=$(grep -c "!/" /etc/sudoers)
if [ $nb -eq 0 ]
 then
        echo "${green}Pas de négation dans votre fichier sudoers${normal}"
 else
        echo "${red}L'utilisation des négations est déconseillée${normal}"
	echo "Exemple :"
	echo "        User ALL=ALL, !/bin/sh"
	echo "         un cp de /bin/sh sous un autre nom suffit à le rendre utilisable"
fi

#R63 Arguments explicites dans les spécifications sudo
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R63 Arguments explicites dans les spécifications sudo${normal}"
#pas de * caractère jocker dans le sudoers
nb=$(grep -c "\*" /etc/sudoers)
if [ $nb -eq 0 ]
 then
        echo "${green}Pas de /* dans votre fichier sudoers${normal}"
 else
        echo "${red}L'utilisation des carat est déconseillée${normal}"
	echo "Toutes les commandes du fichier sudoers doivent préciser strictement les arguments autorisés à être utilisés pour un utilisateur donné."
        echo "L’usage de ( \* wildcard) dans les règles doit être autant que possible évité."
        echo "L’absence d’arguments auprès d’une commande doit être spécifiée par la présence d’une chaînevide (\"\")."
fi

echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R64 Du bon usage de sudoedit${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R65 Activation des profils de sécurité AppArmor${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R66 Activation de la politique targeted avec SELinux${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R67 Paramétrage des booléens SELinux${blue} Non évaluée${normal}"
# setsebool  -P allow_execheap=off"
# setsebool  -P allow_execmem=off
# setsebool  -P allow_execstack=off
# setsebool  -P secure_mode_insmod=off
# setsebool  -P ssh_sysadm_login=off

echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R68 Désinstallation des outils de débogage de politique SELinux${blue} Non évaluée${normal}"
echo "----------------------------------------------------------------------------------------"
echo -e "\n${purple}#R69 Confinement des utilisateurs interactifs non privilégiés${blue} Non évaluées${normal}"
echo "----------------------------------------------------------------------------------------"
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
   "Vérifier les critères de l'ANSSI"  \
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
      7) fonct_anssi > $Nom_Rapport exit ;;
      8) fonct_fail exit ;;
      9) fonct_rap exit ;;
      10) echo "Fin"
         exit 0 ;;
      *) echo "Fonction non implémentée"  ;;
   esac
done
