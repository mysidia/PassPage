<?php

# Who should we send credentials to  by default  when sub1.php is used ?
#
# This is for allowing an external user to submit a credential to an internal user.
#
$DEFAULT_recipient = 'devnull@example.local';

#  Recipients we can e-mail directly, if you use
#   https://example.com/path/to/sub1.php?kc=(CODE HERE)
#
$CODED_recipients = array(
   '*****fewa' => array ('example@localhost', 'Invalid')
);

require 'TECH_WL.php';

$WL2 = 'ameritech amraam arcnet arcofi arcofi-sp arcoti arpanet ashrae attcom autodin
autosevcom autovon ad astra barrnet bitbucket devnull bbd0/1 belcore bellcore benelux bififo
bisync bitnet borscht bisync cassis catlas cd-rom cenelec cerfnet cirris
com/exp compact comptel comsat conacyt contac cornet cosine cosmic cosmos
costar csma csma/ca csma/cd cucrit cislunar cornet das-wdt disoss dl5mda dlu-pg
domain dpn-ph dyrect e-mail eadas/nm eadass ebcdic eeprom empress et/acc
etsaci fccset fedsim foobar fortran fractal geisco grp mod hepnet
iec-q1 institute intelsat inwats isac-p isac-s in-situ jintaccs jovial jvncnet
kermit lcamos lcrmkr macsyma map/top mat-cals matfap mcp/as mctrap mfenet
mflops mifass milnet mosfet ms-dos muldem multics munich nabisco naccirn
nardac navdac navswc nearnet nexrad nicmos norgen nsfnet nysernet nzusugi
oopart orfeus osi/rm ospfigp outwats paccom patrol pc-dos premis prepnet
promats protel physrev qwerty rc mac remobs rlogin roygbiv rsts/e
safenet sampex scoops secnav sicofi sigcat sipmos siscom sitest smaspu
smegma smersh snobol spawar spitbol spuc/dl sql/ds ssttss statmux studialo
sunoco suranet sysgen skyhook tacacs tanstaafl tcp/ip teflon telekom telnet
telsam toplas topsmp trusix unesco unicef unistar uucico viable vm/cms
vpi&su wfpcii wwmccs wysiwis wysiwyg microsoft linux linuxwins windows windowswins macrosoft';



$HASHMAKER_kc = array(
    'example' => array( '', '', 'first.last first last', 'SOFT', 'HIDE' )

);


#######

# Access control list


# What IP ranges are allowed to CREATE a temporary link for sharing? ?
$CREATE_allowed_ip_regex = "/^(10.)/";


# What IP ranges can VIEW a temporary URL ?
$VIEW_allowed_ip_regex = "/.*/";

# What IP ranges can submit a password to staff via credsend ? 
$CREDSEND_allowed_ip_regex = "/.*/";

$CRED_sender = 'credsend@example.local';

# What is the Base URL of this script?
$VIEW_baseurl = "https://example.local/oo/read.php?f=";

####
# Default timezone

date_default_timezone_set('US/Central');

?>
