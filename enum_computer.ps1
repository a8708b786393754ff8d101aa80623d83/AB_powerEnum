$SAMACCOUNTTYPE = [Ordered]@{SAM_DOMAIN_OBJECT = 0; SAM_GROUP_OBJECT  = 10000000; SAM_NON_SECURITY_GROUP_OBJECT =  10000001; SAM_ALIAS_OBJECT  = 20000000; SAM_NON_SECURITY_ALIAS_OBJECT = 20000001; SAM_USER_OBJECT = 30000000; SAM_NORMAL_USER_ACCOUNT = 30000000; SAM_MACHINE_ACCOUNT = 30000001; SAM_TRUST_ACCOUNT = 30000002; SAM_APP_BASIC_GROUP = 40000000; SAM_APP_QUERY_GROUP = 40000001}
$UAC_INDICATOR = [Ordered]@{
    SCRIPT=1;
    ACCOUNTDISABLE=2;
    HOMEDIR_REQUIRED=8;
    LOCKOUT	= 16;
    PASSWD_NOTREQD	= 32;
    PASSWD_CANT_CHANGE = 64;
    ENCRYPTED_TEXT_PWD_ALLOWED= 128;
    TEMP_DUPLICATE_ACCOUNT	= 256;
    NORMAL_ACCOUNT = 512;
    ACCOUNT_DISABLE_NORMAL_ACCOUNT = 514;
    INTERDOMAIN_TRUST_ACCOUNT = 2048;
    WORKSTATION_TRUST_ACCOUNT = 4096;
    NORMAL_ACCOUNT_DONT_EXPIRED_PASSWD = 66048;
    SERVER_TRUST_ACCOUNT = 8192;
    DONT_EXPIRE_PASSWORD = 65536;
    ACCOUNT_DISABLE_PASSWD_NOTREQD_NORMAL_ACCOUNT = 66082;
    MNS_LOGON_ACCOUNT = 131072;
    SMARTCARD_REQUIRED = 262144; 
    TRUSTED_FOR_DELEGATION = 524288;
    NOT_DELEGATED = 1048576;
    USE_DES_KEY_ONLY = 2097152;
    DONT_REQ_PREAUTH = 4194304;
    PASSWORD_EXPIRED = 8388608;
    TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216;
    PARTIAL_SECRETS_ACCOUNT	= 67108864;
}

$objSearch = [adsisearcher]"";

function ComputerObjectEnum{
    <#
        .Description
        ComputerObjectEnum Shows attributes on the given search. 
    #>

    param(
        [System.DirectoryServices.SearchResultCollection]$ResultCollection
    )
    
    foreach ($element in $ResultCollection){
        "Name : $($element.Properties.name)";
        "CN : $($element.Properties.cn)";
        "ADSPath: $($element.Properties.adspath)";
        "SID: $($element.Properties.objectsid)";
        "Object category: $($element.Properties.objectcategory)";
        "sAMAccountName: $($element.Properties.samaccountname)";

        foreach($key in $GROUP_TYPE.Keys){ #NOTE - test le type de group
            if($element.Properties.grouptype -eq $GROUP_TYPE[$key]){
                "Type d'étendue du groupe: $($key)";
            }
            
        }

        foreach($key in $UAC_INDICATOR.Keys){ #NOTE - test UAC
            if($element.Properties.useraccountcontrol[0] -eq $UAC_INDICATOR[$key]){
                "UserAccountControl: $($key)";
            }
        }
        
        if(! [string]::IsNullOrEmpty($element.Properties.member)){
            "Membre: $($element.Properties.member)";
        
        }
        
        foreach($key in $SAMACCOUNTTYPE.Keys){ #NOTE - teste le type de samaccount
            if ([System.Convert]::ToString($element.Properties.samaccounttype[0],16) -eq $SAMACCOUNTTYPE[$Key]){
                "sAMAccountType: $($key)";
            }

        }
        
        if(! [string]::IsNullOrEmpty($element.Properties.iscriticalsystemobject)){
            "Critical Object: $($element.Properties.iscriticalsystemobject)";       
        }

        if(! [string]::IsNullOrEmpty($element.Properties.description)){
            "Description: $($element.Properties.description)";        
        }
        if ($element.Properties.accountExpires -eq 9223372036854775807){
            "Date d'expiration de l'objet: expire jamais";
        }else{
            "Date d'expiration de l'objet: $($element.Properties.accountexpires)";        
        }

        "Nombre de login: $($element.Properties.logoncount)";        
        "Date de derniere connexion: $([datetime]::fromfiletime($element.Properties.lastlogon[0]))";        
        "OS: $($element.Properties.operatingsystem) v$($element.Properties.operatingsystemversion)";      
        "Date de la derniere modification du mot de passe: $([datetime]::fromfiletime($element.Properties.pwdlastset[0]))";
        "Nom du service principale $($element.Properties.serviceprincipalname)"
        "Nombre de mot de passe faux: $($element.Properties.badpwdcount)"
        "Nom d'hôte DNS: $($element.Properties.dnshostname)"
        
        "Certificat: $($element.Properties.usercertificate)";
        " algorithmes de chiffrement pris en charge par les comptes d'utilisateur: $($element.Properties['msds-supportedencryptiontypes'])"
        "================================================================"
    }
}

function Get-Computers{
    <#
        .Description
        Get-Computers Run a filter search on computers.
    #>
    
    $objSearch.Filter = "(&(objectCategory=Computer))"
    $result = $objSearch.FindAll(); 

    ComputerObjectEnum($result);
    "[$]$($result.Count) Ordinateurs[$]"
}
function Get-ComputerDesactivedAdministrator{
    <#
        .Description
        Get-ComputerDesactivedAdministrator Execute a filter search on disabled administrator accounts.
    #>

    $objSearch.Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=2))"
    $result = $objSearch.FindAll(); 

    ComputerObjectEnum($result);
    "[$]$($result.Count) Ordinateurs adminstrativement désavtivé[$]"
}
function Get-ComputersDC{
    <#
        .Description
        Get-ComputersDC Run a filter search on the domain controller search.
    #>

    $objSearch.Filter = "(&(objectCategory=Ordinateur)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    $result = $objSearch.FindAll(); 

    ComputerObjectEnum($result);
    "[$]$($result.Count) controleur(s) de domaine[$]"
}

#================== COMPUTER OS =====================
function Get-ComputerWindows{
    <#
        .Description
        Get-ComputerWindows Run a filter search on Windows Computer Search.
    #>

    $objSearch.Filter = "(&(&(objectCategory=Computer)(operatingSystem=Windows *)))"
    $result = $objSearch.FindAll(); 

    ComputerObjectEnum($result);
    "[$]$($result.Count) Ordinateurs Windows[$]"
}
function Get-ComputerLinux{
    <#
        .Description
        Get-ComputerWindows Run a filter search on Linux Computer Search.
    #>

    $objSearch.Filter = "(&(&(objectCategory=Computer)(operatingSystem=Linux *)))"
    $result = $objSearch.FindAll(); 

    ComputerObjectEnum($result);
    "[$]$($result.Count) Ordinateurs Linux[$]"
}


# $objSearch.Filter = "(sAMAccountType=805306369)"; #Liste de toutes les Workstations
# $objSearch.Filter = "(&(objectClass=computer)(msDS-KeyCredentialLink=*))"; #Liste des machines ayant un KeyCredentialLink