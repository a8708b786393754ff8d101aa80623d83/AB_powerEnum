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
}Windows

$objSearch = [adsisearcher]"";

function UserObjectEnum{

    <#
        .Description
        UserObjectEnum Shows attributes on the given search. 
    #>

    param(
        [System.DirectoryServices.SearchResultCollection]$ResultCollection
    )
    
        
    foreach ($element in $ResultCollection) {
        "CN: $($element.Properties.cn)";
        "ADSPath: $($element.Properties.adspath)";
        "SN: $($element.Properties.sn)";
        "SID: $($element.Properties.objectsid)";
        "Description: $($element.Properties.description)";
        "Membre de: $($element.Properties.memberof)";
        "DisplayName: $($element.Properties.displayname)";
        "DistinguishedName: $($element.Properties.distinguishedname)";
        "sAMAccountName: $($element.Properties.samaccountname)";

        foreach($key in $UAC_INDICATOR.Keys){ #NOTE- test UAC
            if($element.Properties.useraccountcontrol[0] -eq $UAC_INDICATOR[$key]){
                "UserAccountControl: $($key)";
            }
        }
        
        "UserPrincipalName: $($element.Properties.userprincipalname)";
        "Date de la derniere modification du mot de passe: $([datetime]::fromfiletime($element.Properties.pwdlastset[0]))";
        if ($element.Properties.accountExpires -eq 9223372036854775807){
            "Date d'expiration du compte: expire jamais"; #FIXME - fixer la conversion
        }else{
            "Date d'expiration du compte: $($element.Properties.accountexpires)";        
        }
        "=========================================================================";
        "";
    }
}

function Get-User{
    <#
        .Description
        Get-User Run a filtered search on all users search. 
    #>

    $objSearch.Filter = "(&(objectCategory=user))";
    $result = $objSearch.FindAll(); 
    
    UserObjectEnum($result);

    "$($result.Count) utilisateurs dans le domaine";
}
   

function Get-UserAdmin{
    <#
        .Description
        Get-UserAdmin Run a filtered search on admin user search. 
    #>
    
    $objSearch.Filter = "(&(objectCategory=user)(adminCount=1))";
    $result = $objSearch.FindAll(); 
    
    UserObjectEnum($result);

    "$($result.Count) utilisateurs admin";
}
    
function Get-UserDoesChangedPasswd{
    <#
        .Description
        Get-UserDoesChangedPasswd Run a filtered search looking for users who need to change their passwords. 
    #>
    
    $objSearch.Filter = "(&(objectCategory=user)(pwdLastSet=0))"; # Liste de tous les utilisateurs qui doivent changer de mot de passe lors de la prochaine connexion
    $result = $objSearch.FindAll(); 

    UserObjectEnum($result); 

    "$($result.Count) utilisateurs doivent changée leur mot de passe";
}

function Get-Userkerberoastable{
    <#
        .Description
        Get-Userkerberoastable Run a filtered search on finding users who are kerberoastable. 
    #>
    
    $objSearch.Filter = "(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"; #Liste de tous les utilisateurs kerberoastables
    $result = $objSearch.FindAll(); 

    UserObjectEnum($result); 

    "$($result.Count) utilisateurs kerberoastables"
}


function Get-PasswdDescription{
    <#
        .Description
        Get-PasswdDescription Run a filtered search looking for users who have the word password or pwd in their description. 
    #>
    
    $objSearch.Filter = "(&(objectCategory=user)(|description=*pass*)(description=*pwd*))"; #Liste de tous les utilisateurs avec *pass* ou *pwd* dans leur description
    $result = $objSearch.FindAll(); 

    UserObjectEnum($result);

    "$($result.Count) utilisateurs ont une descritpions intéressante.";
}

function Get-UserPasswShort{
    <#
        .Description
        Get-UserPasswShort Run a filtered search looking for users who have a short password (4 characters). 
    #>
    
    $objSearch.Filter = "(&(objectCategory=user)(badPwdCount>=4))"; #Liste de tous les utilisateurs qui sont presque verrouillés
    $result = $objSearch.FindAll(); 

    UserObjectEnum($result); 

    "$($result.Count) utilisateurs ont un mot de passe de 4 caractère";

}

function Get-UserAsrepRoastables{
    <#
        .Description
        Get-UserAsrepRoastables Exécutez une recherche filtrée sur la recherche d'utilisateur qui ne dispose pas de l'attribut requis de pré-authentification Kerberos.. 
    #>
    
    $objSearch.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"; #Liste des utilisateurs asrep-roastables
    $result = $objSearch.FindAll(); 

    UserObjectEnum($result); 

    "$($result.Count) utilisateurs asrep-roastables";
}


