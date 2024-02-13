$objSearch = [adsisearcher]"";


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


function ServiceObjectEnum{

    param(
        [System.DirectoryServices.SearchResultCollection]$ResultCollection
    )
    
        
    foreach ($element in $ResultCollection) {
        "Nom du service: $($element.Properties.serviceprincipalname)"
        "Nom: $($element.Properties.name)";
        "CN: $($element.Properties.cn)";
        "ADSPath: $($element.Properties.adspath)";
        "Description: $($element.Properties.description)";
        "Membre de: $($element.Properties.memberof)";
        "DisplayName: $($element.Properties.displayname)";
        "DistinguishedName: $($element.Properties.distinguishedname)";
        "sAMAccountName: $($element.Properties.samaccountname)";

        foreach($key in $UAC_INDICATOR.Keys){
            if($element.Properties.useraccountcontrol[0] -eq $UAC_INDICATOR[$key]){
                "UserAccountControl: $($key)";
            }
        }
        
        "Date de la derniere modification du mot de passe: $([datetime]::fromfiletime($element.Properties.pwdlastset[0]))";

        if ($element.Properties.accountExpires -eq 9223372036854775807){
            "Date d'expiration du compte: expire jamais"; #FIXME - fixer la conversion
        }else{
            "Date d'expiration du compte: $($element.Properties.accountexpires)";        
        }

        if($element.Properties.admincount -eq 1 ){
            "Compte Administrateur: Yes"
        }
        if($element.Properties.iscriticalsystemobject){
            "Objet critique: Yes"; 
        }
        "=========================================================================";
        "";
    }
}

function Get-Services{
    $objSearch.Filter = "(servicePrincipalName=*)"; #Liste de tous les servicePrincipalName
    $result = $objSearch.FindAll();

    ServiceObjectEnum($result);
    "[-*-]$($result.Count) services[-*-]"
}