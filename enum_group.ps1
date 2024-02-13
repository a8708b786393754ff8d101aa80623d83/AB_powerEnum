$GROUP_TYPE = [Ordered]@{GlobalSecurityGroup =  -2147483646; LocalSecurityGroup = -2147483644; BuiltinGroup = -2147483643; UniversalSecurityGroup = -2147483640};
$SAMACCOUNTTYPE = [Ordered]@{SAM_DOMAIN_OBJECT = 0; SAM_GROUP_OBJECT  = 10000000; SAM_NON_SECURITY_GROUP_OBJECT =  10000001; SAM_ALIAS_OBJECT  = 20000000; SAM_NON_SECURITY_ALIAS_OBJECT = 20000001; SAM_USER_OBJECT = 30000000; SAM_NORMAL_USER_ACCOUNT = 30000000; SAM_MACHINE_ACCOUNT = 30000001; SAM_TRUST_ACCOUNT = 30000002; SAM_APP_BASIC_GROUP = 40000000; SAM_APP_QUERY_GROUP = 40000001}

$objSearch = [adsisearcher]"";



function GroupObjectEnum{
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
        "SID: $($element.Properties.objectsid)";
        "Object category: $($element.Properties.objectcategory)";
        "sAMAccountName: $($element.Properties.samaccountname)";
        "ADSPath: $($element.Properties.adspath)";

        foreach($key in $GROUP_TYPE.Keys){ #NOTE- test le type de group
            if($element.Properties.grouptype -eq $GROUP_TYPE[$key]){
                "Type d'étendue du groupe: $($key)";
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
        "================================================================"
        " ";
    }
}


function Get-Group{
    <#
        .Description
        Get-Group Run a filtered search on searching all groups. 
    #>

    $objSearch.Filter = '(&(objectCategory=group))'; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result);

    "[*] $($result.Count) groupe au total[*]";
}

#================== GROUPE ETENDU =====================
function Get-DomainLocalGroup{
    <#
        .Description
        Get-DomainLocalGroup Run a filtered search on finding all groups in the local domain. 
    #>

    $objSearch.Filter = '(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483652))'; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result);

    "[*] $($result.Count) groupe du domaine [*]";
}

function Get-GlobalGroup{
    <#
        .Description
        Get-GlobalGroup Run a filtered search on finding all group of globals. 
    #>

    $objSearch.Filter = '(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483650))'; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result); 
    
    "[*] $($result.Count) groupe global[*]";
}

function Get-GroupUniversal{
    <#
        .Description
        Get-GroupUniversal Run a filtered search on finding all universal group. 
    #>
    
    $objSearch.Filter = "(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483656))"; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result); 

    "[*] $($result.Count) groupe universal[*]";
}



#================== GROUPE SECURITY =====================
function Get-GroupSecurity{
    <#
        .Description
        Get-GroupSecurity Run a filtered search on searching all security groups. 
    #>
    
    $objSearch.Filter = '(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483648))'; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result);

    "[*] $($result.Count) groupe de securitée[*]";
}


function Get-GroupSecurityGlobal{
    <#
        .Description
        ComputerObjectEnum  Run a filtered search on Universal Security Global Search. 
    #>
    
    $objSearch.Filter = '(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483650))'; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result);

    "[*] $($result.Count) groupe de securitée global[*]";
}

function Get-GroupSecurityLocal{
    <#
        .Description
        Get-GroupSecurityLocal Run a filtered search on Universal Security Local Search. 
    #>

    $objSearch.Filter = '(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483652))'; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result);

    "[*] $($result.Count) groupe de securitée local[*]";
}

function Get-GroupSecurityUniversal{
    <#
        .Description
        Get-GroupSecurityUniversal Run a filtered search on Universal Security Group Search. 
    #>
    
    $objSearch.Filter = '(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483656))'; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result);

    "[*] $($result.Count) groupe de securitée universelle[*]";
}

#================== GROUPE DISTRIBUTION =====================
function Get-GroupDistribution{
    <#
        .Description
        Get-GroupDistribution Run a filtered search on finding all distribution groups. 
    #>

    $objSearch.Filter = '(&(objectCategory=group)(!(groupType:1.2.840.113556.1.4.803:=2147483648)))'; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result);

    "[*] $($result.Count) groupe de distribution[*]";
}

function Get-GroupDistributionGlobal{
    <#
        .Description
        Get-GroupDistributionGlobal Run a filtered search on global distribution group search. 
    #>

    $objSearch.Filter = '(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2)(!(groupType:1.2.840.113556.1.4.803:=2147483648)))'; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result);

    "[*] $($result.Count) groupe de distribution globale[*]";
}

function Get-GroupDistributionLocal{
    <#
        .Description
        Get-GroupDistributionLocal Run a filtered search on local distribution group search. 
    #>

    $objSearch.Filter = '(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=4)(!(groupType:1.2.840.113556.1.4.803:=2147483648)))'; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result);

    "[*] $($result.Count) groupe de distribution local du domaine[*]";
}
function Get-GroupDistributionUniversal{
    <#
        .Description
        Get-GroupDistributionUniversal Run a filtered search on Universal Distribution Group Search. 
    #>

    $objSearch.Filter = '(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=8)(!(groupType:1.2.840.113556.1.4.803:=2147483648)))'; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result);

    "[*] $($result.Count) groupe de distribution universel[*]";
}

#================== GROUPE EMPTY =====================
function Get-EmptyGroups{
    <#
        .Description
        Get-EmptyGroups Execute a filter search on the search for empty groups. 
    #>
    
    $objSearch.Filter = '(&(objectClass=group)(!member=*))'; 
    $result = $objSearch.FindAll();

    GroupObjectEnum($result);

    "[*] $($result.Count) groupe vide [*]";
}