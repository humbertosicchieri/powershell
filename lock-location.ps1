# for get user Account Lockout Host name
$username = Read-Host "Entre com login do usuário: "
 
        $DCCounter = 0  
        $LockedOutStats = @()    
                 
        Try 
        { 
            Import-Module ActiveDirectory -ErrorAction Stop 
        } 
        Catch 
        { 
           Write-Warning $_ 
           Break 
        } 
         
        #Get all domain controllers in domain 
        $DomainControllers = Get-ADDomainController -Filter * 
        $PDCEmulator = ($DomainControllers | Where-Object {$_.OperationMasterRoles -contains "PDCEmulator"}) 
         
        Write-Verbose "Finding the domain controllers in the domain" 
        Foreach($DC in $DomainControllers) 
        { 
            # $DCCounter++ 
            # Write-Progress -Activity "Contacting DCs for lockout info" -Status "Querying $($DC.Hostname)" -PercentComplete (($DCCounter/$DomainControllers.Count) * 100) 
      Write-Verbose "Finding the Which domain controllers Authenticate the Password"
            Try 
            { 
                $UserInfo = Get-ADUser -Identity $username  -Server $DC.Hostname -Properties LastLogonDate -ErrorAction Stop 
      Write-Verbose "Bad Password Attempt count collected"
            } 
            Catch 
            { 
                # Write-Warning $_ 
                Continue 
            } 
            If($UserInfo.LastBadPasswordAttempt) 
            {     
                $LockedOutStats += New-Object -TypeName PSObject -Property @{ 
                        Name                   = $UserInfo.SamAccountName 
                        SID                    = $UserInfo.SID.Value 
                        LockedOut              = $UserInfo.LockedOut 
                        BadPwdCount            = $UserInfo.BadPwdCount 
                        BadPasswordTime        = $UserInfo.BadPasswordTime             
                        DomainController       = $DC.Hostname 
                        AccountLockoutTime     = $UserInfo.AccountLockoutTime 
                        LastLogonDate = ($UserInfo.LastLogonDate).ToLocalTime() 
                    }           
            }#end if 
        }#end foreach DCs 
        $LockedOutStats | Format-Table -Property Name,LockedOut,DomainController,BadPwdCount,AccountLockoutTime,LastBadPasswordAttempt -AutoSize 
 
        #Get User Info 
        Try 
        {   
           Write-Verbose "Querying event log on $($PDCEmulator.HostName)" 
     Write-Verbose "Collecting Event Log"
           $LockedOutEvents = Get-WinEvent -ComputerName $PDCEmulator.HostName -FilterHashtable @{LogName='Security';Id=4740} -ErrorAction Stop | Sort-Object -Property TimeCreated -Descending 
        } 
        Catch  
        {           
           Write-Warning $_ 
           Continue 
        }#end catch      
                                  
        Foreach($Event in $LockedOutEvents) 
        {             
           If($Event | Where {$_.Properties[2].value -match $UserInfo.SID.Value}) 
           {  
               
              $Event | Select-Object -Property @( 
                @{Label = 'User';               Expression = {$_.Properties[0].Value}} 
                @{Label = 'DomainController';   Expression = {$_.MachineName}} 
    @{Label = 'EventId';            Expression = {$_.Id}} 
                @{Label = 'LockedOutTimeStamp'; Expression = {$_.TimeCreated}} 
                @{Label = 'Message';            Expression = {$_.Message -split "`r" | Select -First 1}} 
                @{Label = 'LockedOutLocation';  Expression = {$_.Properties[1].Value}}
             ) 
      Write-host $_.MachineName
                                                 
            }#end ifevent 
             
       }#end foreach lockedout event
  Write-Verbose "Collected Details Update in the Text File. Please find the Text file for More Details"