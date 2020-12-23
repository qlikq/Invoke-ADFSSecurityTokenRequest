function Invoke-ADFSSecurityTokenRequest {
    param(
        [Parameter(Mandatory=$true)][ValidateSet('Windows','UserName','Certificate')] $ClientCredentialType,
        [Parameter(Mandatory=$true)] $ADFSBaseUri,
        [Parameter(Mandatory=$true)] $RelayPartyIdentifier,
        #Username requires UPN format
        [Parameter()] $Username,
        [Parameter()] $Password,
        [Parameter()] $Domain,
        [Parameter()] $CertThrumbprint,
        [Parameter()][ValidateSet('1','2')] $SAMLVersion = 1,
        [Parameter()][ValidateSet('Token','RSTR')] $OutputType = 'Token',
        [Parameter()][Switch] $IgnoreCertificateErrors
    )
    
    Add-Type -AssemblyName 'System.ServiceModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
    Add-Type -AssemblyName 'System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'

    $ADFSTrustPath = 'adfs/services/trust/13'
    $SecurityMode = 'TransportWithMessageCredential'
    
    switch ($ClientCredentialType) {
        'Windows' {
            $MessageCredential = 'Windows'
            $ADFSTrustEndpoint = 'windowsmixed'
            $ADFSBaseUri = $ADFSBaseUri.TrimEnd('/')
            $KeyType = [System.IdentityModel.Protocols.WSTrust.KeyTypes]::Bearer
        }
        'UserName' {
            $MessageCredential = 'UserName'
            $ADFSTrustEndpoint = 'usernamemixed'
            $SecurityMode = 'TransportWithMessageCredential'
            $ADFSBaseUri = $ADFSBaseUri.TrimEnd('/')
            $KeyType = [System.IdentityModel.Protocols.WSTrust.KeyTypes]::Bearer
        }
        'Certificate' {
            $MessageCredential = 'Certificate'
            $ADFSTrustEndpoint = 'certificatemixed'
            $SecurityMode = 'TransportWithMessageCredential'
            #Unsure if cert auth port 49443 is needed
            #$ADFSBaseUri = $ADFSBaseUri.TrimEnd('/')+':49443'
            $ADFSBaseUri = $ADFSBaseUri.TrimEnd('/')
            $KeyType = [System.IdentityModel.Protocols.WSTrust.KeyTypes]::Symmetric
            $Cert = Get-ChildItem Cert:\CurrentUser\My\$CertThrumbprint
        }
    
    }
    
    
    $EP = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList ('{0}/{1}/{2}' -f $ADFSBaseUri,$ADFSTrustPath,$ADFSTrustEndpoint)
    
    if ($ClientCredentialType -eq 'Certificate')
        {
        $Binding = New-Object -TypeName System.ServiceModel.WS2007HttpBinding -ArgumentList ([System.ServiceModel.SecurityMode] $SecurityMode)
        $Binding.Security.Message.EstablishSecurityContext = $true
        $Binding.Security.Message.ClientCredentialType = $MessageCredential
        $Binding.Security.Transport.ClientCredentialType = 'None'          

        $WSTrustChannelFactory = New-Object -TypeName System.ServiceModel.Security.WSTrustChannelFactory -ArgumentList $Binding, $EP
        $WSTrustChannelFactory.TrustVersion = [System.ServiceModel.Security.TrustVersion]::WSTrust13
        $WSTrustChannelFactory.Credentials.ClientCertificate.Certificate = $Cert
        $WSTrustChannelFactory.Credentials.SupportInteractive = $false
        $Channel = $WSTrustChannelFactory.CreateChannel()
        }
    else
        {
        $Credential = New-Object System.Net.NetworkCredential -ArgumentList $Username,$Password,$Domain
    
        $Binding = New-Object -TypeName System.ServiceModel.WS2007HttpBinding -ArgumentList ([System.ServiceModel.SecurityMode] $SecurityMode)
        $Binding.Security.Message.EstablishSecurityContext = $false
        $Binding.Security.Message.ClientCredentialType = $MessageCredential
        $Binding.Security.Transport.ClientCredentialType = 'None'          
    
        $WSTrustChannelFactory = New-Object -TypeName System.ServiceModel.Security.WSTrustChannelFactory -ArgumentList $Binding, $EP
        $WSTrustChannelFactory.TrustVersion = [System.ServiceModel.Security.TrustVersion]::WSTrust13
        $WSTrustChannelFactory.Credentials.Windows.ClientCredential = $Credential
        $WSTrustChannelFactory.Credentials.UserName.UserName = $Credential.UserName
        $WSTrustChannelFactory.Credentials.UserName.Password = $Credential.Password
        $Channel = $WSTrustChannelFactory.CreateChannel()    
        }
    
    
    $TokenType = @{
        SAML11 = 'urn:oasis:names:tc:SAML:1.0:assertion'
        SAML2 = 'urn:oasis:names:tc:SAML:2.0:assertion'
    }
    
    $RST = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.RequestSecurityToken -Property @{
        RequestType   = [System.IdentityModel.Protocols.WSTrust.RequestTypes]::Issue
        AppliesTo     = $RelayPartyIdentifier
        KeyType       = $KeyType
        TokenType     = if ($SAMLVersion -eq '1') {$TokenType.SAML11} else {$TokenType.SAML2}
    }
    $RSTR = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.RequestSecurityTokenResponse
    
    try {
        $OriginalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        if ($IgnoreCertificateErrors.IsPresent) {[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {return $true}}
        $Token = $Channel.Issue($RST, [ref] $RSTR)
    }
    finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $OriginalCallback
    }
    
    if ($OutputType -eq 'RSTR') {
        Write-Output -InputObject $RSTR
    } else {
        Write-Output -InputObject $Token
    }
    
    }