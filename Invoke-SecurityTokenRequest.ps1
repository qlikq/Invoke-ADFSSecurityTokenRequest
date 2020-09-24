function Invoke-ADFSSecurityTokenRequest {
    param(
        [Parameter()][ValidateSet('Windows','UserName','Certificate')] $ClientCredentialType,
        [Parameter()] $ADFSBaseUri,
        [Parameter()] $AppliesTo,
        [Parameter()] $Username,
        [Parameter()] $Password,
        [Parameter()] $Domain,
        [Parameter()] $CertThrumbprint,
        [Parameter()][ValidateSet('1','2')] $SAMLVersion = 1,
        [Parameter()][ValidateSet('Token','RSTR')] $OutputType = 'Token',
        [Parameter()][Switch] $IgnoreCertificateErrors
    )
    
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
            $ADFSBaseUri = $ADFSBaseUri.TrimEnd('/')
            $KeyType = [System.IdentityModel.Protocols.WSTrust.KeyTypes]::Bearer
        }
        'Certificate' {
            $MessageCredential = 'Certificate'
            $ADFSTrustEndpoint = 'certificatemixed'
            $ADFSBaseUri = $ADFSBaseUri.TrimEnd('/')
            $KeyType = [System.IdentityModel.Protocols.WSTrust.KeyTypes]::Symmetric
            $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2[]](Get-ChildItem "Cert:\CurrentUser\My\$CertThrumbprint")
        }
    
    }
    
    Add-Type -AssemblyName 'System.ServiceModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
    Add-Type -AssemblyName 'System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
    
    $EP = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList ('{0}/{1}/{2}' -f $ADFSBaseUri,$ADFSTrustPath,$ADFSTrustEndpoint)
    
    if ($ClientCredentialType -eq 'Certificate')
        {
        <#$CSharpCode = @"
    using System;
    using System.ServiceModel.Security;
    
    namespace Cert
    {
        public class X509CertificateInitiatorClientCredential
        {
        cc.ClientCredentials.ClientCertificate.SetCertificate(
        StoreLocation.CurrentUser,
        StoreName.TrustedPeople,
        X509FindType.FindByThumbprint,
        "$CertThrumbprint");
            }
        }
    }
    "@
    
    Add-Type -TypeDefinition $CSharpCode -Language CSharp
    
    # creating objects of the class
    # throws error because we didn't mention the namespace before class
    [Program]::Main() 
    
     $Key = New-Object -TypeName Cert.X509CertificateInitiatorClientCredential # alternatively
     #>
        #$Credential = Get-SmartCardCred
        $Binding = New-Object -TypeName System.ServiceModel.WS2007HttpBinding -ArgumentList ([System.ServiceModel.SecurityMode] $SecurityMode)
        $WSTrustChannelFactory = New-Object -TypeName System.ServiceModel.Security.WSTrustChannelFactory -ArgumentList $Binding, $EP
        $WSTrustChannelFactory.TrustVersion = [System.ServiceModel.Security.TrustVersion]::WSTrust13
        $WSTrustChannelFactory.Credentials.ClientCertificate.($Cert)
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
        AppliesTo     = $AppliesTo
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