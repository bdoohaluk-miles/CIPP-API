function Invoke-CIPPStandardAntiPhishPolicy {
    <#
    .FUNCTIONALITY
    Internal
    #>

    param($Tenant, $Settings)
    $PolicyName = 'Default Anti-Phishing Policy'

    $CurrentState = New-ExoRequest -tenantid $Tenant -cmdlet 'Get-AntiPhishPolicy' |
        Where-Object -Property Name -EQ $PolicyName |
        Select-Object Name, Enabled, EnableSpoofIntelligence, HonorDmarcPolicy, DmarcQuarantineAction, DmarcRejectAction, AuthenticationFailAction, SpoofQuarantineTag, EnableFirstContactSafetyTips, EnableUnauthenticatedSender, EnableViaTag, PhishThresholdLevel, EnableOrganizationDomainsProtection, EnableMailboxIntelligence, EnableMailboxIntelligenceProtection, TargetedUserProtectionAction, TargetedUserQuarantineTag, TargetedDomainProtectionAction, TargetedDomainQuarantineTag, MailboxIntelligenceProtectionAction, MailboxIntelligenceQuarantineTag, EnableSimilarUsersSafetyTips, EnableSimilarDomainsSafetyTips, EnableUnusualCharactersSafetyTips

    $StateIsCorrect = ($CurrentState.Name -eq $PolicyName) -and
                      ($CurrentState.Enabled -eq $true) -and              
                      ($CurrentState.EnableSpoofIntelligence -eq $Settings.EnableSpoofIntelligence) -and
                      ($CurrentState.HonorDmarcPolicy -eq $Settings.HonorDmarcPolicy) -and
                      ($CurrentState.DmarcQuarantineAction -eq $Settings.DmarcQuarantineAction) -and
                      ($CurrentState.DmarcRejectAction -eq $Settings.DmarcRejectAction) -and
                      ($CurrentState.AuthenticationFailAction -eq $Settings.AuthenticationFailAction) -and
                      ($CurrentState.SpoofQuarantineTag -eq $Settings.SpoofQuarantineTag) -and
                      ($CurrentState.EnableFirstContactSafetyTips -eq $Settings.EnableFirstContactSafetyTips) -and
                      ($CurrentState.EnableUnauthenticatedSender -eq $Settings.EnableUnauthenticatedSender) -and
                      ($CurrentState.EnableViaTag -eq $Settings.EnableViaTag) -and
                      ($CurrentState.PhishThresholdLevel -eq $Settings.PhishThresholdLevel) -and
                      ($CurrentState.EnableOrganizationDomainsProtection -eq $Settings.EnableOrganizationDomainsProtection) -and
                      ($CurrentState.EnableMailboxIntelligence -eq $Settings.EnableMailboxIntelligence) -and
                      ($CurrentState.EnableMailboxIntelligenceProtection -eq $Settings.EnableMailboxIntelligenceProtection) -and
                      ($CurrentState.TargetedUserProtectionAction -eq $Settings.TargetedUserProtectionAction) -and
                      ($CurrentState.TargetedUserQuarantineTag -eq $Settings.TargetedUserQuarantineTag) -and
                      ($CurrentState.TargetedDomainProtectionAction -eq $Settings.TargetedDomainProtectionAction) -and
                      ($CurrentState.TargetedDomainQuarantineTag -eq $Settings.TargetedDomainQuarantineTag) -and
                      ($CurrentState.MailboxIntelligenceProtectionAction -eq $Settings.MailboxIntelligenceProtectionAction) -and
                      ($CurrentState.MailboxIntelligenceQuarantineTag -eq $Settings.MailboxIntelligenceQuarantineTag) -and
                      ($CurrentState.EnableSimilarUsersSafetyTips -eq $Settings.EnableSimilarUsersSafetyTips) -and
                      ($CurrentState.EnableSimilarDomainsSafetyTips -eq $Settings.EnableSimilarDomainsSafetyTips) -and
                      ($CurrentState.EnableUnusualCharactersSafetyTips -eq $Settings.EnableUnusualCharactersSafetyTips)


    $AcceptedDomains = New-ExoRequest -tenantid $Tenant -cmdlet 'Get-AcceptedDomain'

    $RuleState = New-ExoRequest -tenantid $Tenant -cmdlet 'Get-AntiPhishRule' |
        Where-Object -Property Name -EQ "CIPP $PolicyName" |
        Select-Object Name, AntiPhishPolicy, Priority, RecipientDomainIs
    
    $RuleStateIsCorrect = ($RuleState.Name -eq "CIPP $PolicyName") -and
                          ($RuleState.AntiPhishPolicy -eq $PolicyName) -and
                          ($RuleState.Priority -eq 0) -and
                          (!(Compare-Object -ReferenceObject $RuleState.RecipientDomainIs -DifferenceObject $AcceptedDomains.Name))

    if ($Settings.remediate -eq $true) {
        if ($StateIsCorrect -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Anti-phishing Policy already correctly configured' -sev Info
        } else {
            $cmdparams = @{
                Enabled                             = $true
                EnableSpoofIntelligence             = $Settings.EnableSpoofIntelligence
                HonorDmarcPolicy                    = $Settings.HonorDmarcPolicy
                DmarcQuarantineAction               = $Settings.DmarcQuarantineAction
                DmarcRejectAction                   = $Settings.DmarcRejectAction
                AuthenticationFailAction            = $Settings.AuthenticationFailAction
                SpoofQuarantineTag                  = $Settings.SpoofQuarantineTag
                EnableFirstContactSafetyTips        = $Settings.EnableFirstContactSafetyTips
                EnableUnauthenticatedSender         = $Settings.EnableUnauthenticatedSender
                EnableViaTag                        = $Settings.EnableViaTag
                PhishThresholdLevel                 = $Settings.PhishThresholdLevel
                EnableOrganizationDomainsProtection = $Settings.EnableOrganizationDomainsProtection 
                EnableMailboxIntelligence           = $Settings.EnableMailboxIntelligence
                EnableMailboxIntelligenceProtection = $Settings.EnableMailboxIntelligenceProtection
                TargetedUserProtectionAction        = $Settings.TargetedUserProtectionAction
                TargetedUserQuarantineTag           = $Settings.TargetedUserQuarantineTag
                TargetedDomainProtectionAction      = $Settings.TargetedDomainProtectionAction
                TargetedDomainQuarantineTag         = $Settings.TargetedDomainQuarantineTag
                MailboxIntelligenceProtectionAction = $Settings.MailboxIntelligenceProtectionAction
                MailboxIntelligenceQuarantineTag    = $Settings.MailboxIntelligenceQuarantineTag
                EnableSimilarUsersSafetyTips        = $Settings.EnableSimilarUsersSafetyTips
                EnableSimilarDomainsSafetyTips      = $Settings.EnableSimilarDomainsSafetyTips
                EnableUnusualCharactersSafetyTips   = $Settings.EnableUnusualCharactersSafetyTips
            }

            try {
                if ($CurrentState.Name -eq $PolicyName) {
                    $cmdparams.Add('Identity', $PolicyName)
                    New-ExoRequest -tenantid $Tenant -cmdlet 'Set-AntiPhishPolicy' -cmdparams $cmdparams
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Updated Anti-phishing Policy' -sev Info
                } else {
                    $cmdparams.Add('Name', $PolicyName)
                    New-ExoRequest -tenantid $Tenant -cmdlet 'New-AntiPhishPolicy' -cmdparams $cmdparams
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Created Anti-phishing Policy' -sev Info
                }
            } catch {
                $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to create Anti-phishing Policy. Error: $ErrorMessage" -sev Error
            }
        }

        if ($RuleStateIsCorrect -eq $false) {
            $cmdparams = @{
                AntiPhishPolicy     = $PolicyName
                Priority            = 0
                RecipientDomainIs   = $AcceptedDomains.Name
            }

            try {
                if ($RuleState.Name -eq "CIPP $PolicyName") {
                    $cmdparams.Add('Identity', "CIPP $PolicyName")
                    New-ExoRequest -tenantid $Tenant -cmdlet 'Set-AntiPhishRule' -cmdparams $cmdparams
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Updated AntiPhish Rule' -sev Info
                } else {
                    $cmdparams.Add('Name', "CIPP $PolicyName")
                    New-ExoRequest -tenantid $Tenant -cmdlet 'New-AntiPhishRule' -cmdparams $cmdparams
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Created AntiPhish Rule' -sev Info
                }
            } catch {
                $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to create AntiPhish Rule. Error: $ErrorMessage" -sev Error
            }
        }
    }

    if ($Settings.alert -eq $true) {

        if ($StateIsCorrect -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Anti-phishing Policy is enabled' -sev Info
        } else {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Anti-phishing Policy is not enabled' -sev Alert
        }
    }

    if ($Settings.report -eq $true) {
        Add-CIPPBPAField -FieldName 'AntiPhishPolicy' -FieldValue $StateIsCorrect -StoreAs bool -Tenant $tenant
    }

}
