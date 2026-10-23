<#
.SYNOPSIS
  One-time Azure setup for ONE consuming repository of CloudGuard publish/deploy.

.DESCRIPTION
  Creates (safe to re-run):
    - Container Apps environment and the container app (multiple-revision mode)
    - A user-assigned managed identity used ONLY by this repository to deploy
    - A federated credential that trusts exactly ONE repository + ONE GitHub environment
    - Role assignments: AcrPush on the registry, Contributor on the resource group
  Nothing here trusts an organization or "all repositories". Run it once per consuming
  repository (and once per environment). It uses a managed identity instead of an Entra
  app registration, so it works even if your tenant blocks students from registering apps.

  Prerequisites: resource group, registry and the pull identity (AcrPull) already exist.

.EXAMPLE
  .\azure-bootstrap.ps1 -GitHubOwner avniijain -GitHubRepo cloudguard-demo `
      -ResourceGroup rg-cloudguard-demo -AcrName myregistry -Location centralindia `
      -ContainerApp bookmarks-api -TargetPort 8000
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$GitHubOwner,
  [Parameter(Mandatory)][string]$GitHubRepo,
  [Parameter(Mandatory)][string]$ResourceGroup,
  [Parameter(Mandatory)][string]$AcrName,
  [Parameter(Mandatory)][string]$Location,
  [Parameter(Mandatory)][string]$ContainerApp,
  [string]$Environment = 'production',
  [string]$ContainerAppsEnv = 'cae-cloudguard',
  [string]$PullIdentity = 'id-cg-pull',
  [int]$TargetPort = 8000,
  [string]$PlaceholderImage = 'mcr.microsoft.com/k8se/quickstart:latest'
)

# Native-command failures are checked through $LASTEXITCODE, not exceptions.
$ErrorActionPreference = 'Continue'

function Invoke-AzCli {
  $out = & az @args
  if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed (exit $LASTEXITCODE)" }
  $out
}
function Test-AzCli {
  & az @args *> $null
  return ($LASTEXITCODE -eq 0)
}

$tenantId = Invoke-AzCli account show --query tenantId -o tsv
$subscriptionId = Invoke-AzCli account show --query id -o tsv

Write-Host "Registering providers and the containerapp extension..."
foreach ($ns in 'Microsoft.App', 'Microsoft.OperationalInsights', 'Microsoft.ContainerRegistry', 'Microsoft.ManagedIdentity') {
  Invoke-AzCli provider register --namespace $ns --wait | Out-Null
}
Invoke-AzCli extension add --name containerapp --upgrade --only-show-errors | Out-Null

if (-not (Test-AzCli group show -n $ResourceGroup)) { throw "Resource group $ResourceGroup not found." }
if (-not (Test-AzCli acr show -n $AcrName)) { throw "Registry $AcrName not found." }
if (-not (Test-AzCli identity show -n $PullIdentity -g $ResourceGroup)) { throw "Pull identity $PullIdentity not found." }

$loginServer = Invoke-AzCli acr show -n $AcrName --query loginServer -o tsv
$pullId = Invoke-AzCli identity show -n $PullIdentity -g $ResourceGroup --query id -o tsv

Write-Host "Container Apps environment..."
if (-not (Test-AzCli containerapp env show -n $ContainerAppsEnv -g $ResourceGroup)) {
  Invoke-AzCli containerapp env create -n $ContainerAppsEnv -g $ResourceGroup -l $Location | Out-Null
}

Write-Host "Container app..."
if (-not (Test-AzCli containerapp show -n $ContainerApp -g $ResourceGroup)) {
  Invoke-AzCli containerapp create -n $ContainerApp -g $ResourceGroup `
    --environment $ContainerAppsEnv --image $PlaceholderImage `
    --target-port $TargetPort --ingress external `
    --user-assigned $pullId --registry-server $loginServer --registry-identity $pullId `
    --min-replicas 0 --max-replicas 1 --cpu 0.25 --memory 0.5Gi | Out-Null
}
Invoke-AzCli containerapp revision set-mode -n $ContainerApp -g $ResourceGroup --mode multiple | Out-Null

Write-Host "Deployer identity for $GitHubOwner/$GitHubRepo ($Environment)..."
$safeRepo = $GitHubRepo -replace '[^A-Za-z0-9_-]', '-'
$deployName = "id-cg-deploy-$safeRepo"
if (-not (Test-AzCli identity show -n $deployName -g $ResourceGroup)) {
  Invoke-AzCli identity create -n $deployName -g $ResourceGroup -l $Location | Out-Null
}
$clientId = Invoke-AzCli identity show -n $deployName -g $ResourceGroup --query clientId -o tsv
$principalId = Invoke-AzCli identity show -n $deployName -g $ResourceGroup --query principalId -o tsv

# Exactly one repository and one environment. No wildcards.
$subject = "repo:${GitHubOwner}/${GitHubRepo}:environment:${Environment}"
$credName = "github-$Environment"
$credArgs = @('--name', $credName, '--identity-name', $deployName, '--resource-group', $ResourceGroup,
              '--issuer', 'https://token.actions.githubusercontent.com',
              '--subject', $subject, '--audiences', 'api://AzureADTokenExchange')
if (Test-AzCli identity federated-credential show --name $credName --identity-name $deployName --resource-group $ResourceGroup) {
  Invoke-AzCli identity federated-credential update @credArgs | Out-Null
} else {
  Invoke-AzCli identity federated-credential create @credArgs | Out-Null
}

Write-Host "Role assignments (scoped to this resource group and registry)..."
$rgId = Invoke-AzCli group show -n $ResourceGroup --query id -o tsv
$acrId = Invoke-AzCli acr show -n $AcrName --query id -o tsv
Invoke-AzCli role assignment create --assignee-object-id $principalId --assignee-principal-type ServicePrincipal --role Contributor --scope $rgId | Out-Null
Invoke-AzCli role assignment create --assignee-object-id $principalId --assignee-principal-type ServicePrincipal --role AcrPush --scope $acrId | Out-Null

Write-Host ""
Write-Host "Done. Trusted subject: $subject"
Write-Host "Set these as REPOSITORY variables (not secrets) in $GitHubOwner/${GitHubRepo}:"
Write-Host "  AZURE_CLIENT_ID       = $clientId"
Write-Host "  AZURE_TENANT_ID       = $tenantId"
Write-Host "  AZURE_SUBSCRIPTION_ID = $subscriptionId"
Write-Host "  ACR_LOGIN_SERVER      = $loginServer"
Write-Host "  AZURE_RESOURCE_GROUP  = $ResourceGroup"
Write-Host "  AZURE_CONTAINER_APP   = $ContainerApp"
Write-Host ""
Write-Host "Or with the GitHub CLI:"
Write-Host "  gh variable set AZURE_CLIENT_ID --body $clientId --repo $GitHubOwner/$GitHubRepo"
Write-Host ""
Write-Host "Then create the GitHub environment '$Environment' in that repo and restrict it to the deploy branch."
Write-Host "Role assignments can take a few minutes to propagate before the first deployment works."