Clear-Host
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$WarningPreference = "SilentlyContinue"

$banner = @"
8""""8                        8""""8             8"""8                                                                    
8    " e   e eeee eeee e   e  8    8 eeeee eeeee 8   8  eeee eeeee e  eeeee eeeee eeeee  eeeee eeeee e  eeeee eeeee eeeee 
8e     8   8 8    8  8 8   8  8eeee8 8   8 8   8 8eee8e 8    8   8 8  8   "   8   8   8  8   8   8   8  8  88 8   8 8   " 
88     8eee8 8eee 8e   8eee8e 88   8 8eee8 8eee8 88   8 8eee 8e    8e 8eeee   8e  8eee8e 8eee8   8e  8e 8   8 8e  8 8eeee 
88   e 88  8 88   88   88   8 88   8 88    88    88   8 88   88 "8 88    88   88  88   8 88  8   88  88 8   8 88  8    88 
88eee8 88  8 88ee 88e8 88   8 88   8 88    88    88   8 88ee 88ee8 88 8ee88   88  88   8 88  8   88  88 8eee8 88  8 8ee88                   
"@

Write-Host $banner -ForegroundColor Cyan
Write-Host "[Azure AD - Audit et revocation des consentements OAuth]" -ForegroundColor DarkGray
Write-Host ""

# =========================
# Preparation environnement
# =========================
Write-Host "Preparation de l'environnement PowerShell..." -ForegroundColor Yellow

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Write-Host "Installation du fournisseur NuGet..."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Host "Installation du module Microsoft.Graph..."
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
}

Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Applications

# =========================
# Connexion
# =========================
Write-Host "Connexion a Microsoft Graph..." -ForegroundColor Yellow

try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Connect-MgGraph `
        -Scopes "DelegatedPermissionGrant.ReadWrite.All", "Application.Read.All", "User.Read.All" `
        -ContextScope Process `
        -UseDeviceAuthentication `
        -ErrorAction Stop

    $ctx = Get-MgContext
    Write-Host ""
    Write-Host "===== SESSION CONNECTEE =====" -ForegroundColor Cyan
    Write-Host "Compte  : $($ctx.Account)" -ForegroundColor Green
    Write-Host "Tenant  : $($ctx.TenantId)" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host ""
}
catch {
    Write-Host "Erreur : impossible de se connecter. Verifiez vos droits." -ForegroundColor Red
    Write-Host ""
    Write-Host "Appuyez sur ESPACE pour quitter"
    do { $key = [System.Console]::ReadKey($true) } until ($key.Key -eq "Spacebar")
    exit
}

# =========================
# Initialisation log
# =========================
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir    = Join-Path $scriptDir "..\logs"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}
$logFile = Join-Path $logDir "CheckAppRegistrations_$timestamp.log"

function Write-Log {
    param([string]$message)
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $message"
    Add-Content -Path $script:logFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
}

Write-Log "=== Nouvelle session CheckAppRegistrations ==="
Write-Log "Compte admin : $($env:USERNAME)"

# =========================
# Fonction : recuperer le nom d'une appli depuis son AppId
# =========================
function Get-NomApplication {
    param([string]$appId)

    try {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
        if ($sp) { return $sp.DisplayName }
    } catch {}
    return $appId
}

# =========================
# Boucle menu principal
# =========================
while ($true) {

    Write-Host ""
    Write-Host "Mode d'audit :" -ForegroundColor Yellow
    Write-Host "  [1] Consentements OAuth d'un utilisateur"
    Write-Host "  [2] Recherche d'une application par nom sur tout le tenant"
    Write-Host "  [Q] Quitter"
    Write-Host ""
    $mode = Read-Host "Votre choix"

    if ($mode -eq "Q" -or $mode -eq "q") {
        break
    }

    # =========================
    # MODE 1 : consentements d'un utilisateur
    # =========================
    elseif ($mode -eq "1") {

        $upn = Read-Host "Entrez l'adresse email de l'utilisateur"
        if ([string]::IsNullOrWhiteSpace($upn)) {
            Write-Host "Adresse non valide." -ForegroundColor Red
            continue
        }

        Write-Log "Mode : Audit utilisateur | Cible : $upn"
        Write-Host "Recherche des consentements pour $upn" -NoNewline

        try {
            $user = Get-MgUser -UserId $upn -ErrorAction Stop
        }
        catch {
            Write-Host ""
            Write-Host "Erreur : utilisateur introuvable." -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor DarkRed
            Write-Log "ERREUR : utilisateur introuvable - $upn - $($_.Exception.Message)"
            continue
        }

        try {
            $grants = Get-MgUserOauth2PermissionGrant -UserId $user.Id -ErrorAction Stop
        }
        catch {
            Write-Host ""
            Write-Host "Erreur lors de la recuperation des consentements." -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor DarkRed
            Write-Log "ERREUR : $($_.Exception.Message)"
            continue
        }

        Write-Host ""

        if (-not $grants -or $grants.Count -eq 0) {
            Write-Host "Aucun consentement OAuth trouve pour cet utilisateur." -ForegroundColor Yellow
            Write-Log "Aucun consentement trouve pour $upn"
            continue
        }

        Write-Host "Consentements trouves : $($grants.Count)" -ForegroundColor Cyan
        Write-Host ""

        $i = 1
        $listeGrants = @()
        foreach ($g in $grants) {
            $nomApp = Get-NomApplication -appId $g.ClientId
            $scopes = $g.Scope

            Write-Host "  [$i] Application : $nomApp" -ForegroundColor White
            Write-Host "      Permissions : $scopes"
            Write-Host ""

            Write-Log "Consentement $i : App=$nomApp | ClientId=$($g.ClientId) | Scopes=$scopes"
            $listeGrants += [PSCustomObject]@{ Id = $g.Id; App = $nomApp }
            $i++
        }

        Write-Host ""
        $revoquer = Read-Host "Voulez-vous revoquer un consentement ? (OUI pour continuer, toute autre valeur pour retour au menu)"
        if ($revoquer -ne "OUI") { continue }

        $numero = Read-Host "Entrez le numero du consentement a revoquer"
        $index  = 0
        if (-not [int]::TryParse($numero, [ref]$index) -or $index -lt 1 -or $index -gt $listeGrants.Count) {
            Write-Host "Numero invalide." -ForegroundColor Red
            continue
        }

        $cible = $listeGrants[$index - 1]

        Write-Host ""
        Write-Host "ATTENTION : Le consentement de '$($cible.App)' pour $upn va etre revoque." -ForegroundColor Red
        Write-Host "Cette action est IRREVERSIBLE." -ForegroundColor Red
        Write-Host ""
        $confirm = Read-Host "Confirmer la revocation ? (OUI pour confirmer, toute autre valeur pour annuler)"
        if ($confirm -ne "OUI") {
            Write-Host "Revocation annulee." -ForegroundColor Yellow
            Write-Log "Revocation annulee par l'operateur"
            continue
        }

        try {
            Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $cible.Id -ErrorAction Stop
            Write-Host "Consentement revoque avec succes." -ForegroundColor Green
            Write-Log "Succes : consentement de '$($cible.App)' revoque pour $upn"
        }
        catch {
            Write-Host "Erreur lors de la revocation." -ForegroundColor Red
            Write-Log "ERREUR revocation : $($_.Exception.Message)"
        }
    }

    # =========================
    # MODE 2 : recherche par nom d'application sur le tenant
    # =========================
    elseif ($mode -eq "2") {

        $nomRecherche = Read-Host "Entrez le nom (ou partie du nom) de l'application a rechercher"
        if ([string]::IsNullOrWhiteSpace($nomRecherche)) {
            Write-Host "Nom non valide." -ForegroundColor Red
            continue
        }

        Write-Log "Mode : Recherche par appli | Nom : $nomRecherche"
        Write-Host "Recherche des applications correspondantes" -NoNewline

        try {
            $apps = Get-MgServicePrincipal -Filter "startswith(displayName,'$nomRecherche')" -All -ErrorAction Stop
        }
        catch {
            Write-Host ""
            Write-Host "Erreur lors de la recherche d'applications." -ForegroundColor Red
            Write-Log "ERREUR : $($_.Exception.Message)"
            continue
        }

        Write-Host ""

        if (-not $apps -or $apps.Count -eq 0) {
            Write-Host "Aucune application trouvee avec ce nom." -ForegroundColor Yellow
            Write-Log "Aucune application trouvee pour '$nomRecherche'"
            continue
        }

        Write-Host "Applications trouvees : $($apps.Count)" -ForegroundColor Cyan
        $apps | ForEach-Object { Write-Host "  - $($_.DisplayName)  (AppId: $($_.AppId))" }
        Write-Host ""

        $appChoisie = $apps[0]
        if ($apps.Count -gt 1) {
            $choixApp = Read-Host "Plusieurs resultats trouves. Entrez l'AppId exact a analyser"
            $appChoisie = $apps | Where-Object { $_.AppId -eq $choixApp }
            if (-not $appChoisie) {
                Write-Host "AppId non trouve dans la liste." -ForegroundColor Red
                continue
            }
        }

        Write-Host "Recherche des utilisateurs ayant consenti a cette application" -NoNewline

        try {
            $grants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($appChoisie.Id)'" -All -ErrorAction Stop
        }
        catch {
            Write-Host ""
            Write-Host "Erreur lors de la recuperation des consentements." -ForegroundColor Red
            Write-Log "ERREUR : $($_.Exception.Message)"
            continue
        }

        Write-Host ""

        if (-not $grants -or $grants.Count -eq 0) {
            Write-Host "Aucun consentement trouve pour cette application." -ForegroundColor Yellow
            Write-Log "Aucun consentement trouve pour $($appChoisie.DisplayName)"
            continue
        }

        Write-Host "Utilisateurs ayant consenti : $($grants.Count)" -ForegroundColor Cyan
        Write-Host ""

        $i = 1
        $listeGrants = @()
        foreach ($g in $grants) {
            $userDisplay = "Tenant entier (consentement admin)"
            if ($g.PrincipalId) {
                try {
                    $u = Get-MgUser -UserId $g.PrincipalId -ErrorAction SilentlyContinue
                    if ($u) { $userDisplay = $u.UserPrincipalName }
                } catch {}
            }
            Write-Host "  [$i] Utilisateur : $userDisplay" -ForegroundColor White
            Write-Host "      Permissions : $($g.Scope)"
            Write-Host ""
            Write-Log "Consentement $i : User=$userDisplay | Scopes=$($g.Scope)"
            $listeGrants += [PSCustomObject]@{ Id = $g.Id; User = $userDisplay }
            $i++
        }

        Write-Host "Entrez les numeros des consentements a revoquer separes par des virgules (ex: 1,3)" -ForegroundColor DarkGray
        $choix = Read-Host "ou TOUT pour tous, NON pour retourner au menu, toute autre valeur pour quitter"

        if ($choix -eq "NON") { continue }
        if ([string]::IsNullOrWhiteSpace($choix)) { break }

        if ($choix -eq "TOUT") {
            $cibles = $listeGrants
        }
        else {
            try {
                $indices = $choix -split "," | ForEach-Object { [int]$_.Trim() - 1 }
                $cibles  = $indices | ForEach-Object { $listeGrants[$_] }
            }
            catch {
                Write-Host "Choix invalide." -ForegroundColor Red
                continue
            }
        }

        Write-Host ""
        Write-Host "ATTENTION : $($cibles.Count) consentement(s) vont etre revoques pour '$($appChoisie.DisplayName)'." -ForegroundColor Red
        Write-Host "Cette action est IRREVERSIBLE." -ForegroundColor Red
        Write-Host ""
        $confirm = Read-Host "Confirmer ? (OUI pour confirmer, toute autre valeur pour annuler)"
        if ($confirm -ne "OUI") {
            Write-Host "Revocation annulee." -ForegroundColor Yellow
            Write-Log "Revocation annulee par l'operateur"
            continue
        }

        Write-Log "Revocation confirmee par l'operateur pour $($appChoisie.DisplayName)"

        $succes = 0
        $echecs = 0

        foreach ($cible in $cibles) {
            try {
                Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $cible.Id -ErrorAction Stop
                Write-Host "  $($cible.User) - OK" -ForegroundColor Green
                Write-Log "Succes : consentement de '$($cible.User)' revoque"
                $succes++
            }
            catch {
                Write-Host "  $($cible.User) - ECHEC" -ForegroundColor Red
                Write-Log "ECHEC : $($cible.User) - $($_.Exception.Message)"
                $echecs++
            }
        }

        Write-Host ""
        Write-Host "Revocation terminee" -ForegroundColor Green
        Write-Host "  Succes : $succes" -ForegroundColor Green
        if ($echecs -gt 0) {
            Write-Host "  Echecs : $echecs" -ForegroundColor Red
        }
        Write-Log "Bilan - Succes : $succes | Echecs : $echecs"
    }

    else {
        Write-Host "Choix invalide." -ForegroundColor Red
    }
}

Write-Log "=== Fin de session ==="
Write-Host ""
Write-Host "Appuyez sur ESPACE pour quitter"

do {
    $key = [System.Console]::ReadKey($true)
} until ($key.Key -eq "Spacebar")

exit