Auteur : Théo Brasseur | https://github.com/TheoBrasseurSSI | https://linkedin.com/in/tbrasseur
---
Outil PowerShell d'audit et de révocation des consentements OAuth Microsoft 365. Il permet à un administrateur de visualiser quelles applications tierces ont obtenu un accès délégué via le consentement d'un utilisateur, ou de rechercher sur tout le tenant qui a consenti à une application précise — utile pour détecter une application malveillante laissée comme persistance après compromission, qui reste active même après une révocation de session ou un changement de MFA.
---
⚠ La révocation d'un consentement est immédiate et irréversible (l'utilisateur devra re-consentir s'il souhaite réutiliser l'application).
---
Prérequis
* Compte Microsoft 365 avec au moins l'un des rôles suivants :
* Global Administrator
* ou Cloud Application Administrator
* ⚠ Ne pas exécuter dans PowerShell ISE
---
Périmètre de l'outil
* **Mode 1** : consentements OAuth donnés par un utilisateur précis
* **Mode 2** : recherche d'une application par nom sur tout le tenant, puis liste des utilisateurs ayant consenti
* Pour chaque consentement trouvé, l'outil affiche les permissions accordées (scopes)
* Possibilité de révoquer un consentement précis (mode 1) ou plusieurs en une fois (mode 2, par numéro, virgules, ou TOUT)
---
Authentification
* Le script utilise le Device Code Flow (flux OAuth2 standard Microsoft).
* À chaque lancement, un code est affiché dans la console. Il faut :
* Ouvrir le lien affiché (https://microsoft.com/devicelogin)
* Saisir le code affiché
* Se connecter avec le compte admin souhaité
* Cette méthode permet de choisir librement le compte à chaque exécution, quel que soit le tenant ciblé.
* Aucune session n'est mise en cache — la connexion est isolée à la session PowerShell en cours.
* ⚠ Le compte utilisé doit avoir les droits suffisants pour lire et révoquer les consentements OAuth sur le tenant ciblé.
---
Saisie utilisateur
Lors de l'exécution, le script demande :
* Le mode d'audit (1, 2 ou Q pour quitter)
* En mode 1 : l'adresse email de l'utilisateur à auditer
* En mode 2 : le nom (ou partie du nom) de l'application à rechercher
* Pour toute révocation : confirmation explicite avant suppression
---
Lancement
* Créez un raccourci de Launcher.bat → clic-droit → Créer un raccourci.
* Le fichier .bat :
* applique une ExecutionPolicy Bypass (temporaire, pour la session uniquement)
* exécute ensuite le script CheckAppRegistrations.ps1
* ⚠ Le fichier Launcher.bat et le fichier CheckAppRegistrations.ps1 doivent rester dans le même dossier.
* Un fichier .ico est fourni pour l'icône de votre raccourci.
---
Exécution manuelle
Le script peut aussi être lancé directement depuis PowerShell :
powershell.exe -ep Bypass -File .\CheckAppRegistrations.ps1
Le bypass est temporaire et n'applique aucune modification permanente sur le poste.
---
Logs
* Un fichier de log est automatiquement généré à chaque exécution.
* Le dossier logs\ est créé automatiquement au premier lancement, aucune action manuelle nécessaire.
* Les logs sont stockés dans le dossier logs\ à la racine du projet.
* Chaque fichier est nommé avec le timestamp de la session : CheckAppRegistrations_2026-06-16_08-40.log
* Le log contient : compte admin utilisé, utilisateur ou application auditée, consentements trouvés, résultat de chaque révocation (succès/échec).
* ⚠ Le dossier logs\ est exclu du dépôt Git (.gitignore) — vos logs restent locaux.