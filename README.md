# VulnWatch : veille vulnérabilités pour GLPI 11 et 12

VulnWatch croise l'inventaire déjà remonté par GLPI Agent avec des sources de vulnérabilités (NVD, CISA KEV, flux RSS/Atom configurables) et suit les corrections au fil des inventaires. Il ne demande pas d'agent supplémentaire ni de scanner réseau, et fonctionne sans OpenVAS ni Wazuh.

Il répond à quatre questions, dans les fiches GLPI :

1. **Qui est concerné ?** Vues par CVE, par logiciel et par entité, plus un onglet *Vulnérabilités* sur les ordinateurs, téléphones, matériels réseau et imprimantes.
2. **Pourquoi ?** Chaque résultat affiche la source, le produit CPE retenu, la version relevée, la règle appliquée (bornes incluses ou exclues), la date d'inventaire, le niveau de confiance et la liste des raisons.
3. **Quoi traiter d'abord ?** La priorité combine gravité CVSS, exploitation connue (KEV), criticité et exposition de l'actif ; ses critères sont visibles. La confiance (fiabilité de la détection) est affichée séparément.
4. **La correction est-elle appliquée ?** Le statut *Corrigé* n'est posé que si un inventaire plus récent et non ancien montre que la condition n'est plus remplie (logiciel mis à jour ou retiré). Si la version vulnérable revient, une régression est signalée.

Le plugin **suit** les corrections, il n'installe rien.

## Statuts

| Statut | Signification |
|---|---|
| Correspondance établie | association logiciel → produit fiable ET version dans la plage affectée ET aucune condition invérifiable |
| À vérifier | produit probable (association proposée), condition de la source invérifiable (OS, configuration AND, mise à jour), critère sans borne, paquet de distribution Linux (rétroportage possible) |
| Non évalué | version absente ou non comparable, produit non reconnu, type d'actif ou source non couverts |
| Corrigé | nouvel inventaire récent : version hors plage (*mis à jour*) ou logiciel absent (*retiré*) |
| Correction non confirmée | la version a disparu, mais sans inventaire plus récent, ou avec un inventaire trop ancien |
| Clos | la source ne considère plus la version comme affectée, l'association a été rejetée, ou GLPI a recréé l'enregistrement logiciel avec la même version |

Un inventaire ancien, une machine qui ne remonte plus ou une source en erreur ne font **jamais** passer une alerte à *Corrigé*. Une absence de résultat est toujours affichée avec la couverture réelle (logiciels rapprochés, non reconnus, sans version, actifs à l'inventaire ancien).

## Installation

Prérequis : GLPI 11.0.x (PHP ≥ 8.2) ou GLPI 12.0.x (PHP ≥ 8.3, exigé par GLPI 12), extensions curl, dom, libxml et json, inventaire natif activé, actions automatiques GLPI en mode CLI recommandé.

```bash
cd /var/www/glpi/plugins
tar xjf glpi-vulnwatch-1.0.0.tar.bz2          # crée plugins/vulnwatch
php bin/console plugin:install vulnwatch -u <admin>
php bin/console plugin:activate vulnwatch
```

L'installation crée 13 tables `glpi_plugin_vulnwatch_*`, deux droits de profil et trois actions automatiques. La désinstallation supprime les tables, les droits et la configuration du plugin.

### Droits (Administration > Profils > onglet Vulnérabilités)

- `plugin_vulnwatch` : **Lire** (consulter), **Modifier** (valider ou rejeter les associations, traiter la veille, criticité/exposition d'un actif), **Créer** (tickets de campagne ; le droit natif de création de ticket est aussi exigé).
- `plugin_vulnwatch_config` : **Lire**, **Modifier** (flux, versions cibles, paramètres, automatisation). Ajouter un flux demande *Modifier*.

À l'installation, les profils qui ont le droit de modifier la configuration GLPI reçoivent tous les droits du plugin.

### Actions automatiques (Configuration > Actions automatiques)

| Action | Fréquence | Rôle |
|---|---|---|
| `vulnwatchCollect` | 1 h | flux, NVD, KEV : chaque connecteur est isolé, l'échec de l'un n'arrête pas les autres |
| `vulnwatchAnalyze` | 1 h | rapprochement local et suivi des corrections |
| `vulnwatchTickets` | 1 j | tickets automatiques, seulement dans les entités qui les ont activés |

Commande manuelle : `php bin/console plugins:vulnwatch:run --step=collect|analyze|tickets|all`.

## Compatibilité GLPI 11 / 12

Un seul paquet fonctionne sur les deux versions. Il a été testé sur GLPI 11.0.9 et 12.0.1 : installation, désinstallation, chargement de toutes les classes, suite d'intégration complète, pages en navigateur et action automatique lancée par le cron natif.

- **Propriétés typées.** GLPI 12 type les propriétés héritées (`$rightname`, `$dohistory`) et PHP exige la même déclaration dans les classes filles. Les classes de base `GlpiPlugin\Vulnwatch\Compat\*` sont donc chargées depuis `compat/glpi11/` ou `compat/glpi12/` selon `GLPI_VERSION` (voir `setup.php`).
- **Fonctions supprimées.** `Html::displayRightError()` est remplacé par `Glpi\Exception\Http\AccessDeniedHttpException`, disponible dans les deux versions.
- **CSRF.** GLPI 11 utilise un jeton ajouté par `Html::closeForm()`, GLPI 12 contrôle les en-têtes `Origin` et `Sec-Fetch-Site`. Le plugin n'a rien à faire : une requête intersite forgée est refusée (403) dans les deux cas.
- **Inventaire en GLPI 12.** GLPI 12 exige de choisir explicitement le mode d'authentification des agents (*Administration > Inventaire > Configuration > En-tête d'autorisation*). Sans ce réglage, l'inventaire est refusé et le plugin n'a rien à analyser.

Pour vérifier un autre correctif de GLPI : `php tests/load_classes.php /chemin/glpi` charge chaque classe du plugin sur le cœur indiqué.

## Configuration

**Outils > Vulnérabilités > Configuration**

- **NVD** : clé d'API facultative (augmente le débit autorisé). Deux modes :
  - *CVE citées* (par défaut) : seules les CVE citées par les flux ou ajoutées à la main sont demandées, une par une ;
  - *incrémental* : toutes les CVE modifiées depuis la dernière synchronisation.
  L'URL de l'API peut pointer vers un miroir interne.
- **CISA KEV** : met à jour les CVE déjà suivies. L'option « suivre toutes » importe tout le catalogue.
- **Inventaire ancien** : 30 jours par défaut.
- **Sécurité HTTP** : délai et taille maximum, ports autorisés, liste des sources internes autorisées, proxy.
- **Tickets automatiques** : désactivés par défaut, à activer entité par entité, avec un seuil de confiance (≥ 70) et un seuil de priorité.
- **Journal des décisions** : associations, veille, tickets, flux, cibles, contextes d'actifs.

### Flux RSS / Atom (Outils > Vulnérabilités > Flux de veille)

Chaque flux a : nom, URL, activation, fréquence (15 min à 7 jours), entité destinataire (récursive ou non), filtres facultatifs (mots à inclure ou exclure), bouton *Tester la récupération* (n'enregistre rien), bouton *Synchroniser maintenant*. Son état indique la dernière tentative, la dernière réussite et la dernière erreur.

Exemple CERT-FR : `https://www.cert.ssi.gouv.fr/avis/feed/`

Fonctionnement :
- les articles sont dédupliqués par flux et identifiant (y compris les doublons dans une même réponse) ;
- les CVE sont extraites du titre, du résumé, du HTML et des liens ;
- une même CVE peut être reliée à plusieurs bulletins, et chaque lien est conservé ;
- un article qui cite une CVE reste un **signal de veille**, pas une détection ;
- les articles sans CVE vont dans **Veille à vérifier**, où l'on peut lier une CVE à la main, marquer l'article traité ou l'écarter.

### Versions cibles et fin de support (Outils > Vulnérabilités > Versions cibles)

Pour un logiciel et une entité, on peut définir la version approuvée, la branche en fin de support et/ou la date de fin de support, ainsi que la source de la règle. La vue *Par logiciel* distingue « affectée par une CVE », « sous la version cible » et « fin de support ». La version cible approuvée est celle proposée dans les tickets ; ce n'est pas forcément la dernière version publiée.

### Associations (Outils > Vulnérabilités > Associations)

Les noms inventoriés sont normalisés (version, architecture, langue et suffixes juridiques retirés), puis rapprochés des produits CPE cités par les CVE suivies :

- **auto** : dictionnaire vérifié, ou nom ET éditeur concordants avec un seul candidat ;
- **proposée** : même nom mais éditeur différent, inclusion, ou plusieurs candidats. Les résultats correspondants restent *À vérifier*.

Valider ou rejeter une association est une décision tracée, réutilisée par toutes les analyses suivantes. On peut aussi saisir une association à la main.

## Tickets de campagne

Depuis l'onglet d'un actif, la fiche d'une CVE ou le tableau de bord, on coche des alertes puis on choisit **Créer ou compléter le ticket de campagne**.

- Il y a un ticket par **entité × produit × version cible**, pas un par machine.
- Les actifs sont liés au ticket (lien natif), avec les CVE, la version relevée, la version corrigée et la raison de l'alerte.
- Si un ticket ouvert existe déjà, le plugin ajoute un suivi qui ne liste que les nouveaux éléments. Les alertes déjà rattachées ne créent jamais de doublon, même après une nouvelle synchronisation.
- Un ticket résolu ou clos ouvre une nouvelle campagne au besoin.
- La correction est vérifiée au prochain inventaire de chaque actif.

## Données transmises à l'extérieur

Le rapprochement est **entièrement local** : aucun nom de logiciel, version, machine ou entité ne quitte GLPI.

| Connecteur | Requête sortante |
|---|---|
| Flux | `GET` de l'URL du flux (en-têtes If-None-Match / If-Modified-Since) |
| NVD, mode par défaut | `GET …/cves/2.0?cveId=CVE-AAAA-NNNN` + en-tête `apiKey` si configurée |
| NVD, mode incrémental | `GET …/cves/2.0?lastModStartDate=…&lastModEndDate=…&startIndex=…` |
| KEV | `GET` du catalogue JSON complet, sans paramètre |

## Sécurité

- Les droits et le périmètre d'entités GLPI sont appliqués aux listes, fiches, compteurs, onglets, tickets et flux (un flux non récursif de l'entité A est invisible depuis B). Les identifiants forgés sont revérifiés côté serveur.
- **SSRF** : seuls http et https sont acceptés, sur les ports autorisés, sans identifiants dans l'URL. Le plugin résout le DNS lui-même puis épingle l'IP (pas de *DNS rebinding*). Sont refusées les adresses privées, loopback, link-local, CGNAT, métadonnées cloud, IPv6 ULA et IPv4 mappées. Chaque redirection est revalidée (3 au maximum). Une source interne ne passe que si elle figure dans la liste d'autorisation.
- **XML** : tout DOCTYPE ou ENTITY est refusé (XXE, *billion laughs*) et `LIBXML_NONET` est actif. Taille et délai sont limités.
- **Affichage** : le contenu des flux est réduit au texte brut puis échappé, et les liens autres que `http(s)` sont supprimés. Les formulaires utilisent le jeton CSRF natif.
- Aucune modification du cœur de GLPI.

## Couverture actuelle (V1) et suite

**Évalué en V1** : logiciels inventoriés sur ordinateurs et téléphones, comparés à la NVD (CPE et plages de versions), enrichis par KEV et les flux, avec cibles et fin de support.

**Modélisé et affiché, mais « Non évalué »** :
- builds et correctifs Windows : GLPI n'a pas de champ « niveau de correctif » fiable, seulement version, édition et kernelversion ;
- BIOS et firmwares des postes et équipements réseau : la donnée dépend de l'agent ou de la collecte SNMP ;
- paquets Linux : détectés et mis *À vérifier* à cause des rétroportages.

**Phase 2** : connecteurs OSV et avis de distributions (dpkg et rpm sont déjà comparés par `VersionComparator`), builds Windows, firmwares réseau, enrichissement EPSS (le champ existe), import optionnel des constats OpenVAS et Wazuh avec leur provenance (l'interface de connecteur est prévue pour), ponts SecIncident et GLPI MCP sans dépendance.

## Tests

```bash
php tests/unit.php                                       # logique pure, sans GLPI
php tests/load_classes.php /chemin/glpi                  # compatibilité des classes avec ce cœur GLPI
php -S 127.0.0.2:8099 tests/fixture_router.php &         # serveur de jeux de test (NVD/KEV/flux)
php tests/integration.php /chemin/glpi http://127.0.0.1:8088   # instance de TEST uniquement
```

Résultats actuels : 77 tests unitaires et 70 tests d'intégration réussis sur GLPI 11.0.9 comme sur GLPI 12.0.1.

Le test d'intégration vide les tables du plugin et crée des entités et actifs « VW » : **ne jamais le lancer en production**.

## Licence

GPL-3.0-or-later.
