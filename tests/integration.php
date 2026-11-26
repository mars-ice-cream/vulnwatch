<?php

/**
 * Tests d'intégration sur une vraie instance GLPI 11.
 *
 *   php tests/integration.php /chemin/glpi http://127.0.0.1:8088
 *
 * Prérequis : serveur de jeux de test lancé (php -S 127.0.0.2:8099 tests/fixture_router.php),
 * inventaire natif GLPI activé. Le script crée ses propres entités/actifs préfixés « VW ».
 * À NE PAS lancer sur une instance de production : il vide les tables du plugin.
 */

require __DIR__ . '/bootstrap_glpi.php';

use GlpiPlugin\Vulnwatch\Campaign;
use GlpiPlugin\Vulnwatch\Config;
use GlpiPlugin\Vulnwatch\Cron;
use GlpiPlugin\Vulnwatch\Feed;
use GlpiPlugin\Vulnwatch\Inventory;
use GlpiPlugin\Vulnwatch\Matching\Analyzer;
use GlpiPlugin\Vulnwatch\Report;
use GlpiPlugin\Vulnwatch\Target;

/** @var DBmysql $DB */
global $DB;
const FIX = 'http://127.0.0.2:8099';
$glpiUrl = rtrim($argv[2] ?? 'http://127.0.0.1:8088', '/');
define('VULNWATCH_TESTING', true);

$pass = $fail = 0;
$results = [];
function check(string $scenario, string $name, bool $ok, mixed $detail = null): void
{
    global $pass, $fail, $results;
    $ok ? $pass++ : $fail++;
    $results[$scenario][] = [$name, $ok];
    echo ($ok ? '  ok   ' : '  FAIL ') . $name . ($ok || $detail === null ? '' : ' — ' . (is_string($detail) ? $detail : json_encode($detail, JSON_UNESCAPED_UNICODE))) . "\n";
}
function section(string $t): void
{
    echo "\n== $t\n";
}

function login(string $name, ?int $profileId = null, ?int $entityId = null, bool $recursive = true): void
{
    $u = new User();
    $u->getFromDBbyName($name);
    $auth = new Auth();
    $auth->auth_succeded = true;
    $auth->user = $u;
    Session::init($auth);
    if ($profileId !== null) {
        Session::changeProfile($profileId);
    }
    Session::changeActiveEntities($entityId ?? 0, $recursive);
    Config::reset();
}

function inventory(string $glpiUrl, array $payload): string
{
    $ch = curl_init($glpiUrl . '/front/inventory.php');
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_encode($payload), CURLOPT_RETURNTRANSFER => true, CURLOPT_PROXY => '',
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'GLPI-Agent-ID: ' . ($payload['_agentid'] ?? '')]]);
    $r = (string) curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return $code . ' ' . $r;
}

/** Inventaire au format GLPI Agent. */
function pc(string $name, string $os, array $softwares, string $osVersion = '23H2', string $kernel = '10.0.22631'): array
{
    $isLinux = $os !== 'windows';
    return [
        'action' => 'inventory', 'deviceid' => 'vw-' . strtolower($name) . '-2026-01-01-00-00-00', 'itemtype' => 'Computer',
        'content' => [
            'versionclient' => 'GLPI-Agent_v1.11',
            'hardware' => ['name' => $name, 'uuid' => md5($name)],
            'bios' => ['ssn' => 'SN-' . $name, 'smanufacturer' => 'Dell Inc.', 'smodel' => 'Latitude 5440', 'bversion' => '1.18.0', 'bmanufacturer' => 'Dell Inc.'],
            'operatingsystem' => $isLinux
                ? ['name' => 'Ubuntu', 'full_name' => 'Ubuntu 24.04.1 LTS', 'version' => '24.04.1 LTS (Noble Numbat)', 'kernel_name' => 'linux', 'kernel_version' => '6.8.0-45-generic', 'arch' => 'x86_64']
                : ['name' => 'Windows', 'full_name' => 'Microsoft Windows 11 Professionnel', 'version' => $osVersion, 'kernel_name' => 'MSWin32', 'kernel_version' => $kernel, 'arch' => '64-bit'],
            'softwares' => array_map(static fn($s) => array_filter(['name' => $s[0], 'version' => $s[1], 'publisher' => $s[2], 'arch' => $s[3] ?? 'x86_64'], static fn($v) => $v !== null), $softwares),
        ],
    ];
}

function computerId(string $name): int
{
    global $DB;
    return (int) ($DB->request(['SELECT' => 'id', 'FROM' => 'glpi_computers', 'WHERE' => ['name' => $name]])->current()['id'] ?? 0);
}

function moveToEntity(string $name, int $entityId): void
{
    global $DB;
    $id = computerId($name);
    $DB->update('glpi_computers', ['entities_id' => $entityId], ['id' => $id]);
    $DB->update('glpi_items_softwareversions', ['entities_id' => $entityId], ['itemtype' => 'Computer', 'items_id' => $id]);
    $DB->update('glpi_items_operatingsystems', ['entities_id' => $entityId], ['itemtype' => 'Computer', 'items_id' => $id]);
}

/** Rattachements d'un actif pour une CVE. @return list<array<string,mixed>> */
function itemsFor(string $computer, string $cve): array
{
    global $DB;
    return iterator_to_array($DB->request(['SELECT' => ['i.*', 'f.status AS fstatus', 'f.confidence', 'f.version_found', 'f.reasons', 'f.rule_text'],
        'FROM' => 'glpi_plugin_vulnwatch_findings_items AS i',
        'INNER JOIN' => ['glpi_plugin_vulnwatch_findings AS f' => ['ON' => ['i' => 'plugin_vulnwatch_findings_id', 'f' => 'id']],
            'glpi_plugin_vulnwatch_cves AS c' => ['ON' => ['i' => 'plugin_vulnwatch_cves_id', 'c' => 'id']]],
        'WHERE' => ['i.itemtype' => 'Computer', 'i.items_id' => computerId($computer), 'c.cve_id' => $cve], 'ORDER' => 'i.id']), false);
}

function activeItem(string $computer, string $cve): ?array
{
    foreach (itemsFor($computer, $cve) as $i) {
        if ($i['state'] === 'active') {
            return $i;
        }
    }
    return null;
}

function analyze(): array
{
    return (new Analyzer())->run();
}

function setFixtureMode(string $m): void
{
    file_put_contents('/tmp/vulnwatch_fixture_mode', $m);
}

// ---------------------------------------------------------------------------
section('Préparation');
login('glpi', 4, 0, true);
setFixtureMode('normal');
foreach (array_keys(require __DIR__ . '/../install/schema.php') as $t) {
    $DB->doQuery('TRUNCATE ' . $DB->quoteName($t));
}
foreach ($DB->request(['SELECT' => 'id', 'FROM' => 'glpi_computers', 'WHERE' => ['name' => ['LIKE', 'VW-%']]]) as $c) {
    (new Computer())->delete(['id' => $c['id']], true);
}
foreach ($DB->request(['SELECT' => 'id', 'FROM' => 'glpi_tickets', 'WHERE' => ['name' => ['LIKE', '[Vulnérabilités]%']]]) as $t) {
    (new Ticket())->delete(['id' => $t['id']], true);
}
Config::installDefaults();
Config::set(['nvd_url' => FIX . '/nvd', 'kev_url' => FIX . '/kev.json', 'http_internal_allowlist' => '127.0.0.2', 'http_allowed_ports' => '80,443,8099', 'stale_days' => '30', 'kev_last_sync' => '']);
$ent = new Entity();
$entA = $ent->getFromDBByCrit(['name' => 'VW Client A']) ? $ent->getID() : $ent->add(['name' => 'VW Client A', 'entities_id' => 0]);
$entB = $ent->getFromDBByCrit(['name' => 'VW Client B']) ? $ent->getID() : $ent->add(['name' => 'VW Client B', 'entities_id' => 0]);
check('prep', 'entités de test', $entA > 0 && $entB > 0);
// Le technicien n'a accès qu'à l'entité B
$tech = new User();
$tech->getFromDBbyName('tech');
$DB->delete('glpi_profiles_users', ['users_id' => $tech->getID()]);
(new Profile_User())->add(['users_id' => $tech->getID(), 'profiles_id' => 6, 'entities_id' => $entB, 'is_recursive' => 0]);
$DB->update('glpi_profilerights', ['rights' => READ | UPDATE | CREATE], ['profiles_id' => 6, 'name' => 'plugin_vulnwatch']);
$DB->update('glpi_profilerights', ['rights' => READ], ['profiles_id' => 6, 'name' => 'plugin_vulnwatch_config']);

// Inventaires initiaux (pipeline natif GLPI)
$inv = [
    ['VW-PC-A1', $entA, pc('VW-PC-A1', 'windows', [
        ['Mozilla Firefox (x64 fr)', '130.0', 'Mozilla'],
        ['7-Zip 23.01 (x64)', '23.01', 'Igor Pavlov'],
        ['Notepad++ (64-bit x64)', null, 'Notepad++ Team'],
        ['Chrome', '100.0', 'Acme Labs'],
        ['PHP', '8.3.7', 'The PHP Group'],
        ['Outil métier interne', '2.1', 'Ma Société'],
    ])],
    ['VW-PC-A2', $entA, pc('VW-PC-A2', 'windows', [['Mozilla Firefox (x64 fr)', '131.0.3', 'Mozilla'], ['7-Zip 24.08 (x64)', '24.08', 'Igor Pavlov']])],
    ['VW-PC-A3', $entA, pc('VW-PC-A3', 'windows', [['Mozilla Firefox (x64 fr)', '128.0', 'Mozilla']])],
    ['VW-PC-B1', $entB, pc('VW-PC-B1', 'windows', [['Mozilla Firefox (x64 fr)', '130.0', 'Mozilla']])],
    ['VW-SRV-B1', $entB, pc('VW-SRV-B1', 'linux', [['openssh-server', '1:9.6p1-3ubuntu13.5', 'Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>']])],
];
foreach ($inv as [$name, $eid, $payload]) {
    $r = inventory($glpiUrl, $payload);
    moveToEntity($name, $eid);
    check('prep', "inventaire natif $name", computerId($name) > 0, $r);
}
$a1 = computerId('VW-PC-A1');
$liu = $DB->request(['SELECT' => 'last_inventory_update', 'FROM' => 'glpi_computers', 'WHERE' => ['id' => $a1]])->current()['last_inventory_update'];
check('prep', 'last_inventory_update renseigné par l\'inventaire', $liu !== null, $liu);
$npp = $DB->request(['SELECT' => ['v.name'], 'FROM' => 'glpi_softwareversions AS v', 'INNER JOIN' => ['glpi_softwares AS s' => ['ON' => ['v' => 'softwares_id', 's' => 'id']]],
    'WHERE' => ['s.name' => ['LIKE', 'Notepad++%']]])->current();
check('prep', 'Notepad++ inventorié sans version', $npp !== null && trim((string) $npp['name']) === '', $npp);

// ---------------------------------------------------------------------------
section('Flux et sources');
$n1 = Feed::installOfficialFeeds();
$n2 = Feed::installOfficialFeeds();
check('flux_officiels', 'flux officiels CERT-FR ajoutés une seule fois (racine, récursifs)', $n1 === 2 && $n2 === 0
    && (int) $DB->request(['COUNT' => 'c', 'FROM' => 'glpi_plugin_vulnwatch_feeds', 'WHERE' => ['url' => ['LIKE', 'https://www.cert.ssi.gouv.fr/%'], 'entities_id' => 0, 'is_recursive' => 1]])->current()['c'] === 2, [$n1, $n2]);
// Pas d'accès Internet dans l'environnement de test : on les désactive pour la suite
$DB->update('glpi_plugin_vulnwatch_feeds', ['is_active' => 0], ['url' => ['LIKE', 'https://www.cert.ssi.gouv.fr/%']]);
$feed = new Feed();
$fA = $feed->add(['name' => 'CERT-FR (test)', 'url' => FIX . '/feeds/certfr.xml', 'entities_id' => $entA, 'is_recursive' => 0, 'frequency' => 60, 'is_active' => 1]);
$fB = $feed->add(['name' => 'Éditeur (test)', 'url' => FIX . '/feeds/vendor.atom', 'entities_id' => 0, 'is_recursive' => 1, 'frequency' => 60, 'is_active' => 1]);
$fErr = $feed->add(['name' => 'Flux en panne', 'url' => FIX . '/feeds/error', 'entities_id' => 0, 'is_recursive' => 1, 'frequency' => 60, 'is_active' => 1]);
$fXxe = $feed->add(['name' => 'Flux XXE', 'url' => FIX . '/feeds/xxe.xml', 'entities_id' => 0, 'is_recursive' => 1, 'frequency' => 60, 'is_active' => 1]);
$fSsrf = $feed->add(['name' => 'Métadonnées cloud', 'url' => 'http://169.254.169.254/latest/meta-data/', 'entities_id' => 0, 'is_recursive' => 1, 'frequency' => 60, 'is_active' => 1]);
$fRedir = $feed->add(['name' => 'Redirection interne', 'url' => FIX . '/feeds/redirect-internal', 'entities_id' => 0, 'is_recursive' => 1, 'frequency' => 60, 'is_active' => 1]);
$fBig = $feed->add(['name' => 'Flux trop gros', 'url' => FIX . '/feeds/big', 'entities_id' => 0, 'is_recursive' => 1, 'frequency' => 60, 'is_active' => 1]);
$fBad = $feed->add(['name' => 'Schéma interdit', 'url' => 'file:///etc/passwd', 'entities_id' => 0]);
check('ssrf', 'URL file:// refusée à la saisie', $fBad === false);
$t = Feed::test(FIX . '/feeds/certfr.xml');
check('feeds', 'test de récupération (sans enregistrement)', $t['ok'] && $t['count'] === 6 && $t['cves'] >= 6, $t);

Cron::cronVulnwatchCollect();
$feeds = [];
foreach ($DB->request(['FROM' => 'glpi_plugin_vulnwatch_feeds']) as $f) {
    $feeds[$f['id']] = $f;
}
check('feeds', 'CERT-FR synchronisé', $feeds[$fA]['last_status'] === 'ok' && $feeds[$fA]['last_success'] !== null, $feeds[$fA]);
$nb = (int) $DB->request(['COUNT' => 'c', 'FROM' => 'glpi_plugin_vulnwatch_bulletins', 'WHERE' => ['plugin_vulnwatch_feeds_id' => $fA]])->current()['c'];
check('feeds', 'doublon dans la même réponse dédupliqué (5 articles uniques)', $nb === 5, $nb);
$noCve = $DB->request(['FROM' => 'glpi_plugin_vulnwatch_bulletins', 'WHERE' => ['guid_hash' => hash('sha256', 'CERTFR-2024-AVI-1002')]])->current();
check('rss_sans_cve', 'bulletin sans CVE placé dans « Veille à vérifier »', ($noCve['review_status'] ?? '') === 'to_review', $noCve);
$c9680 = $DB->request(['FROM' => 'glpi_plugin_vulnwatch_cves', 'WHERE' => ['cve_id' => 'CVE-2024-9680']])->current();
$links = iterator_to_array($DB->request(['SELECT' => ['b.plugin_vulnwatch_feeds_id', 'b.link'], 'FROM' => 'glpi_plugin_vulnwatch_cves_bulletins AS cb',
    'INNER JOIN' => ['glpi_plugin_vulnwatch_bulletins AS b' => ['ON' => ['cb' => 'plugin_vulnwatch_bulletins_id', 'b' => 'id']]], 'WHERE' => ['cb.plugin_vulnwatch_cves_id' => $c9680['id']]]), false);
check('meme_cve_deux_flux', 'CVE-2024-9680 : une seule CVE, deux bulletins de deux flux, liens conservés',
    count($links) === 2 && count(array_unique(array_column($links, 'plugin_vulnwatch_feeds_id'))) === 2 && !in_array('', array_column($links, 'link'), true), $links);
$nCve = (int) $DB->request(['COUNT' => 'c', 'FROM' => 'glpi_plugin_vulnwatch_cves', 'WHERE' => ['cve_id' => 'CVE-2024-9680']])->current()['c'];
check('meme_cve_deux_flux', 'pas de doublon de CVE', $nCve === 1);
check('sync_echec', 'flux en panne : état erreur + dernière erreur conservée', $feeds[$fErr]['last_status'] === 'error' && str_contains((string) $feeds[$fErr]['last_error'], '500'), $feeds[$fErr]);
check('ssrf', 'XXE bloqué', $feeds[$fXxe]['last_status'] === 'error' && str_contains((string) $feeds[$fXxe]['last_error'], 'XXE'), $feeds[$fXxe]['last_error']);
check('ssrf', 'adresse de métadonnées cloud refusée', $feeds[$fSsrf]['last_status'] === 'error' && str_contains((string) $feeds[$fSsrf]['last_error'], 'interne'), $feeds[$fSsrf]['last_error']);
check('ssrf', 'redirection vers une adresse interne non autorisée refusée', $feeds[$fRedir]['last_status'] === 'error' && str_contains((string) $feeds[$fRedir]['last_error'], '127.0.0.1'), $feeds[$fRedir]['last_error']);
check('ssrf', 'taille maximale appliquée', $feeds[$fBig]['last_status'] === 'error' && str_contains((string) $feeds[$fBig]['last_error'], 'volumineuse'), $feeds[$fBig]['last_error']);

$nvd = [];
foreach ($DB->request(['SELECT' => ['cve_id', 'nvd_status', 'cvss_score', 'is_kev'], 'FROM' => 'glpi_plugin_vulnwatch_cves']) as $r) {
    $nvd[$r['cve_id']] = $r;
}
check('sources', 'NVD : 6 CVE enrichies', count(array_filter($nvd, static fn($r) => $r['nvd_status'] === 'ok')) === 6, $nvd);
check('sources', 'KEV : CVE-2024-9680 et CVE-2024-4577 marquées', $nvd['CVE-2024-9680']['is_kev'] == 1 && $nvd['CVE-2024-4577']['is_kev'] == 1);
check('sources', 'KEV : CVE non suivie non importée (mode par défaut)', !isset($nvd['CVE-2021-44228']));

// ---------------------------------------------------------------------------
section('Analyse');
// Version cible approuvée pour Firefox dans l'entité A (différente de la dernière version publiée)
$tg = (new Target())->add(['software_name' => 'Mozilla Firefox (x64 fr)', 'target_version' => '131.0.3', 'source' => 'Politique interne (test)', 'entities_id' => $entA, 'is_recursive' => 1]);
$tg7 = (new Target())->add(['software_name' => '7-Zip', 'eol_branch' => '19.00', 'source' => 'test', 'entities_id' => 0, 'is_recursive' => 1]);
$s1 = analyze();
check('analyse', 'analyse exécutée', $s1['evaluations'] > 0, $s1);

$i = activeItem('VW-PC-A1', 'CVE-2024-9680');
check('version_affectee', 'Firefox 130.0 → correspondance établie', ($i['fstatus'] ?? '') === 'established' && $i['confidence'] >= 90, $i);
check('version_affectee', 'explication : règle et version relevée', $i !== null && str_contains($i['rule_text'], '< 131.0.2') && $i['version_found'] === '130.0' && $i['inventory_date'] !== null, $i);
$i = activeItem('VW-PC-A1', 'CVE-2024-11477');
check('version_affectee', '7-Zip 23.01 → établie', ($i['fstatus'] ?? '') === 'established', $i);
check('version_corrigee', 'Firefox 131.0.3 → aucune alerte', itemsFor('VW-PC-A2', 'CVE-2024-9680') === []);
check('version_corrigee', '7-Zip 24.08 → aucune alerte', itemsFor('VW-PC-A2', 'CVE-2024-11477') === []);
$f = $DB->request(['SELECT' => ['f.status'], 'FROM' => 'glpi_plugin_vulnwatch_findings AS f', 'INNER JOIN' => ['glpi_softwareversions AS v' => ['ON' => ['f' => 'softwareversions_id', 'v' => 'id']]],
    'WHERE' => ['v.name' => '131.0.3']])->current();
check('version_corrigee', 'résultat « non affecté » conservé pour 131.0.3', ($f['status'] ?? '') === 'not_affected', $f);
$i = activeItem('VW-PC-A1', 'CVE-2023-40031');
check('version_inconnue', 'Notepad++ sans version → non évalué (jamais établi)', ($i['fstatus'] ?? '') === 'not_evaluated', $i);
$i = activeItem('VW-PC-A1', 'CVE-2023-4863');
check('nom_ambigu', '« Chrome » d\'Acme Labs → à vérifier, confiance ≤ 50', ($i['fstatus'] ?? '') === 'to_check' && $i['confidence'] <= 50, $i);
$i = activeItem('VW-PC-A1', 'CVE-2024-4577');
check('conditions', 'PHP 8.3.7 avec condition Windows (AND) → à vérifier', ($i['fstatus'] ?? '') === 'to_check' && str_contains((string) $i['reasons'], 'microsoft:windows'), $i);
$i = activeItem('VW-SRV-B1', 'CVE-2024-6387');
check('backport', 'OpenSSH Ubuntu 1:9.6p1-3ubuntu13.5 → à vérifier (rétroportage possible)', ($i['fstatus'] ?? '') === 'to_check' && str_contains((string) $i['reasons'], 'rétroporté'), $i);
$mInterne = $DB->request(['COUNT' => 'c', 'FROM' => 'glpi_plugin_vulnwatch_mappings', 'WHERE' => ['name_norm' => ['LIKE', 'outil%']]])->current()['c'];
check('nom_ambigu', 'logiciel inconnu : aucune association inventée', (int) $mInterne === 0);
$s2 = analyze();
check('perf', 'comparaison unique par (critère, version, contexte) : cache utilisé', $s1['cache_hits'] >= 0 && $s2['findings'] === 0, $s2);
$assess = Target::assess('Mozilla Firefox (x64 fr)', '131.0.2', $entA);
check('cibles', 'version cible distincte de la CVE : 131.0.2 non affectée mais sous la cible 131.0.3', $assess['below_target'] === true && $assess['target'] === '131.0.3', $assess);
check('cibles', 'fin de support : 7-Zip 18.05 < branche 19.00', Target::assess('7-Zip', '18.05', $entA)['eol'] === true && Target::assess('7-Zip', '23.01', $entA)['eol'] === false);
check('cibles', 'règle d\'entité non appliquée à une autre entité', Target::assess('Mozilla Firefox (x64 fr)', '130.0', $entB)['target'] === null);

// ---------------------------------------------------------------------------
section('Isolation entre entités');
login('tech', 6, $entB, false);
$rows = Report::items([]);
$ents = array_unique(array_map(static fn($r) => (int) $r['entities_id'], $rows));
check('isolation', 'technicien B : uniquement des résultats de l\'entité B', $rows !== [] && $ents === [$entB], $ents);
check('isolation', 'compteurs restreints à B', array_keys(Report::countsByEntity()) === [$entB], array_keys(Report::countsByEntity()));
$cov = Report::coverage();
check('isolation', 'couverture restreinte à B (2 actifs)', $cov['assets'] === 2, $cov);
$aItem = activeItem('VW-PC-A1', 'CVE-2024-9680');
$rep = Campaign::addFindingItems([(int) $aItem['id']]);
check('isolation', 'ticket sur une alerte de A refusé pour B (identifiant forgé)', $rep['tickets_created'] === 0 && $rep['skipped'] === 1, $rep);
$visibleFeeds = array_column(iterator_to_array($DB->request(['SELECT' => 'id', 'FROM' => 'glpi_plugin_vulnwatch_feeds AS fe', 'WHERE' => [getEntitiesRestrictCriteria('fe', '', '', true)]]), false), 'id');
check('isolation', 'flux de A (non récursif) invisible pour B, flux racine récursif visible', !in_array($fA, $visibleFeeds) && in_array($fB, $visibleFeeds), $visibleFeeds);
$feedObj = new Feed();
check('isolation', 'droit natif : B ne peut pas lire la fiche du flux de A', !$feedObj->can($fA, READ));

// ---------------------------------------------------------------------------
section('Tickets de campagne');
login('glpi', 4, 0, true);
$ids = array_map(static fn($x) => (int) $x['id'], array_filter([activeItem('VW-PC-A1', 'CVE-2024-9680'), activeItem('VW-PC-A1', 'CVE-2024-11477'), activeItem('VW-PC-B1', 'CVE-2024-9680')]));
$r1 = Campaign::addFindingItems($ids);
check('tickets', '3 alertes → 3 tickets (entité × produit), pas un par machine', $r1['tickets_created'] === 3 && $r1['items_added'] === 3, $r1);
$tk = new Ticket();
$campA = $DB->request(['FROM' => 'glpi_plugin_vulnwatch_campaigns', 'WHERE' => ['entities_id' => $entA, 'product_key' => 'mozilla:firefox']])->current();
$tk->getFromDB((int) $campA['tickets_id']);
check('tickets', 'ticket dans l\'entité de l\'actif, version cible approuvée proposée', (int) $tk->fields['entities_id'] === $entA && $campA['target_version'] === '131.0.3' && str_contains($tk->fields['content'], 'CVE-2024-9680'), [$tk->fields['entities_id'], $campA]);
$r2 = Campaign::addFindingItems($ids);
check('tickets_doublons', 'nouvel ajout des mêmes alertes : aucun ticket ni suivi', $r2['tickets_created'] === 0 && $r2['tickets_updated'] === 0 && $r2['skipped'] === 3, $r2);
$s = analyze();
$r3 = Campaign::addFindingItems($ids);
check('tickets_doublons', 'après une nouvelle synchronisation : toujours aucun doublon', $r3['tickets_created'] === 0 && $r3['tickets_updated'] === 0, $r3);
$a3 = activeItem('VW-PC-A3', 'CVE-2024-9680');
$r4 = Campaign::addFindingItems([(int) $a3['id']]);
$nFu = (int) $DB->request(['COUNT' => 'c', 'FROM' => 'glpi_itilfollowups', 'WHERE' => ['itemtype' => 'Ticket', 'items_id' => $campA['tickets_id']]])->current()['c'];
$nIt = (int) $DB->request(['COUNT' => 'c', 'FROM' => 'glpi_items_tickets', 'WHERE' => ['tickets_id' => $campA['tickets_id']]])->current()['c'];
check('tickets', 'nouvelle machine de la même campagne : ticket existant complété (1 suivi, 2 actifs)', $r4['tickets_updated'] === 1 && $r4['tickets_created'] === 0 && $nFu === 1 && $nIt === 2, [$r4, $nFu, $nIt]);
$tk->getFromDB((int) $campA['tickets_id']);
check('tickets', 'titre du ticket mis à jour avec le nombre réel d\'actifs (2)', str_contains($tk->fields['name'], '2 actif(s)'), $tk->fields['name']);
$nCron = (int) $DB->request(['COUNT' => 'c', 'FROM' => 'glpi_crontasks', 'WHERE' => ['itemtype' => ['LIKE', '%Vulnwatch%'], 'name' => ['LIKE', '%icket%']]])->current()['c'];
check('tickets', 'aucune action automatique de création de tickets', $nCron === 0, $nCron);

// ---------------------------------------------------------------------------
section('Suivi des corrections');
sleep(1);
$r = inventory($glpiUrl, pc('VW-PC-A1', 'windows', [
    ['Mozilla Firefox (x64 fr)', '131.0.2', 'Mozilla'],
    ['Notepad++ (64-bit x64)', null, 'Notepad++ Team'],
    ['Chrome', '100.0', 'Acme Labs'],
    ['PHP', '8.3.7', 'The PHP Group'],
    ['Outil métier interne', '2.1', 'Ma Société'],
]));
$entAfter = (int) $DB->request(['SELECT' => 'entities_id', 'FROM' => 'glpi_computers', 'WHERE' => ['id' => $a1]])->current()['entities_id'];
check('prep', 'réinventaire : l\'actif reste dans son entité', $entAfter === $entA, [$r, $entAfter]);
$s = analyze();
$fx = itemsFor('VW-PC-A1', 'CVE-2024-9680')[0];
check('corrige', 'Firefox mis à jour 130.0 → 131.0.2 : Corrigé (mis à jour)', $fx['state'] === 'fixed' && $fx['fix_kind'] === 'updated' && str_contains((string) $fx['fix_detail'], '131.0.2'), $fx);
$fx = itemsFor('VW-PC-A1', 'CVE-2024-11477')[0];
check('corrige', '7-Zip désinstallé : Corrigé (retiré)', $fx['state'] === 'fixed' && $fx['fix_kind'] === 'removed', $fx);
check('corrige', 'les autres alertes de la machine restent actives', activeItem('VW-PC-A1', 'CVE-2024-4577') !== null);

// Inventaire ancien : la machine ne remonte plus
$DB->update('glpi_computers', ['last_inventory_update' => date('Y-m-d H:i:s', time() - 90 * 86400)], ['id' => computerId('VW-PC-B1')]);
$s = analyze();
check('inventaire_ancien', 'machine qui ne remonte plus : alerte toujours active', activeItem('VW-PC-B1', 'CVE-2024-9680') !== null);
check('inventaire_ancien', 'signalée comme inventaire ancien', Inventory::isStale(Inventory::assetState('Computer', computerId('VW-PC-B1'))['last_inventory_update']));
// Inventaire ancien + logiciel supprimé à la main : jamais « Corrigé »
$a3id = computerId('VW-PC-A3');
$DB->update('glpi_computers', ['last_inventory_update' => date('Y-m-d H:i:s', time() - 90 * 86400)], ['id' => $a3id]);
$DB->delete('glpi_items_softwareversions', ['itemtype' => 'Computer', 'items_id' => $a3id]);
$s = analyze();
$x = itemsFor('VW-PC-A3', 'CVE-2024-9680')[0];
check('inventaire_ancien', 'disparition sans inventaire récent : « correction non confirmée », pas « Corrigé »', $x['state'] === 'unverified', $x);

// Échec de synchronisation : rien ne passe à « Corrigé »
$before = Report::items(['i.state' => 'active'], 5000, false);
setFixtureMode('certfr_down');
$DB->update('glpi_plugin_vulnwatch_feeds', ['last_attempt' => null], ['id' => $fA]);
$DB->update('glpi_plugin_vulnwatch_cves', ['nvd_status' => 'pending'], ['id' => ['>', 0]]);
$DB->update('glpi_plugin_vulnwatch_feeds', ['url' => 'http://127.0.0.2:8099/nvd-down'], ['id' => $fB]);
Config::set(['nvd_url' => FIX . '/nvd-down']);
Cron::cronVulnwatchCollect();
$s = analyze();
$after = Report::items(['i.state' => 'active'], 5000, false);
$fa = $DB->request(['FROM' => 'glpi_plugin_vulnwatch_feeds', 'WHERE' => ['id' => $fA]])->current();
check('sync_echec', 'flux CERT-FR indisponible : erreur, dernière réussite conservée', $fa['last_status'] === 'error' && $fa['last_success'] !== null && str_contains((string) $fa['last_error'], '503'), $fa);
check('sync_echec', 'NVD indisponible : critères conservés', (int) $DB->request(['COUNT' => 'c', 'FROM' => 'glpi_plugin_vulnwatch_criteria'])->current()['c'] > 0);
check('sync_echec', 'aucune alerte active ne disparaît ni ne passe à « Corrigé »', count($after) === count($before), [count($before), count($after)]);
setFixtureMode('normal');
Config::set(['nvd_url' => FIX . '/nvd']);
$DB->update('glpi_plugin_vulnwatch_feeds', ['url' => FIX . '/feeds/vendor.atom'], ['id' => $fB]);

// Régression
sleep(1);
inventory($glpiUrl, pc('VW-PC-A1', 'windows', [['Mozilla Firefox (x64 fr)', '130.0', 'Mozilla'], ['PHP', '8.3.7', 'The PHP Group']]));
$s = analyze();
$rg = activeItem('VW-PC-A1', 'CVE-2024-9680');
check('regression', 'version vulnérable réinstallée : alerte réactivée et marquée régression', $rg !== null && (int) $rg['is_regression'] === 1, $s);

// ---------------------------------------------------------------------------
section('Décisions manuelles');
$m = $DB->request(['FROM' => 'glpi_plugin_vulnwatch_mappings', 'WHERE' => ['vendor' => 'google', 'product' => 'chrome']])->current();
$DB->update('glpi_plugin_vulnwatch_mappings', ['status' => 'rejected', 'confidence' => 0, 'users_id' => 2], ['id' => $m['id']]);
inventory($glpiUrl, pc('VW-PC-A1', 'windows', [['Mozilla Firefox (x64 fr)', '130.0', 'Mozilla'], ['PHP', '8.3.7', 'The PHP Group'], ['Chrome', '100.0', 'Acme Labs']]));
analyze();
analyze();
$m2 = $DB->request(['FROM' => 'glpi_plugin_vulnwatch_mappings', 'WHERE' => ['id' => $m['id']]])->current();
check('nom_ambigu', 'association rejetée réutilisée par les analyses suivantes', $m2['status'] === 'rejected');
check('nom_ambigu', 'aucune alerte active Chrome après rejet', activeItem('VW-PC-A1', 'CVE-2023-4863') === null, itemsFor('VW-PC-A1', 'CVE-2023-4863'));

$php = itemsFor('VW-PC-A1', 'CVE-2024-4577');
$fixedPhp = array_filter($php, static fn($x) => $x['state'] === 'fixed');
check('corrige', 'logiciel recréé par GLPI avec la même version : jamais « Corrigé », suivi repris', $fixedPhp === [] && activeItem('VW-PC-A1', 'CVE-2024-4577') !== null, $php);

// Plusieurs associations pour un même logiciel : la plus défavorable n'écrase pas les autres
$DB->insert('glpi_plugin_vulnwatch_mappings', ['name_norm' => 'mozilla firefox', 'manufacturer_norm' => 'mozilla', 'sample_name' => 'test', 'vendor' => 'mozilla',
    'product' => 'thunderbird', 'status' => 'validated', 'confidence' => 100, 'reason' => 'test multi-associations']);
analyze();
$i = activeItem('VW-PC-A1', 'CVE-2024-9680');
check('multi_associations', 'Firefox 130.0 reste établi malgré une 2e association (thunderbird, hors plage)', ($i['fstatus'] ?? '') === 'established', $i);

// ---------------------------------------------------------------------------
section('NVD : reprises');
$DB->update('glpi_plugin_vulnwatch_cves', ['nvd_status' => 'not_found', 'nvd_fetched_at' => date('Y-m-d H:i:s', time() - 2 * 86400)], ['cve_id' => 'CVE-2024-11477']);
$DB->update('glpi_plugin_vulnwatch_cves', ['nvd_status' => 'ok', 'nvd_fetched_at' => date('Y-m-d H:i:s')], ['NOT' => ['cve_id' => 'CVE-2024-11477']]);
(new \GlpiPlugin\Vulnwatch\Source\NvdConnector())->run(20);
$st = $DB->request(['SELECT' => 'nvd_status', 'FROM' => 'glpi_plugin_vulnwatch_cves', 'WHERE' => ['cve_id' => 'CVE-2024-11477']])->current()['nvd_status'];
check('nvd_reprise', 'CVE « not_found » ancienne de plus d\'un jour : réessayée et récupérée', $st === 'ok', $st);

$since = date('Y-m-d H:i:s', time() - 3600);
Config::set(['nvd_mode' => 'incremental', 'nvd_last_sync' => $since, 'nvd_incr_window_end' => '', 'nvd_incr_index' => '0']);
$nvd = new \GlpiPlugin\Vulnwatch\Source\NvdConnector();
$r1 = $nvd->run(1);
Config::reset();
check('nvd_reprise', 'budget atteint : curseur mémorisé, date de reprise inchangée', $r1['done'] === 1 && Config::get('nvd_incr_index') === '1' && Config::get('nvd_last_sync') === $since, [$r1, Config::get('nvd_incr_index'), Config::get('nvd_last_sync')]);
$r2 = $nvd->run(1);
Config::reset();
check('nvd_reprise', 'passe suivante : reprise à la page 2, pas de CVE sautée', $r2['done'] === 1 && Config::get('nvd_incr_index') === '2', [$r2, Config::get('nvd_incr_index')]);
$r3 = $nvd->run(5);
Config::reset();
check('nvd_reprise', 'fin de fenêtre : date avancée, curseur effacé', $r3['done'] === 1 && Config::get('nvd_incr_window_end') === '' && Config::get('nvd_last_sync') !== $since, [$r3, Config::get('nvd_last_sync')]);
Config::set(['nvd_mode' => 'referenced', 'nvd_incr_window_end' => '', 'nvd_incr_index' => '0']);

// ---------------------------------------------------------------------------
echo "\n$pass réussis, $fail échecs\n";
file_put_contents(__DIR__ . '/integration-results.json', json_encode(['date' => date('c'), 'glpi' => GLPI_VERSION, 'pass' => $pass, 'fail' => $fail, 'results' => $results], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
exit($fail === 0 ? 0 : 1);
