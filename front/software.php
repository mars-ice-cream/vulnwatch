<?php

use GlpiPlugin\Vulnwatch\Inventory;
use GlpiPlugin\Vulnwatch\Menu;
use GlpiPlugin\Vulnwatch\Target;
use GlpiPlugin\Vulnwatch\Ui;

/** @var DBmysql $DB */
global $DB;
Session::checkRight(Menu::$rightname, READ);
Ui::header(__('Par logiciel', 'vulnwatch'), 'software');
$all = !empty($_GET['all']);
$q = trim((string) ($_GET['q'] ?? ''));

// Résultats par version logicielle (CVE actives dans le périmètre)
$fcount = [];
foreach ($DB->request(['SELECT' => ['f.softwareversions_id AS sv', 'f.status', 'f.fixed_version', 'i.plugin_vulnwatch_cves_id AS cid'], 'DISTINCT' => true,
    'FROM' => 'glpi_plugin_vulnwatch_findings_items AS i', 'INNER JOIN' => ['glpi_plugin_vulnwatch_findings AS f' => ['ON' => ['i' => 'plugin_vulnwatch_findings_id', 'f' => 'id']]],
    'WHERE' => ['i.state' => 'active', Ui::entityCriteria('i')]]) as $r) {
    $fcount[(int) $r['sv']][$r['status']][(int) $r['cid']] = true;
    if ($r['fixed_version']) {
        $fcount[(int) $r['sv']]['fixed'][$r['fixed_version']] = true;
    }
}

$where = Inventory::activeLinkCriteria() + [Ui::entityCriteria('glpi_items_softwareversions')];
if ($q !== '') {
    $where['glpi_softwares.name'] = ['LIKE', '%' . $q . '%'];
}
$rows = $DB->request([
    'SELECT' => ['glpi_softwares.name', 'glpi_softwareversions.id AS sv', 'glpi_softwareversions.name AS version', 'glpi_items_softwareversions.entities_id', 'COUNT' => 'glpi_items_softwareversions.id AS machines'],
    'FROM' => 'glpi_items_softwareversions',
    'INNER JOIN' => [
        'glpi_softwareversions' => ['ON' => ['glpi_items_softwareversions' => 'softwareversions_id', 'glpi_softwareversions' => 'id']],
        'glpi_softwares' => ['ON' => ['glpi_softwareversions' => 'softwares_id', 'glpi_softwares' => 'id']],
    ],
    'WHERE' => $where,
    'GROUPBY' => ['glpi_softwares.name', 'glpi_softwareversions.id', 'glpi_items_softwareversions.entities_id'],
    'ORDER' => ['glpi_softwares.name', 'glpi_softwareversions.name'],
    'LIMIT' => 5000,
]);

echo "<div class='container-fluid'><form method='get' class='d-flex gap-2 my-2'><input class='form-control w-auto' name='q' placeholder='Logiciel' value='" . Ui::e($q) . "'>"
    . "<label class='form-check'><input class='form-check-input' type='checkbox' name='all' value='1'" . ($all ? ' checked' : '') . "> Tous les logiciels</label><button class='btn btn-secondary'>Filtrer</button></form>";
echo "<p class='small text-muted'>" . __('Trois notions distinctes : « affectée par une CVE » (source de vulnérabilités), « sous la version cible approuvée » et « fin de support » (règles de l\'administrateur). La dernière version publiée n\'est pas forcément la version approuvée.', 'vulnwatch') . '</p>';
echo "<table class='table table-sm table-hover'><thead><tr><th>Logiciel</th><th>Version</th><th>Entité</th><th>Machines</th><th>Affectée par une CVE</th><th>Corrigée en (source)</th><th>Sous la version cible</th><th>Fin de support</th></tr></thead><tbody>";
$n = 0;
foreach ($rows as $r) {
    $sv = (int) $r['sv'];
    $fc = $fcount[$sv] ?? [];
    $t = Target::assess((string) $r['name'], (string) $r['version'], (int) $r['entities_id']);
    if (!$all && $fc === [] && $t['target'] === null && $t['eol'] === null) {
        continue;
    }
    $n++;
    $cves = [];
    foreach (['established', 'to_check', 'not_evaluated'] as $st) {
        if (!empty($fc[$st])) {
            $cves[] = Ui::findingBadge($st) . ' ' . count($fc[$st]) . ' CVE';
        }
    }
    $target = $t['target'] === null ? '—' : ($t['below_target'] === null ? Ui::badge('Non comparable', 'bg-secondary') : ($t['below_target'] ? Ui::badge('Oui', 'bg-warning text-dark') : Ui::badge('Non', 'bg-success'))) . ' <span class="small">cible ' . Ui::e($t['target']) . ($t['source'] ? ' — ' . Ui::e($t['source']) : '') . '</span>';
    $eol = $t['eol'] === null ? '—' : ($t['eol'] ? Ui::badge('Oui', 'bg-danger') : Ui::badge('Non', 'bg-success')) . ' <span class="small">' . Ui::e($t['eol_text']) . '</span>';
    $machinesLink = "<a href='" . Ui::e(Menu::url('software.php', ['sv' => $sv])) . "'>" . (int) $r['machines'] . '</a>';
    echo '<tr><td>' . Ui::e($r['name']) . '</td><td><code>' . Ui::e($r['version']) . '</code></td><td>' . Ui::e(Dropdown::getDropdownName('glpi_entities', (int) $r['entities_id'])) . '</td><td>' . $machinesLink . '</td><td>'
        . ($cves === [] ? '—' : implode('<br>', $cves)) . '</td><td>' . Ui::e(implode(', ', array_keys($fc['fixed'] ?? [])) ?: '—') . '</td><td>' . $target . '</td><td>' . $eol . '</td></tr>';
}
if ($n === 0) {
    echo "<tr><td colspan='8' class='text-muted'>" . __('Aucun logiciel concerné dans votre périmètre.', 'vulnwatch') . '</td></tr>';
}
echo '</tbody></table>';

// Détail : machines d'une version
if (($svid = (int) ($_GET['sv'] ?? 0)) > 0) {
    echo '<h3>' . __('Machines associées', 'vulnwatch') . '</h3><ul>';
    foreach (Inventory::linksForVersions([$svid]) as $l) {
        if (Session::haveAccessToEntity($l['entities_id'])) {
            echo '<li>' . Ui::itemLink($l['itemtype'], $l['items_id']) . ' ' . Ui::staleBadge($l['last_inventory_update']) . '</li>';
        }
    }
    echo '</ul>';
}
echo '</div>';
Html::footer();
