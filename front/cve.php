<?php

use GlpiPlugin\Vulnwatch\AssetTab;
use GlpiPlugin\Vulnwatch\Cve;
use GlpiPlugin\Vulnwatch\Menu;
use GlpiPlugin\Vulnwatch\Report;
use GlpiPlugin\Vulnwatch\Ui;

/** @var DBmysql $DB */
global $DB;
Session::checkRight(Menu::$rightname, READ);
Ui::header(__('Par CVE', 'vulnwatch'), 'cve');
$canTicket = Session::haveRight(Menu::$rightname, CREATE) && Session::haveRight('ticket', CREATE);
$feedScope = getEntitiesRestrictCriteria('fe', '', '', true);

$id = (int) ($_GET['id'] ?? 0);
if ($id > 0 && ($cve = Cve::getById($id))) {
    echo "<div class='container-fluid'><h2>" . Ui::e($cve['cve_id']) . ' ' . ($cve['is_kev'] ? Ui::badge('Exploitation connue (CISA KEV)', 'bg-dark') : '') . '</h2>';
    echo '<p>' . Ui::e($cve['description'] ?: '(description non encore récupérée)') . '</p>';
    echo "<table class='table table-sm w-auto'><tr><th>CVSS</th><td>" . Ui::e($cve['cvss_score'] !== null ? $cve['cvss_score'] . ' (v' . $cve['cvss_version'] . ', ' . Cve::severityLabel($cve['severity']) . ') ' . $cve['cvss_vector'] : 'inconnu') . '</td></tr>'
        . '<tr><th>NVD</th><td>' . Ui::e($cve['nvd_status'] . ($cve['nvd_error'] ? ' — ' . $cve['nvd_error'] : '') . ($cve['nvd_fetched_at'] ? ' (récupéré le ' . $cve['nvd_fetched_at'] . ')' : '')) . " — <a target='_blank' rel='noopener noreferrer' href='https://nvd.nist.gov/vuln/detail/" . Ui::e(rawurlencode($cve['cve_id'])) . "'>fiche NVD</a></td></tr>"
        . ($cve['is_kev'] ? '<tr><th>KEV</th><td>' . Ui::e('ajoutée le ' . $cve['kev_date_added'] . ', échéance CISA ' . $cve['kev_due_date'] . ', rançongiciel : ' . $cve['kev_ransomware']) . '</td></tr>' : '')
        . '<tr><th>Origine</th><td>' . Ui::e($cve['origin']) . '</td></tr></table>';

    echo '<h3>' . __('Bulletins et sources', 'vulnwatch') . '</h3><ul>';
    $nb = 0;
    foreach ($DB->request(['SELECT' => ['b.title', 'b.link', 'b.date_published', 'fe.name AS feed'], 'FROM' => 'glpi_plugin_vulnwatch_cves_bulletins AS cb',
        'INNER JOIN' => ['glpi_plugin_vulnwatch_bulletins AS b' => ['ON' => ['cb' => 'plugin_vulnwatch_bulletins_id', 'b' => 'id']],
            'glpi_plugin_vulnwatch_feeds AS fe' => ['ON' => ['b' => 'plugin_vulnwatch_feeds_id', 'fe' => 'id']]],
        'WHERE' => ['cb.plugin_vulnwatch_cves_id' => $id, $feedScope], 'ORDER' => 'b.date_published DESC']) as $b) {
        $nb++;
        echo '<li>' . Ui::e($b['feed']) . ' — ' . ($b['link'] ? "<a target='_blank' rel='noopener noreferrer' href='" . Ui::e($b['link']) . "'>" . Ui::e($b['title']) . '</a>' : Ui::e($b['title'])) . ' <span class="small text-muted">' . Ui::e($b['date_published']) . '</span></li>';
    }
    echo ($nb === 0 ? '<li class="text-muted">Aucun bulletin de vos flux ne cite cette CVE.</li>' : '') . '</ul>';

    echo '<h3>' . __('Critères d\'applicabilité (source)', 'vulnwatch') . "</h3><ul class='small'>";
    foreach ($DB->request(['FROM' => 'glpi_plugin_vulnwatch_criteria', 'WHERE' => ['plugin_vulnwatch_cves_id' => $id]]) as $c) {
        echo '<li><code>' . Ui::e(GlpiPlugin\Vulnwatch\Matching\Evaluator::describeRule($c)) . '</code>' . ($c['conditions'] ? '<br>' . Ui::e('Conditions : ' . $c['conditions']) : '') . '</li>';
    }
    echo '</ul>';

    $rows = Report::items(['i.plugin_vulnwatch_cves_id' => $id]);
    echo '<h3>' . __('Actifs concernés', 'vulnwatch') . ' (' . count($rows) . ')</h3>';
    AssetTab::findingsTable($rows, $canTicket, false, true);
    echo '</div>';
    Html::footer();
    return;
}

// Liste
$filter = (string) ($_GET['filter'] ?? 'affected');
$cveFilter = strtoupper(trim((string) ($_GET['q'] ?? '')));
echo "<div class='container-fluid'><form method='get' class='d-flex gap-2 my-2'>";
echo "<select name='filter' class='form-select w-auto'>";
foreach (['affected' => 'CVE avec actifs concernés', 'all' => 'Toutes les CVE suivies', 'kev' => 'Exploitation connue (KEV)'] as $k => $l) {
    echo "<option value='" . Ui::e($k) . "'" . ($filter === $k ? ' selected' : '') . '>' . Ui::e($l) . '</option>';
}
echo "</select><input class='form-control w-auto' name='q' placeholder='CVE-2024-…' value='" . Ui::e($cveFilter) . "'><button class='btn btn-secondary'>Filtrer</button></form>";

$counts = [];
foreach ($DB->request(['SELECT' => ['i.plugin_vulnwatch_cves_id AS cid', 'f.status', 'COUNT' => 'i.id AS n'], 'FROM' => 'glpi_plugin_vulnwatch_findings_items AS i',
    'INNER JOIN' => ['glpi_plugin_vulnwatch_findings AS f' => ['ON' => ['i' => 'plugin_vulnwatch_findings_id', 'f' => 'id']]],
    'WHERE' => ['i.state' => 'active', Ui::entityCriteria('i')], 'GROUPBY' => ['i.plugin_vulnwatch_cves_id', 'f.status']]) as $r) {
    $counts[(int) $r['cid']][$r['status']] = (int) $r['n'];
}
$bulletins = [];
foreach ($DB->request(['SELECT' => ['cb.plugin_vulnwatch_cves_id AS cid', 'COUNT' => 'cb.id AS n'], 'FROM' => 'glpi_plugin_vulnwatch_cves_bulletins AS cb',
    'INNER JOIN' => ['glpi_plugin_vulnwatch_bulletins AS b' => ['ON' => ['cb' => 'plugin_vulnwatch_bulletins_id', 'b' => 'id']],
        'glpi_plugin_vulnwatch_feeds AS fe' => ['ON' => ['b' => 'plugin_vulnwatch_feeds_id', 'fe' => 'id']]],
    'WHERE' => [$feedScope], 'GROUPBY' => 'cb.plugin_vulnwatch_cves_id']) as $r) {
    $bulletins[(int) $r['cid']] = (int) $r['n'];
}
$where = [];
if ($filter === 'kev') {
    $where['is_kev'] = 1;
}
if ($cveFilter !== '') {
    $where['cve_id'] = ['LIKE', '%' . $cveFilter . '%'];
}
echo "<table class='table table-sm table-hover'><thead><tr><th>CVE</th><th>CVSS</th><th>KEV</th><th>Établies</th><th>À vérifier</th><th>Non évaluées</th><th>Bulletins</th><th>NVD</th></tr></thead><tbody>";
$shown = 0;
foreach ($DB->request(['FROM' => 'glpi_plugin_vulnwatch_cves', 'WHERE' => $where, 'ORDER' => ['is_kev DESC', 'cvss_score DESC'], 'LIMIT' => 2000]) as $c) {
    $n = $counts[(int) $c['id']] ?? [];
    if ($filter === 'affected' && array_sum($n) === 0) {
        continue;
    }
    if ($filter !== 'kev' && $filter !== 'affected' && array_sum($n) === 0 && !isset($bulletins[(int) $c['id']]) && $c['origin'] === 'kev') {
        continue; // CVE KEV globales sans lien avec le périmètre
    }
    $shown++;
    echo '<tr><td>' . Ui::cveLink($c['cve_id'], (int) $c['id']) . '</td><td>' . Ui::e($c['cvss_score'] ?? '—') . ' ' . Ui::e(Cve::severityLabel($c['severity'])) . '</td><td>' . ($c['is_kev'] ? Ui::badge('KEV', 'bg-dark') : '') . '</td>'
        . '<td>' . ($n['established'] ?? 0) . '</td><td>' . ($n['to_check'] ?? 0) . '</td><td>' . ($n['not_evaluated'] ?? 0) . '</td><td>' . ($bulletins[(int) $c['id']] ?? 0) . '</td><td>' . Ui::e($c['nvd_status']) . '</td></tr>';
}
if ($shown === 0) {
    echo "<tr><td colspan='8' class='text-muted'>" . __('Aucune CVE ne correspond. Une absence de résultat ne prouve pas l\'absence de vulnérabilité : voir la couverture sur le tableau de bord.', 'vulnwatch') . '</td></tr>';
}
echo '</tbody></table></div>';
Html::footer();
