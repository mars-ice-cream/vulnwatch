<?php

use GlpiPlugin\Vulnwatch\AssetTab;
use GlpiPlugin\Vulnwatch\Cve;
use GlpiPlugin\Vulnwatch\CveView;
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

// Liste : une entrée par CVE, et dedans tous les actifs concernés
$q = strtoupper(trim((string) ($_GET['q'] ?? '')));
$kevOnly = !empty($_GET['kev']);
$withNotEvaluated = !empty($_GET['ne']);
echo "<div class='container-fluid'><form method='get' class='d-flex flex-wrap gap-3 align-items-center my-2'>"
    . "<input class='form-control w-auto' name='q' placeholder='CVE-2024-…' value='" . Ui::e($q) . "'>"
    . "<label class='form-check'><input class='form-check-input' type='checkbox' name='kev' value='1'" . ($kevOnly ? ' checked' : '') . "> Exploitées (KEV) seulement</label>"
    . "<label class='form-check'><input class='form-check-input' type='checkbox' name='ne' value='1'" . ($withNotEvaluated ? ' checked' : '') . "> Inclure les « non évalués »</label>"
    . "<button class='btn btn-secondary'>Filtrer</button></form>";

$where = ['i.state' => ['active', 'unverified'], 'f.status' => $withNotEvaluated ? ['established', 'to_check', 'not_evaluated'] : ['established', 'to_check']];
if ($kevOnly) {
    $where['c.is_kev'] = 1;
}
if ($q !== '') {
    $where['c.cve_id'] = ['LIKE', '%' . $q . '%'];
}
CveView::render(Report::items($where, 20000), $canTicket, 1);

// CVE suivies (citées par vos flux) sans actif concerné : utile pour la veille
$affected = [];
foreach ($DB->request(['SELECT' => ['plugin_vulnwatch_cves_id'], 'DISTINCT' => true, 'FROM' => 'glpi_plugin_vulnwatch_findings_items AS i',
    'WHERE' => ['i.state' => ['active', 'unverified'], Ui::entityCriteria('i')]]) as $r) {
    $affected[(int) $r['plugin_vulnwatch_cves_id']] = true;
}
$others = [];
foreach ($DB->request(['SELECT' => ['c.id', 'c.cve_id', 'c.cvss_score', 'c.severity', 'c.is_kev', 'c.nvd_status'], 'DISTINCT' => true, 'FROM' => 'glpi_plugin_vulnwatch_cves AS c',
    'INNER JOIN' => ['glpi_plugin_vulnwatch_cves_bulletins AS cb' => ['ON' => ['cb' => 'plugin_vulnwatch_cves_id', 'c' => 'id']],
        'glpi_plugin_vulnwatch_bulletins AS b' => ['ON' => ['cb' => 'plugin_vulnwatch_bulletins_id', 'b' => 'id']],
        'glpi_plugin_vulnwatch_feeds AS fe' => ['ON' => ['b' => 'plugin_vulnwatch_feeds_id', 'fe' => 'id']]],
    'WHERE' => [$feedScope], 'ORDER' => ['c.cvss_score DESC'], 'LIMIT' => 500]) as $c) {
    if (!isset($affected[(int) $c['id']])) {
        $others[] = $c;
    }
}
echo "<details class='mt-4'><summary>" . Ui::e(sprintf(__('%d CVE citées par vos flux sans actif concerné dans votre périmètre', 'vulnwatch'), count($others))) . "</summary><table class='table table-sm'><tbody>";
foreach ($others as $c) {
    echo '<tr><td>' . Ui::cveLink($c['cve_id'], (int) $c['id']) . '</td><td>' . Ui::e($c['cvss_score'] ?? '—') . ' ' . Ui::e(Cve::severityLabel($c['severity'])) . '</td><td>' . ($c['is_kev'] ? Ui::badge('KEV', 'bg-dark') : '') . '</td><td class="small text-muted">NVD : ' . Ui::e($c['nvd_status']) . '</td></tr>';
}
echo '</tbody></table></details></div>';
Html::footer();
