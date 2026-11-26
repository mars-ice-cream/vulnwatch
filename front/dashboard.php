<?php

use GlpiPlugin\Vulnwatch\CveView;
use GlpiPlugin\Vulnwatch\Config;
use GlpiPlugin\Vulnwatch\Menu;
use GlpiPlugin\Vulnwatch\Report;
use GlpiPlugin\Vulnwatch\Ui;

/** @var DBmysql $DB */
global $DB;
Session::checkRight(Menu::$rightname, READ);
Ui::header(__('Vulnérabilités', 'vulnwatch'), 'dashboard');

$counts = Report::countsByEntity();
$tot = ['established' => 0, 'to_check' => 0, 'not_evaluated' => 0, 'fixed' => 0, 'unverified' => 0, 'regressions' => 0];
foreach ($counts as $c) {
    foreach ($tot as $k => $_) {
        $tot[$k] += $c[$k];
    }
}
$cov = Report::coverage();

// État des sources (flux visibles dans le périmètre)
$feeds = iterator_to_array($DB->request(['FROM' => 'glpi_plugin_vulnwatch_feeds', 'WHERE' => [getEntitiesRestrictCriteria('glpi_plugin_vulnwatch_feeds', '', '', true)]]), false);
$feedErrors = array_filter($feeds, static fn($f) => $f['is_active'] && $f['last_status'] === 'error');
$nvd = [];
foreach ($DB->request(['SELECT' => ['nvd_status', 'COUNT' => 'id AS n'], 'FROM' => 'glpi_plugin_vulnwatch_cves', 'GROUPBY' => 'nvd_status']) as $r) {
    $nvd[$r['nvd_status']] = (int) $r['n'];
}
$toReview = (int) $DB->request(['COUNT' => 'c', 'FROM' => 'glpi_plugin_vulnwatch_bulletins AS b',
    'INNER JOIN' => ['glpi_plugin_vulnwatch_feeds AS fe' => ['ON' => ['b' => 'plugin_vulnwatch_feeds_id', 'fe' => 'id']]],
    'WHERE' => ['b.review_status' => 'to_review', getEntitiesRestrictCriteria('fe', '', '', true)]])->current()['c'];

echo "<div class='container-fluid'>";
echo "<div class='row mt-2'>";
echo Ui::card('Correspondances établies', (string) $tot['established'], 'rattachements actifs', 'border-danger');
echo Ui::card('À vérifier', (string) $tot['to_check'], 'produit probable ou donnée manquante', 'border-warning');
echo Ui::card('Corrigées (observées)', (string) $tot['fixed'], $tot['unverified'] . ' disparition(s) non confirmée(s)');
echo Ui::card('Régressions', (string) $tot['regressions'], 'version vulnérable réapparue');
echo '</div>';

echo "<div class='row'>";
$covPct = $cov['installed'] > 0 ? round(100 * $cov['mapped'] / $cov['installed']) : 0;
echo Ui::card('Couverture logicielle', $covPct . ' %', Ui::e(sprintf('%d version(s) installée(s), %d rapprochée(s), %d sans produit reconnu, %d sans version exploitable', $cov['installed'], $cov['mapped'], $cov['unmapped'], $cov['no_version'])));
echo Ui::card('Inventaires anciens', (string) $cov['stale_assets'], Ui::e(sprintf('sur %d actif(s) ; %d jamais inventorié(s) par agent ; seuil %d j', $cov['assets'], $cov['never_inventoried'], Config::getInt('stale_days'))));
echo Ui::card('Veille à vérifier', (string) $toReview, "<a href='" . Ui::e(Menu::url('review.php')) . "'>bulletins sans CVE ou incomplets</a>");
$srcSub = sprintf('%d flux, %d en erreur · NVD : %d enrichie(s), %d en attente, %d erreur(s)', count($feeds), count($feedErrors), $nvd['ok'] ?? 0, $nvd['pending'] ?? 0, $nvd['error'] ?? 0);
if (Config::get('kev_last_error') !== '') {
    $srcSub .= ' · KEV en erreur';
}
echo Ui::card('Sources', count($feedErrors) + ($nvd['error'] ?? 0) > 0 ? 'Attention' : 'OK', Ui::e($srcSub), count($feedErrors) > 0 ? 'border-danger' : '');
echo '</div>';

if ($feedErrors !== []) {
    echo "<div class='alert alert-danger'>" . __('Flux en erreur (les alertes existantes sont conservées, rien ne passe à « Corrigé » à cause d\'une source indisponible) :', 'vulnwatch') . '<ul>';
    foreach ($feedErrors as $f) {
        echo '<li>' . Ui::e($f['name'] . ' — ' . $f['last_error_date'] . ' : ' . $f['last_error']) . '</li>';
    }
    echo '</ul></div>';
}

// Vue par entité
echo '<h3>' . __('Par entité', 'vulnwatch') . "</h3><table class='table table-sm'><thead><tr><th>Entité</th><th>Établies</th><th>À vérifier</th><th>Non évaluées</th><th>Corrigées</th><th>Non confirmées</th><th>Régressions</th></tr></thead><tbody>";
foreach ($counts as $e => $c) {
    echo '<tr><td>' . Ui::e(Dropdown::getDropdownName('glpi_entities', $e)) . '</td><td>' . $c['established'] . '</td><td>' . $c['to_check'] . '</td><td>' . $c['not_evaluated']
        . '</td><td>' . $c['fixed'] . '</td><td>' . $c['unverified'] . '</td><td>' . $c['regressions'] . '</td></tr>';
}
if ($counts === []) {
    echo "<tr><td colspan='7' class='text-muted'>" . __('Aucun résultat dans votre périmètre. Vérifiez la couverture ci-dessus avant de conclure.', 'vulnwatch') . '</td></tr>';
}
echo '</tbody></table>';

// Priorités : une entrée par CVE, les actifs à l'intérieur
$top = Report::items(['i.state' => ['active', 'unverified'], 'f.status' => ['established', 'to_check']], 5000);
echo '<h3>' . __('CVE à traiter en priorité', 'vulnwatch') . '</h3>';
echo "<p class='small text-muted'>" . __('Priorité = gravité + exploitation connue + criticité + exposition (détail au survol). La confiance mesure la fiabilité de la détection, séparément.', 'vulnwatch') . '</p>';
CveView::render($top, Session::haveRight(Menu::$rightname, CREATE) && Session::haveRight('ticket', CREATE), 3, 15);
echo '</div>';
Html::footer();
