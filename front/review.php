<?php

use GlpiPlugin\Vulnwatch\Cve;
use GlpiPlugin\Vulnwatch\Logger;
use GlpiPlugin\Vulnwatch\Menu;
use GlpiPlugin\Vulnwatch\Ui;

/** @var DBmysql $DB */
global $DB;
Session::checkRight(Menu::$rightname, READ);
$scope = getEntitiesRestrictCriteria('fe', '', '', true);

if (isset($_POST['review_action'])) {
    Session::checkRight(Menu::$rightname, UPDATE);
    $bid = (int) ($_POST['bulletin_id'] ?? 0);
    $b = $DB->request(['SELECT' => ['b.*', 'fe.entities_id'], 'FROM' => 'glpi_plugin_vulnwatch_bulletins AS b',
        'INNER JOIN' => ['glpi_plugin_vulnwatch_feeds AS fe' => ['ON' => ['b' => 'plugin_vulnwatch_feeds_id', 'fe' => 'id']]],
        'WHERE' => ['b.id' => $bid, $scope]])->current();
    if (!$b) {
        Html::displayRightError();
    }
    $action = (string) $_POST['review_action'];
    $upd = ['users_id_review' => Session::getLoginUserID(), 'date_review' => $_SESSION['glpi_currenttime']];
    if ($action === 'link_cve') {
        $ids = preg_split('/[\s,;]+/', strtoupper((string) ($_POST['cve_ids'] ?? ''))) ?: [];
        $ok = 0;
        foreach (array_filter($ids) as $cid) {
            if (Cve::isValidId($cid)) {
                $pk = Cve::ensure($cid, 'manual');
                $DB->updateOrInsert('glpi_plugin_vulnwatch_cves_bulletins', ['plugin_vulnwatch_cves_id' => $pk, 'plugin_vulnwatch_bulletins_id' => $bid],
                    ['plugin_vulnwatch_cves_id' => $pk, 'plugin_vulnwatch_bulletins_id' => $bid]);
                $ok++;
            }
        }
        if ($ok > 0) {
            $upd += ['review_status' => 'linked', 'cve_count' => $b['cve_count'] + $ok, 'review_reason' => 'CVE associée(s) manuellement'];
        }
    } elseif (in_array($action, ['processed', 'dismissed'], true)) {
        $upd += ['review_status' => $action, 'review_reason' => mb_substr((string) ($_POST['comment'] ?? ''), 0, 255)];
    }
    $DB->update('glpi_plugin_vulnwatch_bulletins', $upd, ['id' => $bid]);
    Logger::decision('bulletin_' . $action, 'bulletin', $bid, ['cves' => $_POST['cve_ids'] ?? '', 'comment' => $_POST['comment'] ?? ''], (int) $b['entities_id']);
    Html::back();
}

Ui::header(__('Veille à vérifier', 'vulnwatch'), 'review');
$status = in_array($_GET['status'] ?? '', ['to_review', 'linked', 'processed', 'dismissed'], true) ? $_GET['status'] : 'to_review';
echo "<div class='container-fluid'><p class='small text-muted'>" . __('Un bulletin qui cite une CVE ou un produit est un signal de veille : il ne suffit pas à déclarer une installation vulnérable. Les bulletins sans CVE ou sans données suffisantes arrivent ici.', 'vulnwatch') . '</p>';
echo "<div class='btn-group mb-2'>";
foreach (['to_review' => 'À vérifier', 'linked' => 'Liés à des CVE', 'processed' => 'Traités', 'dismissed' => 'Écartés'] as $k => $l) {
    echo "<a class='btn btn-sm " . ($k === $status ? 'btn-primary' : 'btn-outline-primary') . "' href='" . Ui::e(Menu::url('review.php', ['status' => $k])) . "'>" . Ui::e($l) . '</a>';
}
echo '</div>';
$canUpdate = Session::haveRight(Menu::$rightname, UPDATE);
echo "<table class='table table-sm'><thead><tr><th>Date</th><th>Flux</th><th>Bulletin</th><th>CVE</th><th>Raison</th>" . ($canUpdate ? '<th>Action</th>' : '') . '</tr></thead><tbody>';
foreach ($DB->request(['SELECT' => ['b.*', 'fe.name AS feed'], 'FROM' => 'glpi_plugin_vulnwatch_bulletins AS b',
    'INNER JOIN' => ['glpi_plugin_vulnwatch_feeds AS fe' => ['ON' => ['b' => 'plugin_vulnwatch_feeds_id', 'fe' => 'id']]],
    'WHERE' => ['b.review_status' => $status, $scope], 'ORDER' => 'b.date_published DESC', 'LIMIT' => 500]) as $b) {
    $cves = [];
    foreach ($DB->request(['SELECT' => ['c.id', 'c.cve_id', 'c.nvd_status'], 'FROM' => 'glpi_plugin_vulnwatch_cves_bulletins AS cb',
        'INNER JOIN' => ['glpi_plugin_vulnwatch_cves AS c' => ['ON' => ['cb' => 'plugin_vulnwatch_cves_id', 'c' => 'id']]], 'WHERE' => ['cb.plugin_vulnwatch_bulletins_id' => $b['id']]]) as $c) {
        $cves[] = Ui::cveLink($c['cve_id'], (int) $c['id']) . ($c['nvd_status'] !== 'ok' ? ' <span class="small text-muted">(' . Ui::e($c['nvd_status']) . ')</span>' : '');
    }
    echo '<tr><td class="small">' . Ui::e($b['date_published']) . '</td><td>' . Ui::e($b['feed']) . '</td><td>'
        . ($b['link'] ? "<a target='_blank' rel='noopener noreferrer' href='" . Ui::e($b['link']) . "'>" . Ui::e($b['title']) . '</a>' : Ui::e($b['title']))
        . "<details><summary class='small'>Résumé</summary><div class='small' style='white-space:pre-wrap'>" . Ui::e($b['summary']) . '</div></details></td><td>' . (implode('<br>', $cves) ?: '—')
        . '</td><td class="small">' . Ui::e($b['review_reason']) . '</td>';
    if ($canUpdate) {
        echo "<td><form method='post' action='" . Ui::e(Menu::url('review.php')) . "' class='d-flex flex-column gap-1'>" . Html::hidden('bulletin_id', ['value' => $b['id']])
            . "<input class='form-control form-control-sm' name='cve_ids' placeholder='CVE-…'>"
            . "<input class='form-control form-control-sm' name='comment' placeholder='Commentaire'>"
            . "<div class='btn-group btn-group-sm'><button class='btn btn-outline-primary' name='review_action' value='link_cve'>Lier CVE</button>"
            . "<button class='btn btn-outline-success' name='review_action' value='processed'>Traité</button><button class='btn btn-outline-secondary' name='review_action' value='dismissed'>Écarter</button></div>";
        Html::closeForm();
        echo '</td>';
    }
    echo '</tr>';
}
echo '</tbody></table></div>';
Html::footer();
