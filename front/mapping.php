<?php

use GlpiPlugin\Vulnwatch\Logger;
use GlpiPlugin\Vulnwatch\Matching\Normalizer;
use GlpiPlugin\Vulnwatch\Menu;
use GlpiPlugin\Vulnwatch\Ui;

/** @var DBmysql $DB */
global $DB;
Session::checkRight(Menu::$rightname, READ);
$T = 'glpi_plugin_vulnwatch_mappings';

if (isset($_POST['mapping_action'])) {
    Session::checkRight(Menu::$rightname, UPDATE);
    $now = $_SESSION['glpi_currenttime'];
    $action = (string) $_POST['mapping_action'];
    if ($action === 'add') {
        $name = Normalizer::softwareName((string) ($_POST['software_name'] ?? ''));
        $manuf = Normalizer::manufacturer((string) ($_POST['manufacturer'] ?? ''));
        $vendor = strtolower(trim((string) ($_POST['vendor'] ?? '')));
        $product = strtolower(trim((string) ($_POST['product'] ?? '')));
        if ($name === '' || !preg_match('/^[a-z0-9_\-.\\\\+&!~]+$/', $vendor) || !preg_match('/^[a-z0-9_\-.\\\\+&!~]+$/', $product)) {
            Session::addMessageAfterRedirect(__('Nom, vendor et product CPE obligatoires (format CPE).', 'vulnwatch'), false, ERROR);
        } else {
            $DB->updateOrInsert($T, ['status' => 'validated', 'confidence' => 100, 'reason' => 'Association saisie manuellement', 'users_id' => Session::getLoginUserID(),
                'date_decision' => $now, 'date_mod' => $now, 'sample_name' => (string) $_POST['software_name'], 'sample_manufacturer' => (string) ($_POST['manufacturer'] ?? ''), 'date_creation' => $now],
                ['name_norm' => $name, 'manufacturer_norm' => $manuf, 'vendor' => $vendor, 'product' => $product]);
            Logger::decision('mapping_add', 'mapping', 0, compact('name', 'manuf', 'vendor', 'product'));
        }
    } else {
        $id = (int) ($_POST['id'] ?? 0);
        $row = $DB->request(['FROM' => $T, 'WHERE' => ['id' => $id]])->current();
        if ($row) {
            $map = ['validate' => ['validated', 100], 'reject' => ['rejected', 0], 'reset' => ['proposed', 50]];
            if (isset($map[$action])) {
                [$st, $conf] = $map[$action];
                $DB->update($T, ['status' => $st, 'confidence' => $conf, 'users_id' => Session::getLoginUserID(), 'date_decision' => $now, 'date_mod' => $now,
                    'comment' => mb_substr((string) ($_POST['comment'] ?? ''), 0, 1000)], ['id' => $id]);
                Logger::decision('mapping_' . $action, 'mapping', $id, ['from' => $row['status'], 'to' => $st, 'software' => $row['sample_name'], 'cpe' => $row['vendor'] . ':' . $row['product'], 'comment' => $_POST['comment'] ?? '']);
            }
        }
    }
    Session::addMessageAfterRedirect(__('Décision enregistrée. Elle sera appliquée à la prochaine analyse.', 'vulnwatch'));
    Html::back();
}

Ui::header(__('Associations logiciel → produit', 'vulnwatch'), 'mapping');
$status = in_array($_GET['status'] ?? '', ['proposed', 'auto', 'validated', 'rejected'], true) ? $_GET['status'] : 'proposed';
$canUpdate = Session::haveRight(Menu::$rightname, UPDATE);
echo "<div class='container-fluid'><p class='small text-muted'>" . __('Les associations « proposées » produisent uniquement des résultats « À vérifier ». Une décision (valider/rejeter) est conservée et réutilisée par toutes les analyses suivantes.', 'vulnwatch') . '</p>';
echo "<div class='btn-group mb-2'>";
foreach (['proposed' => 'Proposées (ambiguës)', 'auto' => 'Automatiques', 'validated' => 'Validées', 'rejected' => 'Rejetées'] as $k => $l) {
    echo "<a class='btn btn-sm " . ($k === $status ? 'btn-primary' : 'btn-outline-primary') . "' href='" . Ui::e(Menu::url('mapping.php', ['status' => $k])) . "'>" . Ui::e($l) . '</a>';
}
echo '</div>';
echo "<table class='table table-sm'><thead><tr><th>Logiciel (exemple)</th><th>Éditeur</th><th>Produit CPE</th><th>Confiance</th><th>Raison</th><th>Décision</th>" . ($canUpdate ? '<th></th>' : '') . '</tr></thead><tbody>';
foreach ($DB->request(['FROM' => $T, 'WHERE' => ['status' => $status], 'ORDER' => 'sample_name', 'LIMIT' => 1000]) as $m) {
    echo '<tr><td>' . Ui::e($m['sample_name']) . ' <span class="small text-muted">(' . Ui::e($m['name_norm']) . ')</span></td><td>' . Ui::e($m['sample_manufacturer']) . '</td><td><code>'
        . Ui::e($m['vendor'] . ':' . $m['product']) . '</code></td><td>' . Ui::confidence((int) $m['confidence']) . '</td><td class="small">' . Ui::e($m['reason']) . '</td><td class="small">'
        . ($m['users_id'] ? Ui::e(getUserName((int) $m['users_id']) . ' — ' . $m['date_decision'] . ($m['comment'] ? ' — ' . $m['comment'] : '')) : '—') . '</td>';
    if ($canUpdate) {
        echo "<td><form method='post' action='" . Ui::e(Menu::url('mapping.php')) . "' class='d-flex gap-1'>" . Html::hidden('id', ['value' => $m['id']])
            . "<input class='form-control form-control-sm' name='comment' placeholder='Motif'>"
            . ($m['status'] !== 'validated' ? "<button class='btn btn-sm btn-outline-success' name='mapping_action' value='validate'>Valider</button>" : '')
            . ($m['status'] !== 'rejected' ? "<button class='btn btn-sm btn-outline-danger' name='mapping_action' value='reject'>Rejeter</button>" : '')
            . (in_array($m['status'], ['validated', 'rejected'], true) ? "<button class='btn btn-sm btn-outline-secondary' name='mapping_action' value='reset'>Annuler la décision</button>" : '');
        Html::closeForm();
        echo '</td>';
    }
    echo '</tr>';
}
echo '</tbody></table>';
if ($canUpdate) {
    echo '<h3>' . __('Ajouter une association manuelle', 'vulnwatch') . "</h3><form method='post' action='" . Ui::e(Menu::url('mapping.php')) . "' class='d-flex gap-2'>"
        . "<input class='form-control' name='software_name' placeholder='Nom inventorié' required><input class='form-control' name='manufacturer' placeholder='Éditeur inventorié'>"
        . "<input class='form-control' name='vendor' placeholder='vendor CPE' required><input class='form-control' name='product' placeholder='product CPE' required>"
        . "<button class='btn btn-primary' name='mapping_action' value='add'>Ajouter</button>";
    Html::closeForm();
}
echo '</div>';
Html::footer();
