<?php

use GlpiPlugin\Vulnwatch\Config;
use GlpiPlugin\Vulnwatch\Cron;
use GlpiPlugin\Vulnwatch\Logger;
use GlpiPlugin\Vulnwatch\Matching\Analyzer;
use GlpiPlugin\Vulnwatch\Menu;
use GlpiPlugin\Vulnwatch\Ui;

/** @var DBmysql $DB */
global $DB;
Session::checkRight('plugin_vulnwatch_config', READ);

if (!empty($_POST)) {
    Session::checkRight('plugin_vulnwatch_config', UPDATE);
    if (isset($_POST['save_config'])) {
        $in = array_intersect_key($_POST, Config::DEFAULTS);
        unset($in['nvd_last_sync'], $in['nvd_incr_window_end'], $in['nvd_incr_index'], $in['kev_last_sync'], $in['kev_last_error']);
        foreach (['nvd_enabled', 'kev_enabled', 'kev_track_all'] as $b) {
            $in[$b] = !empty($_POST[$b]) ? '1' : '0';
        }
        if (($in['nvd_api_key'] ?? '') === '********') {
            unset($in['nvd_api_key']); // inchangée
        }
        $in['nvd_mode'] = in_array($in['nvd_mode'] ?? '', ['referenced', 'incremental'], true) ? $in['nvd_mode'] : 'referenced';
        $in['stale_days'] = (string) max(1, min(365, (int) ($in['stale_days'] ?? 30)));
        $in['http_timeout'] = (string) max(3, min(120, (int) ($in['http_timeout'] ?? 20)));
        $in['http_max_bytes'] = (string) max(65536, min(52428800, (int) ($in['http_max_bytes'] ?? 5242880)));
        $in['http_allowed_ports'] = implode(',', array_filter(array_map('intval', explode(',', (string) ($in['http_allowed_ports'] ?? '80,443'))), static fn($p) => $p > 0 && $p < 65536));
        Config::set($in);
        Logger::decision('config_update', 'config', 0, array_diff_key($in, ['nvd_api_key' => 1]));
        Session::addMessageAfterRedirect(__('Configuration enregistrée.', 'vulnwatch'));
    } elseif (isset($_POST['save_entity'])) {
        $eid = (int) $_POST['entities_id'];
        if (!Session::haveAccessToEntity($eid)) {
            throw new \Glpi\Exception\Http\AccessDeniedHttpException();
        }
        $data = ['auto_ticket' => !empty($_POST['auto_ticket']) ? 1 : 0, 'auto_min_confidence' => max(70, min(100, (int) $_POST['auto_min_confidence'])),
            'auto_min_priority' => max(0, min(100, (int) $_POST['auto_min_priority'])), 'date_mod' => $_SESSION['glpi_currenttime']];
        $DB->updateOrInsert('glpi_plugin_vulnwatch_entityconfigs', $data, ['entities_id' => $eid]);
        Logger::decision('entity_automation', 'entity', $eid, $data, $eid);
        Session::addMessageAfterRedirect(__('Paramètres de l\'entité enregistrés.', 'vulnwatch'));
    } elseif (isset($_POST['run_collect'])) {
        Cron::cronVulnwatchCollect();
        Session::addMessageAfterRedirect(__('Collecte exécutée (voir le journal vulnwatch.log).', 'vulnwatch'));
    } elseif (isset($_POST['run_analyze'])) {
        $s = (new Analyzer())->run();
        Session::addMessageAfterRedirect(htmlescape('Analyse : ' . json_encode($s)));
    }
    Html::back();
}

Ui::header(__('Configuration VulnWatch', 'vulnwatch'), 'config');
$canEdit = Session::haveRight('plugin_vulnwatch_config', UPDATE);
$v = static fn($k) => Ui::e(Config::get($k));
$chk = static fn($k) => Config::getBool($k) ? ' checked' : '';
echo "<div class='container-fluid'><form method='post' action='" . Ui::e(Menu::url('config.php')) . "'>";
echo "<h3>Sources</h3><table class='table table-sm w-auto'>";
echo "<tr><td>NVD activée</td><td><input type='checkbox' class='form-check-input' name='nvd_enabled' value='1'{$chk('nvd_enabled')}></td></tr>";
echo "<tr><td>Clé d'API NVD (facultative, augmente le débit)</td><td><input class='form-control' name='nvd_api_key' value='" . (Config::get('nvd_api_key') !== '' ? '********' : '') . "' autocomplete='off'></td></tr>";
echo "<tr><td>Mode NVD</td><td><select class='form-select' name='nvd_mode'><option value='referenced'" . (Config::get('nvd_mode') === 'referenced' ? ' selected' : '') . ">CVE citées par les flux ou ajoutées (par identifiant)</option><option value='incremental'" . (Config::get('nvd_mode') === 'incremental' ? ' selected' : '') . ">Toutes les CVE modifiées (par dates)</option></select></td></tr>";
echo "<tr><td>URL de l'API NVD (miroir interne possible)</td><td><input class='form-control' name='nvd_url' value='{$v('nvd_url')}'></td></tr>";
echo "<tr><td>Lot NVD par exécution</td><td><input class='form-control' type='number' name='nvd_batch_size' value='{$v('nvd_batch_size')}'></td></tr>";
echo "<tr><td>CISA KEV activé</td><td><input type='checkbox' class='form-check-input' name='kev_enabled' value='1'{$chk('kev_enabled')}> <span class='small'>dernière synchro : {$v('kev_last_sync')} {$v('kev_last_error')}</span></td></tr>";
echo "<tr><td>Suivre toutes les CVE KEV (pas seulement celles déjà connues)</td><td><input type='checkbox' class='form-check-input' name='kev_track_all' value='1'{$chk('kev_track_all')}></td></tr>";
echo "<tr><td>URL du catalogue KEV</td><td><input class='form-control' name='kev_url' value='{$v('kev_url')}'></td></tr>";
echo "</table><h3>Analyse</h3><table class='table table-sm w-auto'>";
echo "<tr><td>Inventaire considéré comme ancien après (jours)</td><td><input class='form-control' type='number' name='stale_days' value='{$v('stale_days')}'></td></tr>";
echo "</table><h3>Sécurité des récupérations</h3><table class='table table-sm w-auto'>";
echo "<tr><td>Délai maximal (s)</td><td><input class='form-control' type='number' name='http_timeout' value='{$v('http_timeout')}'></td></tr>";
echo "<tr><td>Taille maximale (octets)</td><td><input class='form-control' type='number' name='http_max_bytes' value='{$v('http_max_bytes')}'></td></tr>";
echo "<tr><td>Ports autorisés</td><td><input class='form-control' name='http_allowed_ports' value='{$v('http_allowed_ports')}'></td></tr>";
echo "<tr><td>Sources internes explicitement autorisées<br><span class='small text-muted'>un nom d'hôte, une IP ou un CIDR par ligne ; tout le reste du réseau interne est refusé (SSRF)</span></td><td><textarea class='form-control' name='http_internal_allowlist' rows='3'>{$v('http_internal_allowlist')}</textarea></td></tr>";
echo "<tr><td>Proxy sortant (facultatif)</td><td><input class='form-control' name='http_proxy' value='{$v('http_proxy')}' placeholder='http://proxy:3128'></td></tr>";
echo '</table>';
if ($canEdit) {
    echo Html::submit(_sx('button', 'Save'), ['name' => 'save_config', 'class' => 'btn btn-primary']) . ' ';
    echo Html::submit(__('Lancer la collecte maintenant', 'vulnwatch'), ['name' => 'run_collect', 'class' => 'btn btn-outline-secondary']) . ' ';
    echo Html::submit(__('Lancer l\'analyse maintenant', 'vulnwatch'), ['name' => 'run_analyze', 'class' => 'btn btn-outline-secondary']);
}
Html::closeForm();

echo "<h3 class='mt-4'>Données transmises à l'extérieur</h3><p class='small'>Le rapprochement est entièrement local : aucun nom de logiciel, version, machine ou entité n'est transmis.</p><ul class='small'>";
foreach (Cron::connectors() as $c) {
    echo '<li><strong>' . Ui::e($c->getLabel()) . '</strong> (' . ($c->isEnabled() ? 'activé' : 'désactivé') . ') : ' . Ui::e($c->describeOutboundData()) . '</li>';
}
echo '</ul>';

echo "<h3 class='mt-4'>Tickets automatiques par entité</h3><p class='small text-muted'>Désactivés par défaut. Seules les correspondances établies, au-dessus des seuils et sur des actifs à l'inventaire récent, sont regroupées dans des tickets de campagne.</p>";
echo "<table class='table table-sm w-auto'><thead><tr><th>Entité</th><th>Actif</th><th>Confiance min.</th><th>Priorité min.</th><th></th></tr></thead><tbody>";
$cfgs = [];
foreach ($DB->request(['FROM' => 'glpi_plugin_vulnwatch_entityconfigs']) as $r) {
    $cfgs[(int) $r['entities_id']] = $r;
}
foreach ($_SESSION['glpiactiveentities'] as $eid) {
    $c = $cfgs[(int) $eid] ?? ['auto_ticket' => 0, 'auto_min_confidence' => 90, 'auto_min_priority' => 70];
    echo "<tr><form method='post' action='" . Ui::e(Menu::url('config.php')) . "'><td>" . Ui::e(Dropdown::getDropdownName('glpi_entities', (int) $eid)) . Html::hidden('entities_id', ['value' => $eid]) . '</td>'
        . "<td><input type='checkbox' class='form-check-input' name='auto_ticket' value='1'" . ($c['auto_ticket'] ? ' checked' : '') . '></td>'
        . "<td><input class='form-control form-control-sm' type='number' min='70' max='100' name='auto_min_confidence' value='" . (int) $c['auto_min_confidence'] . "'></td>"
        . "<td><input class='form-control form-control-sm' type='number' min='0' max='100' name='auto_min_priority' value='" . (int) $c['auto_min_priority'] . "'></td><td>"
        . ($canEdit ? Html::submit(_sx('button', 'Save'), ['name' => 'save_entity', 'class' => 'btn btn-sm btn-secondary']) : '') . '</td>';
    Html::closeForm();
    echo '</tr>';
}
echo '</tbody></table>';

echo "<h3 class='mt-4'>Journal des décisions</h3><table class='table table-sm small'><thead><tr><th>Date</th><th>Utilisateur</th><th>Action</th><th>Objet</th><th>Détails</th></tr></thead><tbody>";
foreach ($DB->request(['FROM' => 'glpi_plugin_vulnwatch_decisionlogs', 'WHERE' => [Ui::entityCriteria('glpi_plugin_vulnwatch_decisionlogs')], 'ORDER' => 'id DESC', 'LIMIT' => 100]) as $l) {
    echo '<tr><td>' . Ui::e($l['date_creation']) . '</td><td>' . Ui::e($l['users_id'] ? getUserName((int) $l['users_id']) : 'automatique') . '</td><td>' . Ui::e($l['action']) . '</td><td>' . Ui::e($l['object_type'] . ' #' . $l['object_id']) . '</td><td><code>' . Ui::e($l['details']) . '</code></td></tr>';
}
echo '</tbody></table></div>';
Html::footer();
