<?php

namespace GlpiPlugin\Vulnwatch;

use CommonGLPI;
use Html;
use Session;

/** Onglet « Vulnérabilités » sur les fiches d'actifs (mécanisme natif addtabon). */
final class AssetTab extends CommonGLPI
{
    public const SUPPORTED_ITEMTYPES = Inventory::TAB_ITEMTYPES;

    public static $rightname = 'plugin_vulnwatch';

    public static function getTypeName($nb = 0)
    {
        return __('Vulnérabilités', 'vulnwatch');
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!Session::haveRight(self::$rightname, READ) || !in_array($item->getType(), self::SUPPORTED_ITEMTYPES, true) || $item->isNewItem()) {
            return '';
        }
        $n = 0;
        if ($_SESSION['glpishow_count_on_tabs'] ?? false) {
            /** @var \DBmysql $DB */
            global $DB;
            $n = (int) $DB->request(['COUNT' => 'c', 'FROM' => 'glpi_plugin_vulnwatch_findings_items',
                'WHERE' => ['itemtype' => $item->getType(), 'items_id' => $item->getID(), 'state' => 'active']])->current()['c'];
        }
        return self::createTabEntry(self::getTypeName(), $n, null, 'ti ti-shield-exclamation');
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if (!$item instanceof \CommonDBTM || !$item->can($item->getID(), READ)) {
            return false;
        }
        self::show($item);
        return true;
    }

    public static function show(\CommonDBTM $item): void
    {
        $itemtype = $item->getType();
        $id = $item->getID();
        $last = $item->fields['last_inventory_update'] ?? null;
        $ctx = Priority::assetContext($itemtype, $id);
        $canUpdate = Session::haveRight(self::$rightname, UPDATE) && $item->can($id, UPDATE);
        $canTicket = Session::haveRight(self::$rightname, CREATE) && Session::haveRight('ticket', CREATE);

        echo "<div class='p-3'>";
        echo "<div class='mb-2'><strong>" . __('Dernier inventaire', 'vulnwatch') . ' :</strong> ' . Ui::staleBadge($last);
        if (Inventory::isStale($last)) {
            echo " <span class='small text-muted'>" . Ui::e(sprintf(__('Au-delà de %d jours, aucune alerte ne passe à « Corrigé » pour cet actif.', 'vulnwatch'), Config::getInt('stale_days'))) . '</span>';
        }
        echo '</div>';

        // Contexte de priorité
        echo "<form method='post' action='" . Ui::e(Menu::url('asset.form.php')) . "' class='mb-3 d-flex gap-2 align-items-center'>";
        echo Html::hidden('itemtype', ['value' => $itemtype]) . Html::hidden('items_id', ['value' => $id]);
        echo '<span>' . __('Criticité', 'vulnwatch') . '</span>';
        echo self::select('criticality', [0 => 'Non renseignée', 1 => 'Faible', 2 => 'Moyenne', 3 => 'Haute'], $ctx['criticality'], !$canUpdate);
        echo '<span>' . __('Exposition réseau', 'vulnwatch') . '</span>';
        echo self::select('exposure', [0 => 'Inconnue', 1 => 'Interne', 2 => 'Exposé à Internet'], $ctx['exposure'], !$canUpdate);
        if ($canUpdate) {
            echo Html::submit(__('Enregistrer le contexte', 'vulnwatch'), ['name' => 'save_context', 'class' => 'btn btn-sm btn-secondary']);
        }
        Html::closeForm();

        $rows = Report::items(['i.itemtype' => $itemtype, 'i.items_id' => $id]);
        $active = array_filter($rows, static fn($r) => in_array($r['state'], ['active', 'unverified'], true) && $r['fstatus'] !== 'not_evaluated');
        $notEval = array_filter($rows, static fn($r) => $r['state'] === 'active' && $r['fstatus'] === 'not_evaluated');
        $history = array_filter($rows, static fn($r) => !in_array($r['state'], ['active', 'unverified'], true));

        echo '<h3>' . __('Vulnérabilités concernant cet actif', 'vulnwatch') . ' (' . count($active) . ')</h3>';
        if ($active === []) {
            echo "<p class='text-muted'>" . __('Aucune correspondance active. Ce résultat ne vaut que pour la couverture ci-dessous.', 'vulnwatch') . '</p>';
        } else {
            self::findingsTable($active, $canTicket, true);
        }

        if ($notEval !== []) {
            echo '<h4>' . __('Non évalué', 'vulnwatch') . ' (' . count($notEval) . ')</h4>';
            self::findingsTable($notEval, false, false);
        }

        self::coverage($itemtype, $id);

        if ($history !== []) {
            echo '<h4>' . __('Corrections observées et historique', 'vulnwatch') . '</h4>';
            self::findingsTable($history, false, false);
        }
        echo '</div>';
    }

    /** @param array<int,array<string,mixed>> $rows */
    public static function findingsTable(array $rows, bool $withCheckbox, bool $showAsset = false, bool $assetColumn = false): void
    {
        if ($withCheckbox) {
            echo "<form method='post' action='" . Ui::e(Menu::url('campaign.form.php')) . "'>";
        }
        echo "<div class='table-responsive'><table class='table table-sm table-hover align-middle'><thead><tr>";
        if ($withCheckbox) {
            echo '<th></th>';
        }
        if ($assetColumn) {
            echo '<th>' . __('Actif', 'vulnwatch') . '</th><th>' . __('Inventaire', 'vulnwatch') . '</th>';
        }
        echo '<th>CVE</th><th>' . __('Logiciel / version relevée', 'vulnwatch') . '</th><th>' . __('Statut', 'vulnwatch') . '</th><th>' . __('Priorité', 'vulnwatch')
            . '</th><th>' . __('Confiance', 'vulnwatch') . '</th><th>' . __('Corrigé en', 'vulnwatch') . '</th><th>' . __('Pourquoi', 'vulnwatch') . '</th><th>' . __('Suivi', 'vulnwatch') . '</th></tr></thead><tbody>';
        foreach ($rows as $r) {
            echo '<tr>';
            if ($withCheckbox) {
                $ok = $r['state'] === 'active' && in_array($r['fstatus'], ['established', 'to_check'], true);
                echo '<td>' . ($ok ? "<input type='checkbox' class='form-check-input' name='finding_items[]' value='" . (int) $r['id'] . "'>" : '') . '</td>';
            }
            if ($assetColumn) {
                echo '<td>' . Ui::itemLink($r['itemtype'], (int) $r['items_id']) . '</td><td>' . Ui::staleBadge(Inventory::assetState($r['itemtype'], (int) $r['items_id'])['last_inventory_update']) . '</td>';
            }
            echo '<td>' . Ui::cveLink($r['cve_id'], (int) $r['plugin_vulnwatch_cves_id']) . ($r['is_kev'] ? ' ' . Ui::badge('KEV', 'bg-dark') : '') . '</td>';
            echo '<td>' . Ui::e($r['software']) . ' <code>' . Ui::e($r['version_found']) . '</code><div class="small text-muted">'
                . Ui::e(($r['vendor'] ?? '') . ':' . ($r['product'] ?? '')) . ' — association ' . Ui::e($r['mstatus'] ?? '?') . '</div></td>';
            echo '<td>' . Ui::findingBadge($r['fstatus']) . '</td>';
            echo '<td>' . Ui::priorityBadge($r['priority']) . Ui::priorityFactors($r['priority']) . '</td>';
            echo '<td>' . Ui::confidence((int) $r['confidence']) . '</td>';
            echo '<td>' . Ui::e($r['fixed_version'] ?? '—') . ($r['fixed_version'] ? '<div class="small text-muted">source NVD</div>' : '') . '</td>';
            echo '<td><div class="small"><code>' . Ui::e($r['rule_text']) . '</code></div>' . Ui::reasons($r['reasons'])
                . '<div class="small text-muted">' . Ui::e(sprintf('Inventaire du %s, évalué le %s', $r['inventory_date'] ?? '?', $r['date_eval'] ?? '?')) . '</div></td>';
            echo '<td>' . Ui::itemStateBadge($r['state'], (bool) $r['is_regression']) . ($r['fix_detail'] ? '<div class="small">' . Ui::e($r['fix_detail']) . '</div>' : '')
                . ($r['tickets_id'] ? '<div><a href="' . Ui::e(\Ticket::getFormURLWithID((int) $r['tickets_id'])) . '">Ticket #' . (int) $r['tickets_id'] . '</a></div>' : '') . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table></div>';
        if ($withCheckbox) {
            echo Html::submit(__('Créer ou compléter le ticket de campagne', 'vulnwatch'), ['name' => 'add_to_campaign', 'class' => 'btn btn-primary btn-sm']);
            Html::closeForm();
        }
    }

    private static function coverage(string $itemtype, int $id): void
    {
        /** @var \DBmysql $DB */
        global $DB;
        echo '<h4>' . __('Couverture de l\'analyse pour cet actif', 'vulnwatch') . '</h4>';
        if (!in_array($itemtype, Inventory::SOFTWARE_ITEMTYPES, true)) {
            echo "<p class='text-muted'>" . __('Logiciels : non évalués pour ce type d\'actif en V1.', 'vulnwatch') . '</p>';
        } else {
            $mapped = [];
            foreach ($DB->request(['SELECT' => ['name_norm', 'manufacturer_norm', 'status'], 'FROM' => 'glpi_plugin_vulnwatch_mappings']) as $m) {
                $mapped[$m['name_norm'] . '|' . $m['manufacturer_norm']][] = $m['status'];
            }
            $total = 0;
            $unmapped = [];
            foreach ($DB->request([
                'SELECT' => ['glpi_softwares.name', 'glpi_manufacturers.name AS manufacturer', 'glpi_softwareversions.name AS version'],
                'FROM' => 'glpi_items_softwareversions',
                'INNER JOIN' => [
                    'glpi_softwareversions' => ['ON' => ['glpi_items_softwareversions' => 'softwareversions_id', 'glpi_softwareversions' => 'id']],
                    'glpi_softwares' => ['ON' => ['glpi_softwareversions' => 'softwares_id', 'glpi_softwares' => 'id']],
                ],
                'LEFT JOIN' => ['glpi_manufacturers' => ['ON' => ['glpi_softwares' => 'manufacturers_id', 'glpi_manufacturers' => 'id']]],
                'WHERE' => ['glpi_items_softwareversions.itemtype' => $itemtype, 'glpi_items_softwareversions.items_id' => $id, 'glpi_items_softwareversions.is_deleted' => 0],
            ]) as $s) {
                $total++;
                $k = Matching\Normalizer::softwareName((string) $s['name']) . '|' . Matching\Normalizer::manufacturer((string) $s['manufacturer']);
                $st = $mapped[$k] ?? [];
                if ($st === [] || array_diff($st, ['rejected']) === []) {
                    $unmapped[] = $s['name'] . ' ' . $s['version'];
                }
            }
            echo '<p>' . Ui::e(sprintf('%d logiciel(s) inventorié(s), %d rapproché(s) d\'un produit connu des sources, %d non évalué(s) (produit non reconnu ou absent des CVE suivies).',
                $total, $total - count($unmapped), count($unmapped))) . '</p>';
            if ($unmapped !== []) {
                echo "<details><summary class='small'>" . __('Logiciels non évalués', 'vulnwatch') . "</summary><p class='small'>" . Ui::e(implode(', ', array_slice($unmapped, 0, 300))) . '</p></details>';
            }
        }
        $pc = Inventory::platformContext($itemtype, $id);
        $os = $pc['os'] === [] ? 'aucune donnée' : implode(' ; ', array_map(static fn($o) => trim(implode(' ', array_filter([$o['os'], $o['version'], $o['edition'], $o['arch'], $o['servicepack'] ? 'SP ' . $o['servicepack'] : '', $o['kernel'] ? 'noyau/build ' . $o['kernel'] : '']))), $pc['os']));
        $fw = $pc['firmwares'] === [] ? 'aucune donnée' : implode(' ; ', array_map(static fn($f) => trim($f['manufacturer'] . ' ' . $f['designation'] . ' ' . $f['version']), $pc['firmwares']));
        echo "<ul class='small'><li><strong>Système :</strong> " . Ui::e($os) . ' — ' . Ui::badge('Non évalué', 'bg-secondary') . ' ' . Ui::e('builds et correctifs OS : prévu en phase 2 (aucun champ « niveau de correctif » fiable dans l\'inventaire GLPI)') . '</li>';
        echo '<li><strong>BIOS / firmware :</strong> ' . Ui::e($fw) . ' — ' . Ui::badge('Non évalué', 'bg-secondary') . ' ' . Ui::e('prévu en phase 2 (donnée dépendante de l\'agent ou de la collecte SNMP)') . '</li></ul>';
    }

    private static function select(string $name, array $opts, int $value, bool $disabled): string
    {
        $h = "<select class='form-select form-select-sm w-auto' name='" . Ui::e($name) . "'" . ($disabled ? ' disabled' : '') . '>';
        foreach ($opts as $k => $l) {
            $h .= "<option value='" . (int) $k . "'" . ($k === $value ? ' selected' : '') . '>' . Ui::e($l) . '</option>';
        }
        return $h . '</select>';
    }
}
