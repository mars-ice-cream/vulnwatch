<?php

namespace GlpiPlugin\Vulnwatch;

use Html;

/**
 * Vue principale : une entrée par CVE, et à l'intérieur tous les actifs concernés.
 * Les CVE sont triées par priorité (la plus haute de leurs actifs), puis par nombre d'actifs.
 */
final class CveView
{
    /**
     * @param list<array<string,mixed>> $rows lignes de Report::items()
     */
    public static function render(array $rows, bool $canTicket, int $openFirst = 3, ?int $limit = null): void
    {
        $groups = self::group($rows);
        if ($groups === []) {
            echo "<p class='text-muted'>" . __('Aucun actif concerné dans votre périmètre. Une absence de résultat ne prouve pas l\'absence de vulnérabilité : voir la couverture.', 'vulnwatch') . '</p>';
            return;
        }
        $total = count($groups);
        if ($limit !== null) {
            $groups = array_slice($groups, 0, $limit);
        }
        if ($canTicket) {
            echo "<form method='post' action='" . Ui::e(Menu::url('campaign.form.php')) . "'>";
        }
        foreach ($groups as $n => $g) {
            self::renderGroup($g, $canTicket, $n < $openFirst);
        }
        if ($limit !== null && $total > $limit) {
            echo "<p><a href='" . Ui::e(Menu::url('cve.php')) . "'>" . Ui::e(sprintf(__('Voir les %d CVE', 'vulnwatch'), $total)) . '</a></p>';
        }
        if ($canTicket) {
            echo "<div class='sticky-bottom bg-body py-2'>" . Html::submit(__('Créer ou compléter le ticket de campagne pour les actifs cochés', 'vulnwatch'), ['name' => 'add_to_campaign', 'class' => 'btn btn-primary'])
                . " <span class='small text-muted'>" . __('Un ticket par client et par logiciel ; jamais de ticket créé automatiquement.', 'vulnwatch') . '</span></div>';
            Html::closeForm();
        }
    }

    /** @return list<array<string,mixed>> */
    public static function group(array $rows): array
    {
        $groups = [];
        foreach ($rows as $r) {
            if (!in_array($r['state'], ['active', 'unverified'], true)) {
                continue;
            }
            $k = (int) $r['plugin_vulnwatch_cves_id'];
            $g = &$groups[$k];
            $g ??= ['cve' => $r, 'rows' => [], 'max' => $r['priority'], 'count' => ['established' => 0, 'to_check' => 0, 'not_evaluated' => 0],
                'assets' => [], 'software' => [], 'fixed' => [], 'stale' => 0];
            $g['rows'][] = $r;
            if ($r['priority']['score'] > $g['max']['score']) {
                $g['max'] = $r['priority'];
            }
            if (isset($g['count'][$r['fstatus']])) {
                $g['count'][$r['fstatus']]++;
            }
            $g['assets'][$r['itemtype'] . $r['items_id']] = true;
            $g['software'][$r['software'] . ' ' . $r['version_found']] = true;
            if (!empty($r['fixed_version'])) {
                $g['fixed'][$r['fixed_version']] = true;
            }
            unset($g);
        }
        $groups = array_values($groups);
        usort($groups, static fn($a, $b) => [$b['max']['score'], count($b['assets'])] <=> [$a['max']['score'], count($a['assets'])]);
        return $groups;
    }

    private static function renderGroup(array $g, bool $canTicket, bool $open): void
    {
        $c = $g['cve'];
        $id = 'vwcve' . (int) $c['plugin_vulnwatch_cves_id'];
        $summary = [];
        foreach (['established' => 'établi(s)', 'to_check' => 'à vérifier', 'not_evaluated' => 'non évalué(s)'] as $st => $label) {
            if ($g['count'][$st] > 0) {
                $summary[] = $g['count'][$st] . ' ' . $label;
            }
        }
        echo "<details class='card mb-2' id='" . $id . "'" . ($open ? ' open' : '') . '>';
        echo "<summary class='card-header d-flex flex-wrap align-items-center gap-2' style='cursor:pointer;list-style:none'>";
        echo Ui::priorityBadge($g['max']);
        echo "<strong class='fs-3'>" . Ui::cveLink($c['cve_id'], (int) $c['plugin_vulnwatch_cves_id']) . '</strong>';
        if ($c['is_kev']) {
            echo Ui::badge('Exploitée (KEV)', 'bg-dark');
        }
        echo "<span class='text-muted'>" . Ui::e($c['cvss_score'] !== null ? 'CVSS ' . $c['cvss_score'] . ' · ' . Cve::severityLabel($c['severity']) : 'CVSS inconnu') . '</span>';
        echo '<span>' . Ui::e(implode(', ', array_keys($g['software']))) . '</span>';
        echo "<span class='ms-auto'><strong>" . count($g['assets']) . ' actif(s)</strong> — ' . Ui::e(implode(', ', $summary))
            . ($g['fixed'] !== [] ? ' — corrigé en ' . Ui::e(implode(', ', array_keys($g['fixed']))) : '') . '</span>';
        echo '</summary>';

        echo "<div class='card-body p-0'><div class='table-responsive'><table class='table table-sm table-hover align-middle mb-0'><thead><tr>";
        if ($canTicket) {
            echo "<th><input type='checkbox' class='form-check-input' title='Tout cocher' onclick=\"document.querySelectorAll('#" . $id . " input[name=&quot;finding_items[]&quot;]').forEach(c=>c.checked=this.checked)\"></th>";
        }
        echo '<th>Actif</th><th>Client</th><th>Dernier inventaire</th><th>Logiciel / version</th><th>Statut</th><th>Confiance</th><th>Pourquoi</th><th>Suivi</th></tr></thead><tbody>';
        usort($g['rows'], static fn($a, $b) => [$b['priority']['score'], $b['confidence']] <=> [$a['priority']['score'], $a['confidence']]);
        foreach ($g['rows'] as $r) {
            $inv = Inventory::assetState($r['itemtype'], (int) $r['items_id'])['last_inventory_update'];
            echo '<tr>';
            if ($canTicket) {
                $ok = $r['state'] === 'active' && in_array($r['fstatus'], ['established', 'to_check'], true);
                echo '<td>' . ($ok ? "<input type='checkbox' class='form-check-input' name='finding_items[]' value='" . (int) $r['id'] . "'>" : '') . '</td>';
            }
            $reasons = json_decode((string) $r['reasons'], true) ?: [];
            echo '<td>' . Ui::itemLink($r['itemtype'], (int) $r['items_id']) . '</td>'
                . '<td class="small">' . Ui::e(\Dropdown::getDropdownName('glpi_entities', (int) $r['entities_id'])) . '</td>'
                . '<td>' . Ui::staleBadge($inv) . '</td>'
                . '<td>' . Ui::e($r['software']) . ' <code>' . Ui::e($r['version_found']) . '</code></td>'
                . '<td>' . Ui::findingBadge($r['fstatus']) . '</td>'
                . '<td>' . Ui::confidence((int) $r['confidence']) . '</td>'
                . "<td class='small' title='" . Ui::e($r['rule_text']) . "'>" . Ui::e(implode(' ; ', $reasons)) . '</td>'
                . '<td>' . Ui::itemStateBadge($r['state'], (bool) $r['is_regression'])
                . ($r['tickets_id'] ? ' <a href="' . Ui::e(\Ticket::getFormURLWithID((int) $r['tickets_id'])) . '">#' . (int) $r['tickets_id'] . '</a>' : '') . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table></div></div></details>';
    }
}
