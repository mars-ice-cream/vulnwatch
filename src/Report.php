<?php

namespace GlpiPlugin\Vulnwatch;

/**
 * Requêtes de restitution. Toutes appliquent la restriction d'entités de la session :
 * listes, fiches, compteurs et exports passent par ici.
 */
final class Report
{
    /** @return list<array<string,mixed>> */
    public static function items(array $where = [], int $limit = 2000, bool $restrict = true): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        if ($restrict) {
            $where[] = Ui::entityCriteria('i');
        }
        $rows = $DB->request([
            'SELECT' => [
                'i.*', 'f.status AS fstatus', 'f.confidence', 'f.version_found', 'f.fixed_version', 'f.rule_text', 'f.reasons', 'f.softwares_id', 'f.softwareversions_id',
                'f.date_eval', 'c.cve_id', 'c.cvss_score', 'c.cvss_version', 'c.severity', 'c.is_kev', 'c.kev_due_date', 'c.epss_score', 'c.description',
                's.name AS software', 'm.vendor', 'm.product', 'm.status AS mstatus', 'ctx.criticality', 'ctx.exposure', 'camp.tickets_id',
            ],
            'FROM' => 'glpi_plugin_vulnwatch_findings_items AS i',
            'INNER JOIN' => [
                'glpi_plugin_vulnwatch_findings AS f' => ['ON' => ['i' => 'plugin_vulnwatch_findings_id', 'f' => 'id']],
                'glpi_plugin_vulnwatch_cves AS c' => ['ON' => ['i' => 'plugin_vulnwatch_cves_id', 'c' => 'id']],
            ],
            'LEFT JOIN' => [
                'glpi_softwares AS s' => ['ON' => ['f' => 'softwares_id', 's' => 'id']],
                'glpi_plugin_vulnwatch_mappings AS m' => ['ON' => ['f' => 'plugin_vulnwatch_mappings_id', 'm' => 'id']],
                'glpi_plugin_vulnwatch_assetcontexts AS ctx' => ['ON' => ['ctx' => 'items_id', 'i' => 'items_id', ['AND' => ['ctx.itemtype' => new \Glpi\DBAL\QueryExpression($DB->quoteName('i.itemtype'))]]]],
                'glpi_plugin_vulnwatch_campaigns AS camp' => ['ON' => ['i' => 'plugin_vulnwatch_campaigns_id', 'camp' => 'id']],
            ],
            'WHERE' => $where,
            'LIMIT' => $limit,
        ]);
        $out = [];
        foreach ($rows as $r) {
            $r['priority'] = Priority::compute($r, ['criticality' => (int) ($r['criticality'] ?? 0), 'exposure' => (int) ($r['exposure'] ?? 0)]);
            $out[] = $r;
        }
        usort($out, static fn($a, $b) => [$b['priority']['score'], $b['confidence']] <=> [$a['priority']['score'], $a['confidence']]);
        return $out;
    }

    /** Compteurs par entité visible. @return array<int,array<string,int>> */
    public static function countsByEntity(): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $out = [];
        $rows = $DB->request([
            'SELECT' => ['i.entities_id', 'i.state', 'f.status', 'i.is_regression', 'COUNT' => 'i.id AS n'],
            'FROM' => 'glpi_plugin_vulnwatch_findings_items AS i',
            'INNER JOIN' => ['glpi_plugin_vulnwatch_findings AS f' => ['ON' => ['i' => 'plugin_vulnwatch_findings_id', 'f' => 'id']]],
            'WHERE' => [Ui::entityCriteria('i')],
            'GROUPBY' => ['i.entities_id', 'i.state', 'f.status', 'i.is_regression'],
        ]);
        foreach ($rows as $r) {
            $e = (int) $r['entities_id'];
            $out[$e] ??= ['established' => 0, 'to_check' => 0, 'not_evaluated' => 0, 'fixed' => 0, 'unverified' => 0, 'regressions' => 0, 'closed' => 0];
            if ($r['state'] === 'active') {
                if (isset($out[$e][$r['status']])) {
                    $out[$e][$r['status']] += (int) $r['n'];
                }
                if ($r['is_regression']) {
                    $out[$e]['regressions'] += (int) $r['n'];
                }
            } elseif (isset($out[$e][$r['state']])) {
                $out[$e][$r['state']] += (int) $r['n'];
            } else {
                $out[$e]['closed'] += (int) $r['n'];
            }
        }
        return $out;
    }

    /**
     * Couverture réelle de l'analyse, restreinte aux entités visibles.
     * @return array{installed:int, mapped:int, unmapped:int, no_version:int, assets:int, stale_assets:int, never_inventoried:int}
     */
    public static function coverage(): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $mapped = [];
        foreach ($DB->request(['SELECT' => ['name_norm', 'manufacturer_norm'], 'FROM' => 'glpi_plugin_vulnwatch_mappings', 'WHERE' => ['NOT' => ['status' => 'rejected']]]) as $m) {
            $mapped[$m['name_norm'] . '|' . $m['manufacturer_norm']] = true;
        }
        $res = ['installed' => 0, 'mapped' => 0, 'unmapped' => 0, 'no_version' => 0, 'assets' => 0, 'stale_assets' => 0, 'never_inventoried' => 0];
        $rows = $DB->request([
            'SELECT' => ['glpi_softwares.name', 'glpi_manufacturers.name AS manufacturer', 'glpi_softwareversions.name AS version'],
            'DISTINCT' => true,
            'FROM' => 'glpi_items_softwareversions',
            'INNER JOIN' => [
                'glpi_softwareversions' => ['ON' => ['glpi_items_softwareversions' => 'softwareversions_id', 'glpi_softwareversions' => 'id']],
                'glpi_softwares' => ['ON' => ['glpi_softwareversions' => 'softwares_id', 'glpi_softwares' => 'id']],
            ],
            'LEFT JOIN' => ['glpi_manufacturers' => ['ON' => ['glpi_softwares' => 'manufacturers_id', 'glpi_manufacturers' => 'id']]],
            'WHERE' => Inventory::activeLinkCriteria() + [Ui::entityCriteria('glpi_items_softwareversions')],
        ]);
        foreach ($rows as $r) {
            $res['installed']++;
            $k = Matching\Normalizer::softwareName((string) $r['name']) . '|' . Matching\Normalizer::manufacturer((string) $r['manufacturer']);
            isset($mapped[$k]) ? $res['mapped']++ : $res['unmapped']++;
            if (!Matching\VersionComparator::isComparable((string) $r['version'])) {
                $res['no_version']++;
            }
        }
        foreach (Inventory::SOFTWARE_ITEMTYPES as $it) {
            $t = getTableForItemType($it);
            foreach ($DB->request(['SELECT' => ['last_inventory_update'], 'FROM' => $t, 'WHERE' => ['is_deleted' => 0, 'is_template' => 0, Ui::entityCriteria($t)]]) as $a) {
                $res['assets']++;
                if ($a['last_inventory_update'] === null) {
                    $res['never_inventoried']++;
                } elseif (Inventory::isStale($a['last_inventory_update'])) {
                    $res['stale_assets']++;
                }
            }
        }
        return $res;
    }
}
