<?php

namespace GlpiPlugin\Vulnwatch;

use GlpiPlugin\Vulnwatch\Matching\Normalizer;
use GlpiPlugin\Vulnwatch\Matching\VersionComparator;
use Item_Ticket;
use ITILFollowup;
use Session;
use Ticket;

/**
 * Campagnes de correction : un ticket par (entité, produit, version cible).
 * Ré-ajouter des alertes déjà rattachées ne crée ni ticket ni suivi supplémentaire.
 * Le plugin suit les corrections ; il n'installe rien.
 */
final class Campaign
{
    public const TABLE = 'glpi_plugin_vulnwatch_campaigns';

    /**
     * @param list<int> $findingItemIds lignes de glpi_plugin_vulnwatch_findings_items
     * @return array{tickets_created:int, tickets_updated:int, items_added:int, skipped:int, tickets:list<int>, errors:list<string>}
     */
    public static function addFindingItems(array $findingItemIds, bool $auto = false): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $report = ['tickets_created' => 0, 'tickets_updated' => 0, 'items_added' => 0, 'skipped' => 0, 'tickets' => [], 'errors' => []];
        if ($findingItemIds === []) {
            return $report;
        }
        $rows = $DB->request([
            'SELECT' => ['i.id', 'i.itemtype', 'i.items_id', 'i.entities_id', 'i.state', 'i.plugin_vulnwatch_campaigns_id',
                'f.status', 'f.confidence', 'f.version_found', 'f.fixed_version', 'f.rule_text', 'f.reasons', 'f.softwares_id',
                'c.cve_id', 'c.cvss_score', 'c.severity', 'c.is_kev', 'm.vendor', 'm.product', 's.name AS software'],
            'FROM' => 'glpi_plugin_vulnwatch_findings_items AS i',
            'INNER JOIN' => [
                'glpi_plugin_vulnwatch_findings AS f' => ['ON' => ['i' => 'plugin_vulnwatch_findings_id', 'f' => 'id']],
                'glpi_plugin_vulnwatch_cves AS c' => ['ON' => ['i' => 'plugin_vulnwatch_cves_id', 'c' => 'id']],
                'glpi_plugin_vulnwatch_mappings AS m' => ['ON' => ['f' => 'plugin_vulnwatch_mappings_id', 'm' => 'id']],
                'glpi_softwares AS s' => ['ON' => ['f' => 'softwares_id', 's' => 'id']],
            ],
            'WHERE' => ['i.id' => array_map('intval', $findingItemIds), 'i.state' => 'active', 'f.status' => ['established', 'to_check']],
        ]);

        $groups = [];
        foreach ($rows as $r) {
            if (!$auto && !Session::haveAccessToEntity((int) $r['entities_id'])) {
                $report['skipped']++;
                continue; // isolation des entités, même si l'identifiant est forgé
            }
            $productKey = $r['vendor'] . ':' . $r['product'];
            $groups[(int) $r['entities_id'] . '|' . $productKey][] = $r;
        }

        foreach ($groups as $gk => $list) {
            [$entityId, $productKey] = explode('|', $gk, 2);
            $entityId = (int) $entityId;
            $target = self::targetVersion($list, $entityId);
            try {
                $campaign = self::findOpen($entityId, $productKey, $target);
                $new = array_values(array_filter($list, static fn($r) => (int) $r['plugin_vulnwatch_campaigns_id'] === 0
                    || (int) $r['plugin_vulnwatch_campaigns_id'] !== (int) ($campaign['id'] ?? -1)));
                if ($campaign !== null && $new === []) {
                    $report['skipped'] += count($list);
                    continue;
                }
                if ($campaign === null) {
                    $campaign = self::create($entityId, $productKey, $target, $list, $auto);
                    $report['tickets_created']++;
                    $new = $list;
                } else {
                    self::appendFollowup((int) $campaign['tickets_id'], $new, $auto);
                    $report['tickets_updated']++;
                }
                $report['tickets'][] = (int) $campaign['tickets_id'];
                foreach ($new as $r) {
                    $link = new Item_Ticket();
                    if (!$link->getFromDBByCrit(['tickets_id' => $campaign['tickets_id'], 'itemtype' => $r['itemtype'], 'items_id' => $r['items_id']])) {
                        $link->add(['tickets_id' => $campaign['tickets_id'], 'itemtype' => $r['itemtype'], 'items_id' => $r['items_id']]);
                    }
                    $DB->update('glpi_plugin_vulnwatch_findings_items', ['plugin_vulnwatch_campaigns_id' => $campaign['id']], ['id' => $r['id']]);
                    $report['items_added']++;
                }
                Logger::decision($auto ? 'ticket_auto' : 'ticket_manual', 'campaign', (int) $campaign['id'],
                    ['ticket' => (int) $campaign['tickets_id'], 'product' => $productKey, 'target' => $target, 'findings_items' => array_column($new, 'id')], $entityId);
            } catch (\Throwable $e) {
                $report['errors'][] = $productKey . ' : ' . $e->getMessage();
                Logger::log('Campagne ' . $gk . ' : ' . $e->getMessage());
            }
        }
        $report['tickets'] = array_values(array_unique($report['tickets']));
        return $report;
    }

    /** Version cible : celle approuvée pour l'entité si elle existe, sinon la plus haute version corrigée connue. */
    private static function targetVersion(array $list, int $entityId): string
    {
        $t = Target::findFor((string) $list[0]['software'], $entityId);
        if ($t !== null && $t['target_version'] !== null && $t['target_version'] !== '') {
            return (string) $t['target_version'];
        }
        $best = '';
        foreach ($list as $r) {
            $fv = (string) ($r['fixed_version'] ?? '');
            if ($fv === '' || str_starts_with($fv, '>')) {
                continue;
            }
            if ($best === '' || (VersionComparator::compare($fv, $best) ?? 0) > 0) {
                $best = $fv;
            }
        }
        return $best;
    }

    private static function findOpen(int $entityId, string $productKey, string $target): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;
        foreach ($DB->request(['FROM' => self::TABLE, 'WHERE' => ['entities_id' => $entityId, 'product_key' => $productKey, 'target_version' => $target, 'is_open' => 1]]) as $c) {
            $t = new Ticket();
            if ($t->getFromDB((int) $c['tickets_id']) && !$t->fields['is_deleted'] && !in_array((int) $t->fields['status'], [Ticket::SOLVED, Ticket::CLOSED], true)) {
                return $c;
            }
            $DB->update(self::TABLE, ['is_open' => 0, 'date_mod' => date('Y-m-d H:i:s')], ['id' => $c['id']]);
        }
        return null;
    }

    private static function create(int $entityId, string $productKey, string $target, array $list, bool $auto): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $software = (string) $list[0]['software'];
        $name = sprintf('[Vulnérabilités] %s%s — %d actif(s)', $software, $target !== '' ? ' → ' . $target : '', count(array_unique(array_map(static fn($r) => $r['itemtype'] . $r['items_id'], $list))));
        $ticket = new Ticket();
        $input = [
            'name'        => mb_substr($name, 0, 255),
            'content'     => self::renderContent($list, $target, true),
            'entities_id' => $entityId,
            'type'        => Ticket::DEMAND_TYPE,
            'urgency'     => self::urgency($list),
            '_disablenotif' => $auto,
        ];
        $id = $ticket->add($input);
        if (!$id) {
            throw new \RuntimeException('Création du ticket refusée par GLPI');
        }
        $now = date('Y-m-d H:i:s');
        $DB->insert(self::TABLE, ['entities_id' => $entityId, 'name' => mb_substr($name, 0, 255), 'product_key' => $productKey, 'target_version' => $target,
            'tickets_id' => $id, 'is_open' => 1, 'is_auto' => $auto ? 1 : 0, 'users_id' => (int) Session::getLoginUserID(), 'date_creation' => $now, 'date_mod' => $now]);
        return ['id' => (int) $DB->insertId(), 'tickets_id' => (int) $id];
    }

    private static function appendFollowup(int $ticketId, array $new, bool $auto): void
    {
        $fu = new ITILFollowup();
        $fu->add(['itemtype' => Ticket::class, 'items_id' => $ticketId, 'is_private' => 0,
            'content' => '<p>VulnWatch : nouveaux éléments rattachés à cette campagne.</p>' . self::renderContent($new, null, false), '_disablenotif' => $auto]);
    }

    private static function urgency(array $list): int
    {
        $max = 0;
        foreach ($list as $r) {
            $max = max($max, (float) ($r['cvss_score'] ?? 0) + (!empty($r['is_kev']) ? 3 : 0));
        }
        return $max >= 9 ? 5 : ($max >= 7 ? 4 : ($max >= 4 ? 3 : 2));
    }

    private static function renderContent(array $list, ?string $target, bool $intro): string
    {
        $h = static fn($s) => htmlescape((string) $s);
        $out = '';
        if ($intro) {
            $out .= '<p>Campagne de correction générée par VulnWatch à partir de l\'inventaire GLPI. Le plugin ne réalise aucune installation : '
                . 'la correction est vérifiée au prochain inventaire de chaque actif.</p>';
            $out .= '<p><strong>Correction proposée :</strong> ' . ($target !== null && $target !== '' ? 'mettre à jour vers ' . $h($target) . ' ou ultérieure (version cible)' : 'version corrigée non publiée par la source — voir les bulletins') . '</p>';
        }
        $out .= '<table border="1" cellpadding="3"><tr><th>Actif</th><th>CVE</th><th>Version relevée</th><th>Corrigée en</th><th>Statut / confiance</th><th>Raison</th></tr>';
        foreach ($list as $r) {
            $reasons = json_decode((string) $r['reasons'], true) ?: [];
            $out .= '<tr><td>' . $h($r['itemtype'] . ' #' . $r['items_id'] . ' ' . self::assetName($r['itemtype'], (int) $r['items_id'])) . '</td>'
                . '<td>' . $h($r['cve_id']) . (!empty($r['is_kev']) ? ' (KEV)' : '') . '</td><td>' . $h($r['version_found']) . '</td>'
                . '<td>' . $h($r['fixed_version'] ?? '?') . '</td><td>' . $h(($r['status'] === 'established' ? 'Correspondance établie' : 'À vérifier') . ' / ' . $r['confidence'] . ' %') . '</td>'
                . '<td>' . $h($r['rule_text'] . ' — ' . implode(' ; ', $reasons)) . '</td></tr>';
        }
        return $out . '</table>';
    }

    private static function assetName(string $itemtype, int $id): string
    {
        $item = getItemForItemtype($itemtype);
        return ($item && $item->getFromDB($id)) ? (string) $item->fields['name'] : '';
    }

    /** Mode automatique : uniquement les entités qui l'ont activé, uniquement les correspondances fiables. */
    public static function runAutomatic(): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $total = ['tickets_created' => 0, 'tickets_updated' => 0, 'items_added' => 0, 'skipped' => 0, 'tickets' => [], 'errors' => []];
        foreach ($DB->request(['FROM' => 'glpi_plugin_vulnwatch_entityconfigs', 'WHERE' => ['auto_ticket' => 1]]) as $cfg) {
            $ids = [];
            foreach ($DB->request([
                'SELECT' => ['i.id', 'i.itemtype', 'i.items_id', 'c.cvss_score', 'c.cvss_version', 'c.severity', 'c.is_kev', 'c.kev_due_date', 'c.epss_score'],
                'FROM' => 'glpi_plugin_vulnwatch_findings_items AS i',
                'INNER JOIN' => [
                    'glpi_plugin_vulnwatch_findings AS f' => ['ON' => ['i' => 'plugin_vulnwatch_findings_id', 'f' => 'id']],
                    'glpi_plugin_vulnwatch_cves AS c' => ['ON' => ['i' => 'plugin_vulnwatch_cves_id', 'c' => 'id']],
                ],
                'WHERE' => ['i.entities_id' => (int) $cfg['entities_id'], 'i.state' => 'active', 'i.plugin_vulnwatch_campaigns_id' => 0,
                    'f.status' => 'established', 'f.confidence' => ['>=', (int) $cfg['auto_min_confidence']]],
            ]) as $r) {
                if (Inventory::isStale(Inventory::assetState($r['itemtype'], (int) $r['items_id'])['last_inventory_update'])) {
                    continue;
                }
                $p = Priority::compute($r, Priority::assetContext($r['itemtype'], (int) $r['items_id']));
                if ($p['score'] >= (int) $cfg['auto_min_priority']) {
                    $ids[] = (int) $r['id'];
                }
            }
            $rep = self::addFindingItems($ids, true);
            foreach (['tickets_created', 'tickets_updated', 'items_added', 'skipped'] as $k) {
                $total[$k] += $rep[$k];
            }
            $total['tickets'] = array_merge($total['tickets'], $rep['tickets']);
            $total['errors'] = array_merge($total['errors'], $rep['errors']);
        }
        return $total;
    }

    public static function normalizeKey(string $software): string
    {
        return Normalizer::softwareName($software);
    }
}
