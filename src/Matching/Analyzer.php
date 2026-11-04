<?php

namespace GlpiPlugin\Vulnwatch\Matching;

use GlpiPlugin\Vulnwatch\Config;
use GlpiPlugin\Vulnwatch\Inventory;
use GlpiPlugin\Vulnwatch\Logger;

/**
 * Rapprochement local inventaire ↔ critères d'applicabilité, puis suivi des corrections.
 *
 * 1. regroupe les logiciels installés par (nom normalisé, éditeur normalisé) ;
 * 2. met à jour les associations vers les produits CPE connus (sans écraser une décision manuelle) ;
 * 3. évalue chaque couple (CVE, version logicielle) une seule fois, quel que soit le nombre d'actifs ;
 * 4. rattache le résultat aux actifs et suit corrections, régressions et inventaires anciens.
 *
 * Aucune donnée d'inventaire ne sort de GLPI.
 */
final class Analyzer
{
    public const T_MAPPINGS = 'glpi_plugin_vulnwatch_mappings';
    public const T_FINDINGS = 'glpi_plugin_vulnwatch_findings';
    public const T_ITEMS    = 'glpi_plugin_vulnwatch_findings_items';
    public const T_CRITERIA = 'glpi_plugin_vulnwatch_criteria';

    /** @var array<string,int> */
    private array $stats = ['versions' => 0, 'mappings' => 0, 'evaluations' => 0, 'cache_hits' => 0, 'findings' => 0,
        'attached' => 0, 'fixed' => 0, 'unverified' => 0, 'regressions' => 0, 'closed' => 0];

    private string $now;

    public function __construct()
    {
        $this->now = date('Y-m-d H:i:s');
    }

    /** @return array<string,int> */
    public function run(): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $installed = Inventory::installedSoftwareVersions();
        $this->stats['versions'] = count($installed);

        // Produits connus (cités par au moins un critère vulnérable)
        $productsByToken = [];
        $knownProducts = [];
        foreach ($DB->request(['SELECT' => ['vendor', 'product'], 'DISTINCT' => true, 'FROM' => self::T_CRITERIA, 'WHERE' => ['part' => 'a']]) as $r) {
            $vp = $r['vendor'] . ':' . $r['product'];
            $tok = Normalizer::cpeToken($r['product']);
            $productsByToken[$tok][] = $vp;
            $knownProducts[$vp] = Normalizer::tokens($tok);
        }

        // 1. groupes de logiciels
        $groups = [];
        foreach ($installed as $sv) {
            $key = Normalizer::softwareName($sv['name']) . '|' . Normalizer::manufacturer($sv['manufacturer']);
            $groups[$key]['sample'] ??= $sv;
            $groups[$key]['versions'][$sv['softwareversions_id']] = $sv;
        }

        // Contexte OS par version (pour target_sw)
        $allVersionIds = array_map(static fn($s) => $s['softwareversions_id'], $installed);
        $links = Inventory::linksForVersions($allVersionIds);
        $osByVersion = [];
        $linksByVersion = [];
        foreach ($links as $l) {
            $osByVersion[$l['softwareversions_id']][Evaluator::osFamily($l['os'])] = true;
            $linksByVersion[$l['softwareversions_id']][] = $l;
        }

        $touchedFindings = [];
        $evalCache = [];
        $criteriaCache = [];
        foreach ($groups as $key => $group) {
            [$nameNorm, $manufNorm] = explode('|', $key, 2);
            $mappings = $this->syncMappings($nameNorm, $manufNorm, $group['sample'], $productsByToken, $knownProducts);
            // Résultats de TOUTES les associations du groupe, combinés par (CVE, version) avant l'écriture :
            // une association ne doit pas écraser le résultat d'une autre.
            $pending = [];
            foreach ($mappings as $m) {
                if ($m['status'] === 'rejected') {
                    continue;
                }
                $vp = $m['vendor'] . ':' . $m['product'];
                $criteriaCache[$vp] ??= iterator_to_array($DB->request(['FROM' => self::T_CRITERIA, 'WHERE' => ['vendor' => $m['vendor'], 'product' => $m['product'], 'part' => 'a', 'is_vulnerable' => 1]]), false);
                foreach ($group['versions'] as $svid => $sv) {
                    $families = array_keys($osByVersion[$svid] ?? []);
                    sort($families);
                    foreach ($criteriaCache[$vp] as $c) {
                        $ck = $c['id'] . '|' . $sv['version'] . '|' . implode(',', $families) . '|' . $m['status'] . $m['confidence'];
                        if (isset($evalCache[$ck])) {
                            $this->stats['cache_hits']++;
                        } else {
                            $evalCache[$ck] = Evaluator::evaluate($c, $sv['version'], $m, ['os_families' => $families, 'arch' => $sv['arch']]) + ['criteria_id' => (int) $c['id']];
                            $this->stats['evaluations']++;
                        }
                        $pending[$svid][(int) $c['plugin_vulnwatch_cves_id']][] = $evalCache[$ck] + ['mapping_id' => (int) $m['id']];
                    }
                }
            }
            foreach ($pending as $svid => $byCve) {
                foreach ($byCve as $cvePk => $results) {
                    $best = Evaluator::combine($results);
                    $fid = $this->upsertFinding($cvePk, $group['versions'][$svid], $best['mapping_id'], $best);
                    $touchedFindings[$fid] = true;
                }
            }
        }

        // Résultats plus produits par l'analyse : association rejetée ou critère retiré par la source
        $this->closeUntouchedFindings($touchedFindings, $allVersionIds);

        // 2. rattachement aux actifs et suivi des corrections
        $this->attachAndTrack($linksByVersion);

        Logger::log('Analyse : ' . json_encode($this->stats));
        return $this->stats;
    }

    /** @return list<array<string,mixed>> mappings applicables (y compris rejetés, filtrés ensuite) */
    private function syncMappings(string $nameNorm, string $manufNorm, array $sample, array $productsByToken, array $knownProducts): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $existing = [];
        foreach ($DB->request(['FROM' => self::T_MAPPINGS, 'WHERE' => ['name_norm' => $nameNorm, 'manufacturer_norm' => $manufNorm]]) as $r) {
            $existing[$r['vendor'] . ':' . $r['product']] = $r;
        }
        foreach (Mapper::candidates($nameNorm, $manufNorm, $productsByToken, $knownProducts) as $c) {
            $vp = $c['vendor'] . ':' . $c['product'];
            if (isset($existing[$vp])) {
                $row = $existing[$vp];
                if (in_array($row['status'], ['validated', 'rejected'], true)) {
                    continue; // décision manuelle réutilisée telle quelle
                }
                if ($row['status'] !== $c['status'] || (int) $row['confidence'] !== $c['confidence']) {
                    $DB->update(self::T_MAPPINGS, ['status' => $c['status'], 'confidence' => $c['confidence'], 'reason' => $c['reason'], 'date_mod' => $this->now], ['id' => $row['id']]);
                    $existing[$vp] = array_merge($row, $c);
                }
                continue;
            }
            $DB->insert(self::T_MAPPINGS, [
                'name_norm' => $nameNorm, 'manufacturer_norm' => $manufNorm,
                'sample_name' => mb_substr($sample['name'], 0, 255), 'sample_manufacturer' => mb_substr($sample['manufacturer'], 0, 255),
                'vendor' => $c['vendor'], 'product' => $c['product'], 'status' => $c['status'], 'confidence' => $c['confidence'],
                'reason' => mb_substr($c['reason'], 0, 512), 'date_creation' => $this->now, 'date_mod' => $this->now,
            ]);
            $existing[$vp] = ['id' => (int) $DB->insertId()] + $c + ['name_norm' => $nameNorm];
            $this->stats['mappings']++;
        }
        return array_values($existing);
    }

    private function upsertFinding(int $cvePk, array $sv, int $mappingId, array $r): int
    {
        /** @var \DBmysql $DB */
        global $DB;
        $fields = [
            'softwares_id' => $sv['softwares_id'],
            'plugin_vulnwatch_mappings_id' => $mappingId,
            'plugin_vulnwatch_criteria_id' => $r['criteria_id'],
            'status' => $r['status'],
            'confidence' => $r['confidence'],
            'version_found' => mb_substr($sv['version'], 0, 255),
            'fixed_version' => $r['fixed_version'] !== null ? mb_substr($r['fixed_version'], 0, 128) : null,
            'rule_text' => $r['rule_text'],
            'reasons' => json_encode($r['reasons'], JSON_UNESCAPED_UNICODE),
            'date_eval' => $this->now,
        ];
        $fields['eval_hash'] = hash('sha256', $fields['status'] . $fields['confidence'] . $fields['rule_text'] . $fields['reasons'] . $mappingId);
        $row = $DB->request(['SELECT' => ['id', 'eval_hash'], 'FROM' => self::T_FINDINGS,
            'WHERE' => ['plugin_vulnwatch_cves_id' => $cvePk, 'softwareversions_id' => $sv['softwareversions_id']]])->current();
        if ($row) {
            if ($row['eval_hash'] !== $fields['eval_hash']) {
                $DB->update(self::T_FINDINGS, $fields, ['id' => $row['id']]);
            } else {
                $DB->update(self::T_FINDINGS, ['date_eval' => $this->now], ['id' => $row['id']]);
            }
            return (int) $row['id'];
        }
        $DB->insert(self::T_FINDINGS, $fields + ['plugin_vulnwatch_cves_id' => $cvePk, 'softwareversions_id' => $sv['softwareversions_id'], 'date_first_seen' => $this->now]);
        $this->stats['findings']++;
        return (int) $DB->insertId();
    }

    /** @param array<int,bool> $touched */
    private function closeUntouchedFindings(array $touched, array $installedVersionIds): void
    {
        /** @var \DBmysql $DB */
        global $DB;
        $installed = array_flip($installedVersionIds);
        foreach ($DB->request(['SELECT' => ['f.id', 'f.softwareversions_id', 'f.status', 'm.status AS mstatus'], 'FROM' => self::T_FINDINGS . ' AS f',
            'LEFT JOIN' => [self::T_MAPPINGS . ' AS m' => ['ON' => ['f' => 'plugin_vulnwatch_mappings_id', 'm' => 'id']]],
            'WHERE' => ['NOT' => ['f.status' => ['not_affected', 'rejected']]]]) as $f) {
            if (isset($touched[$f['id']])) {
                continue;
            }
            if (($f['mstatus'] ?? null) === 'rejected' || $f['mstatus'] === null) {
                $DB->update(self::T_FINDINGS, ['status' => 'rejected', 'date_eval' => $this->now,
                    'reasons' => json_encode(['Association logiciel → produit rejetée par un administrateur'], JSON_UNESCAPED_UNICODE)], ['id' => $f['id']]);
            } elseif (isset($installed[$f['softwareversions_id']])) {
                // Version toujours installée mais plus couverte par aucun critère : la source a changé
                $DB->update(self::T_FINDINGS, ['status' => 'not_affected', 'date_eval' => $this->now,
                    'reasons' => json_encode(['Plus aucun critère de la source ne couvre cette version (mise à jour de la source)'], JSON_UNESCAPED_UNICODE)], ['id' => $f['id']]);
            }
            // Version plus installée nulle part : le résultat est conservé, le suivi par actif décide
        }
    }

    /** @param array<int, list<array<string,mixed>>> $linksByVersion */
    private function attachAndTrack(array $linksByVersion): void
    {
        /** @var \DBmysql $DB */
        global $DB;
        $seen = [];
        $findings = $DB->request(['SELECT' => ['id', 'plugin_vulnwatch_cves_id', 'softwareversions_id', 'softwares_id', 'status'], 'FROM' => self::T_FINDINGS,
            'WHERE' => ['status' => ['established', 'to_check', 'not_evaluated']]]);
        foreach ($findings as $f) {
            foreach ($linksByVersion[$f['softwareversions_id']] ?? [] as $l) {
                $key = ['plugin_vulnwatch_findings_id' => $f['id'], 'itemtype' => $l['itemtype'], 'items_id' => $l['items_id']];
                $row = $DB->request(['FROM' => self::T_ITEMS, 'WHERE' => $key])->current();
                $data = ['entities_id' => $l['entities_id'], 'inventory_date' => $l['last_inventory_update'], 'date_last_seen' => $this->now,
                    'plugin_vulnwatch_cves_id' => $f['plugin_vulnwatch_cves_id']];
                if (!$row) {
                    // Même CVE déjà corrigée sur cet actif (autre version / logiciel recréé) : régression
                    $wasFixed = $f['status'] !== 'not_evaluated' && (int) $DB->request(['COUNT' => 'c', 'FROM' => self::T_ITEMS, 'WHERE' => [
                        'plugin_vulnwatch_cves_id' => $f['plugin_vulnwatch_cves_id'], 'itemtype' => $l['itemtype'], 'items_id' => $l['items_id'], 'state' => 'fixed']])->current()['c'] > 0;
                    if ($wasFixed) {
                        $data['is_regression'] = 1;
                        $this->stats['regressions']++;
                        Logger::log(sprintf('Régression : %s #%d, CVE #%d', $l['itemtype'], $l['items_id'], $f['plugin_vulnwatch_cves_id']));
                    }
                    $DB->insert(self::T_ITEMS, $key + $data + ['state' => 'active', 'date_first_seen' => $this->now]);
                    $this->stats['attached']++;
                    $seen[(int) $DB->insertId()] = true;
                    continue;
                }
                if ($row['state'] !== 'active') {
                    $data['state'] = 'active';
                    $data['fix_kind'] = null;
                    $data['fix_detail'] = null;
                    $data['date_fixed'] = null;
                    if ($row['state'] === 'fixed' && $f['status'] !== 'not_evaluated') {
                        $data['is_regression'] = 1;
                        $this->stats['regressions']++;
                        Logger::log(sprintf('Régression : %s #%d, résultat #%d', $l['itemtype'], $l['items_id'], $f['id']));
                    }
                }
                $DB->update(self::T_ITEMS, $data, ['id' => $row['id']]);
                $seen[(int) $row['id']] = true;
            }
        }

        // Rattachements actifs non revus : déterminer pourquoi
        foreach ($DB->request(['SELECT' => ['i.*', 'f.status AS fstatus', 'f.softwares_id', 'f.softwareversions_id', 'f.version_found', 'm.name_norm', 'm.manufacturer_norm'],
            'FROM' => self::T_ITEMS . ' AS i', 'INNER JOIN' => [self::T_FINDINGS . ' AS f' => ['ON' => ['i' => 'plugin_vulnwatch_findings_id', 'f' => 'id']]],
            'LEFT JOIN' => [self::T_MAPPINGS . ' AS m' => ['ON' => ['f' => 'plugin_vulnwatch_mappings_id', 'm' => 'id']]],
            'WHERE' => ['i.state' => ['active', 'unverified']]]) as $i) {
            if (isset($seen[$i['id']])) {
                continue;
            }
            $upd = $this->decideDisappeared($i);
            $DB->update(self::T_ITEMS, $upd, ['id' => $i['id']]);
        }
    }

    /** @return array<string,mixed> */
    private function decideDisappeared(array $i): array
    {
        if ($i['fstatus'] === 'not_affected') {
            $this->stats['closed']++;
            return ['state' => 'closed', 'fix_kind' => 'source_update', 'fix_detail' => 'La source ne considère plus cette version comme affectée', 'date_fixed' => $this->now];
        }
        if ($i['fstatus'] === 'rejected') {
            $this->stats['closed']++;
            return ['state' => 'closed', 'fix_kind' => 'mapping_rejected', 'fix_detail' => 'Association rejetée par un administrateur', 'date_fixed' => $this->now];
        }
        $asset = Inventory::assetState($i['itemtype'], (int) $i['items_id']);
        if (!$asset['exists'] || $asset['deleted']) {
            $this->stats['closed']++;
            return ['state' => 'out_of_scope', 'fix_detail' => 'Actif supprimé ou mis à la corbeille', 'date_fixed' => null];
        }
        $newer = $asset['last_inventory_update'] !== null && $i['inventory_date'] !== null
            ? strtotime($asset['last_inventory_update']) > strtotime($i['inventory_date'])
            : $asset['last_inventory_update'] !== null && $i['inventory_date'] === null && strtotime($asset['last_inventory_update']) > strtotime($i['date_last_seen']);
        if (!$newer || Inventory::isStale($asset['last_inventory_update'])) {
            $this->stats['unverified']++;
            return ['state' => 'unverified', 'fix_detail' => $newer
                ? 'Version disparue mais inventaire trop ancien pour confirmer'
                : 'Version disparue sans nouvel inventaire (modification manuelle ?) : correction non confirmée'];
        }
        // Même logiciel = même nom et éditeur normalisés (GLPI peut recréer le logiciel dans une autre entité)
        $others = Inventory::versionsOfSoftwareOnItem((int) $i['softwares_id'], $i['itemtype'], (int) $i['items_id'], $i['name_norm'] ?? null, $i['manufacturer_norm'] ?? null);
        if ($others !== []) {
            $names = array_column($others, 'name');
            if (in_array(trim((string) $i['version_found']), array_map('trim', $names), true)) {
                // Même version toujours présente : GLPI a recréé l'enregistrement logiciel (ex. autre entité).
                // Ce n'est pas une correction ; le suivi continue sur le nouvel enregistrement.
                $this->stats['closed']++;
                return ['state' => 'closed', 'fix_kind' => null, 'fix_detail' => 'Même version toujours installée (enregistrement logiciel recréé par GLPI) : suivi repris sur le nouvel enregistrement',
                    'date_fixed' => null];
            }
            $comparable = array_filter($names, static fn($n) => VersionComparator::isComparable($n));
            if ($comparable === []) {
                $this->stats['unverified']++;
                return ['state' => 'unverified', 'fix_detail' => 'Nouvelle version sans numéro exploitable : ' . implode(', ', $names)];
            }
            /** @var \DBmysql $DB */
            global $DB;
            $still = $DB->request(['COUNT' => 'c', 'FROM' => self::T_ITEMS, 'WHERE' => ['plugin_vulnwatch_cves_id' => $i['plugin_vulnwatch_cves_id'],
                'itemtype' => $i['itemtype'], 'items_id' => $i['items_id'], 'state' => 'active', 'NOT' => ['id' => $i['id']]]])->current();
            if ((int) $still['c'] > 0) {
                $this->stats['closed']++;
                return ['state' => 'closed', 'fix_kind' => 'updated', 'fix_detail' => mb_substr('Mis à jour (' . $i['version_found'] . ' → ' . implode(', ', $names) . ') mais la nouvelle version reste concernée', 0, 255),
                    'date_fixed' => $this->now, 'inventory_date' => $asset['last_inventory_update']];
            }
            $this->stats['fixed']++;
            return ['state' => 'fixed', 'fix_kind' => 'updated', 'fix_detail' => mb_substr($i['version_found'] . ' → ' . implode(', ', $names), 0, 255),
                'date_fixed' => $this->now, 'inventory_date' => $asset['last_inventory_update']];
        }
        if ($i['fstatus'] === 'not_evaluated') {
            // Logiciel retiré, mais il n'avait jamais été évalué : on ne parle pas de correction
            $this->stats['closed']++;
            return ['state' => 'closed', 'fix_kind' => 'removed', 'fix_detail' => 'Logiciel retiré (n\'avait pas pu être évalué)', 'date_fixed' => $this->now];
        }
        $this->stats['fixed']++;
        return ['state' => 'fixed', 'fix_kind' => 'removed', 'fix_detail' => 'Logiciel retiré (absent de l\'inventaire du ' . $asset['last_inventory_update'] . ')',
            'date_fixed' => $this->now, 'inventory_date' => $asset['last_inventory_update']];
    }
}
