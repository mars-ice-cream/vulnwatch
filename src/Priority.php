<?php

namespace GlpiPlugin\Vulnwatch;

/**
 * Priorité de traitement, à critères visibles. La confiance de détection est volontairement
 * exclue du calcul : elle est affichée à part pour distinguer urgence et fiabilité.
 */
final class Priority
{
    /**
     * @param array<string,mixed> $cve ligne de glpi_plugin_vulnwatch_cves
     * @param array{criticality?:int, exposure?:int} $asset
     * @return array{score:int, level:string, factors:list<array{0:string,1:int,2:string}>}
     */
    public static function compute(array $cve, array $asset = []): array
    {
        $f = [];
        if ($cve['cvss_score'] !== null && $cve['cvss_score'] !== '') {
            $f[] = [sprintf('CVSS %s %.1f (%s)', $cve['cvss_version'] ?? '', $cve['cvss_score'], Cve::severityLabel($cve['severity'] ?? null)), (int) round(((float) $cve['cvss_score']) * 5), 'CVSS ' . $cve['cvss_score']];
        } else {
            $f[] = ['Gravité inconnue (CVSS absent)', 15, 'CVSS ?'];
        }
        if (!empty($cve['is_kev'])) {
            $f[] = ['Exploitation connue (CISA KEV' . (!empty($cve['kev_due_date']) ? ', échéance ' . $cve['kev_due_date'] : '') . ')', 25, 'KEV'];
        }
        if ($cve['epss_score'] !== null && $cve['epss_score'] !== '' && (float) $cve['epss_score'] >= 0.1) {
            $f[] = [sprintf('EPSS %.0f %%', (float) $cve['epss_score'] * 100), 10, 'EPSS'];
        }
        $crit = (int) ($asset['criticality'] ?? 0);
        if ($crit > 0) {
            $f[] = ['Criticité de l\'actif : ' . self::criticalityLabel($crit), [1 => 0, 2 => 5, 3 => 10][$crit] ?? 0, 'criticité ' . self::criticalityLabel($crit)];
        }
        $exp = (int) ($asset['exposure'] ?? 0);
        if ($exp === 2) {
            $f[] = ['Actif exposé à Internet', 10, 'Internet'];
        } elseif ($exp === 1) {
            $f[] = ['Actif interne', 0, 'interne'];
        }
        $score = min(100, array_sum(array_column($f, 1)));
        $level = match (true) {
            $score >= 80 => 'P1',
            $score >= 60 => 'P2',
            $score >= 40 => 'P3',
            default      => 'P4',
        };
        return ['score' => $score, 'level' => $level, 'factors' => $f];
    }

    public static function criticalityLabel(int $c): string
    {
        return [0 => 'non renseignée', 1 => 'faible', 2 => 'moyenne', 3 => 'haute'][$c] ?? 'non renseignée';
    }

    public static function exposureLabel(int $e): string
    {
        return [0 => 'inconnue', 1 => 'interne', 2 => 'exposé Internet'][$e] ?? 'inconnue';
    }

    /** @return array{criticality:int, exposure:int} */
    public static function assetContext(string $itemtype, int $id): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $r = $DB->request(['FROM' => 'glpi_plugin_vulnwatch_assetcontexts', 'WHERE' => ['itemtype' => $itemtype, 'items_id' => $id]])->current();
        return ['criticality' => (int) ($r['criticality'] ?? 0), 'exposure' => (int) ($r['exposure'] ?? 0)];
    }
}
