<?php

namespace GlpiPlugin\Vulnwatch\Matching;

/**
 * Évaluation pure (sans base) d'un critère d'applicabilité contre une version relevée.
 * Toute la logique de décision est ici pour être testable et explicable.
 */
final class Evaluator
{
    public const ESTABLISHED   = 'established';
    public const TO_CHECK      = 'to_check';
    public const NOT_EVALUATED = 'not_evaluated';
    public const NOT_AFFECTED  = 'not_affected';

    /** Ordre de « gravité » pour combiner plusieurs critères d'une même CVE. */
    public const RANK = [self::ESTABLISHED => 4, self::TO_CHECK => 3, self::NOT_EVALUATED => 2, self::NOT_AFFECTED => 1];

    /** Familles d'OS reconnues pour target_sw. */
    private const TARGET_SW_FAMILY = [
        'windows' => 'windows', 'microsoft_windows' => 'windows',
        'linux' => 'linux', 'linux_kernel' => 'linux',
        'macos' => 'macos', 'mac_os_x' => 'macos', 'mac_os' => 'macos', 'macos_x' => 'macos',
    ];

    /**
     * @param array<string,mixed> $criterion ligne de glpi_plugin_vulnwatch_criteria
     * @param array{status:string,confidence:int} $mapping association logiciel → produit
     * @param array{os_families?:list<string>, arch?:string} $context
     * @return array{status:string, confidence:int, rule_text:string, reasons:list<string>, fixed_version:?string}
     */
    public static function evaluate(array $criterion, string $version, array $mapping, array $context = []): array
    {
        $reasons = [];
        $unverifiable = false; // une condition nécessaire non vérifiable impose « À vérifier »
        $rule = self::describeRule($criterion);
        $version = trim($version);
        $confidence = (int) $mapping['confidence'];

        if ($version === '' || !VersionComparator::isComparable($version)) {
            return self::out(self::NOT_EVALUATED, 0, $rule, ['Version absente ou non comparable dans l\'inventaire (« ' . $version . ' »)'], null);
        }

        $scheme = 'generic';
        $distro = VersionComparator::looksLikeDistroPackage($version);
        $raw = $version;
        if ($distro) {
            // Les plages NVD portent sur la version amont : on compare la partie amont (sans epoch ni révision
            // de paquet), puis le résultat reste « À vérifier » à cause des rétroportages possibles.
            $version = VersionComparator::upstreamPart($version);
        }

        $hasRange = self::filled($criterion['version_start_including'] ?? null) || self::filled($criterion['version_start_excluding'] ?? null)
            || self::filled($criterion['version_end_including'] ?? null) || self::filled($criterion['version_end_excluding'] ?? null);
        $cpeVersion = (string) ($criterion['cpe_version'] ?? '*');
        $fixed = null;

        if ($hasRange) {
            $checks = [
                ['version_start_including', static fn(int $c) => $c >= 0],
                ['version_start_excluding', static fn(int $c) => $c > 0],
                ['version_end_including',   static fn(int $c) => $c <= 0],
                ['version_end_excluding',   static fn(int $c) => $c < 0],
            ];
            foreach ($checks as [$field, $ok]) {
                $bound = $criterion[$field] ?? null;
                if (!self::filled($bound)) {
                    continue;
                }
                $cmp = VersionComparator::compare($version, (string) $bound, $scheme);
                if ($cmp === null) {
                    return self::out(self::NOT_EVALUATED, 0, $rule, ['Borne de la source non comparable : ' . $bound], null);
                }
                if (!$ok($cmp)) {
                    return self::out(self::NOT_AFFECTED, $confidence, $rule, [sprintf('Version %s hors de la plage affectée', $version)], null);
                }
            }
            if (self::filled($criterion['version_end_excluding'] ?? null)) {
                $fixed = (string) $criterion['version_end_excluding'];
            } elseif (self::filled($criterion['version_end_including'] ?? null)) {
                $fixed = '> ' . $criterion['version_end_including'];
            }
            $reasons[] = sprintf('Version %s dans la plage affectée', $version);
        } elseif ($cpeVersion !== '*' && $cpeVersion !== '-' && $cpeVersion !== '') {
            $cmp = VersionComparator::compare($version, $cpeVersion, $scheme);
            if ($cmp === null) {
                return self::out(self::NOT_EVALUATED, 0, $rule, ['Version de la source non comparable : ' . $cpeVersion], null);
            }
            if ($cmp !== 0) {
                return self::out(self::NOT_AFFECTED, $confidence, $rule, [sprintf('Version %s différente de la version affectée %s', $version, $cpeVersion)], null);
            }
            $reasons[] = sprintf('Version %s égale à la version affectée', $version);
            $update = (string) ($criterion['cpe_update'] ?? '*');
            if ($update !== '*' && $update !== '-' && $update !== '') {
                $reasons[] = 'Condition non vérifiable : mise à jour/édition « ' . $update . ' » requise par la source';
                $confidence -= 30;
                $unverifiable = true;
            }
        } else {
            $reasons[] = 'La source ne borne pas les versions affectées (« toutes versions ») : vérification manuelle nécessaire';
            $confidence -= 40;
            $unverifiable = true;
        }

        // Plateforme cible (target_sw) : vérifiable seulement si l'OS des actifs est connu
        $target = strtolower((string) ($criterion['target_sw'] ?? '*'));
        if ($target !== '*' && $target !== '-' && $target !== '') {
            $family = self::TARGET_SW_FAMILY[$target] ?? null;
            $families = array_values(array_unique($context['os_families'] ?? []));
            if ($family === null || $families === [] || in_array('unknown', $families, true)) {
                $reasons[] = 'Condition non vérifiable : plateforme cible « ' . $target . ' »';
                $confidence -= 20;
                $unverifiable = true;
            } elseif (!in_array($family, $families, true)) {
                return self::out(self::NOT_AFFECTED, $confidence, $rule, ['Plateforme cible « ' . $target . ' » absente des actifs concernés'], null);
            } elseif (count($families) > 1) {
                $reasons[] = 'Plateforme cible « ' . $target . ' » vérifiée pour une partie des actifs seulement';
                $confidence -= 10;
                $unverifiable = true;
            } else {
                $reasons[] = 'Plateforme cible « ' . $target . ' » vérifiée par l\'OS inventorié';
            }
        }

        if (!empty($criterion['conditions'])) {
            $reasons[] = 'Conditions de configuration non vérifiables depuis l\'inventaire : ' . str_replace("\n", ' ; ', (string) $criterion['conditions']);
            $confidence -= 30;
            $unverifiable = true;
        }

        if ($distro) {
            $reasons[] = sprintf('Paquet de distribution Linux (%s, version amont %s) : correctif possiblement rétroporté sans changement de version amont, à confirmer avec l\'avis de la distribution', $raw, $version);
            $confidence -= 40;
            $unverifiable = true;
        }

        $mappingTrusted = in_array($mapping['status'], ['auto', 'validated'], true);
        if (!$mappingTrusted) {
            $reasons[] = 'Association logiciel → produit non validée (' . $mapping['status'] . ')';
            $confidence = min($confidence, 50);
        }

        $confidence = max(5, min(100, $confidence));
        $status = ($mappingTrusted && !$unverifiable && $confidence >= 70) ? self::ESTABLISHED : self::TO_CHECK;
        return self::out($status, $confidence, $rule, $reasons, $fixed);
    }

    public static function describeRule(array $c): string
    {
        $s = ($c['vendor'] ?? '?') . ':' . ($c['product'] ?? '?');
        $v = (string) ($c['cpe_version'] ?? '*');
        if ($v !== '*' && $v !== '') {
            $s .= ' = ' . $v;
        }
        foreach (['version_start_including' => '≥', 'version_start_excluding' => '>', 'version_end_including' => '≤', 'version_end_excluding' => '<'] as $k => $op) {
            if (self::filled($c[$k] ?? null)) {
                $s .= ' ' . $op . ' ' . $c[$k];
            }
        }
        if (($c['target_sw'] ?? '*') !== '*' && ($c['target_sw'] ?? '') !== '-') {
            $s .= ' [plateforme ' . $c['target_sw'] . ']';
        }
        return $s . ' (' . ($c['criteria'] ?? '') . ')';
    }

    private static function filled(mixed $v): bool
    {
        return $v !== null && $v !== '';
    }

    private static function out(string $status, int $confidence, string $rule, array $reasons, ?string $fixed): array
    {
        return ['status' => $status, 'confidence' => $confidence, 'rule_text' => $rule, 'reasons' => $reasons, 'fixed_version' => $fixed];
    }

    /** Combine les résultats de plusieurs critères d'une même CVE : le plus significatif l'emporte. */
    public static function combine(array $results): ?array
    {
        $best = null;
        foreach ($results as $r) {
            if ($best === null || self::RANK[$r['status']] > self::RANK[$best['status']]
                || (self::RANK[$r['status']] === self::RANK[$best['status']] && $r['confidence'] > $best['confidence'])) {
                $best = $r;
            }
        }
        return $best;
    }

    /** Famille d'OS d'après le nom inventorié. */
    public static function osFamily(?string $osName): string
    {
        $n = strtolower((string) $osName);
        return match (true) {
            $n === '' => 'unknown',
            str_contains($n, 'windows') => 'windows',
            str_contains($n, 'mac') || str_contains($n, 'darwin') => 'macos',
            (bool) preg_match('/linux|ubuntu|debian|centos|red ?hat|rhel|fedora|suse|alma|rocky|mint|arch/', $n) => 'linux',
            default => 'other',
        };
    }
}
