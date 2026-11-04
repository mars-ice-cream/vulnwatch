<?php

namespace GlpiPlugin\Vulnwatch\Source;

use GlpiPlugin\Vulnwatch\Config;
use GlpiPlugin\Vulnwatch\Cve;
use GlpiPlugin\Vulnwatch\Http\SafeHttpClient;
use GlpiPlugin\Vulnwatch\Logger;

/**
 * NVD API 2.0 : CVE, critères d'applicabilité CPE, CVSS.
 *
 * Mode « referenced » (défaut) : seules les CVE citées par les flux ou ajoutées à la main
 * sont demandées, une par une (paramètre cveId). Mode « incremental » : toutes les CVE
 * modifiées depuis la dernière synchronisation (paramètres de dates). Dans les deux cas,
 * aucune donnée d'inventaire (nom de logiciel, version, machine) n'est transmise.
 */
final class NvdConnector implements SourceConnectorInterface
{
    public const API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

    public function __construct(private ?SafeHttpClient $client = null)
    {
    }

    /** URL de l'API (modifiable pour un miroir interne autorisé). */
    public static function apiUrl(): string
    {
        return Config::get('nvd_url') ?: self::API;
    }

    public function getKey(): string
    {
        return 'nvd';
    }

    public function getLabel(): string
    {
        return 'NVD (NIST) – API CVE 2.0';
    }

    public function isEnabled(): bool
    {
        return Config::getBool('nvd_enabled');
    }

    public function describeOutboundData(): string
    {
        return Config::get('nvd_mode') === 'incremental'
            ? 'GET ' . self::apiUrl() . '?lastModStartDate=…&lastModEndDate=…&startIndex=… (dates uniquement) ; en-tête apiKey si configurée.'
            : 'GET ' . self::apiUrl() . '?cveId=CVE-AAAA-NNNN (identifiant CVE uniquement) ; en-tête apiKey si configurée.';
    }

    public function run(int $budget): array
    {
        if (!$this->isEnabled()) {
            return ['ok' => true, 'done' => 0, 'errors' => 0, 'message' => 'désactivé'];
        }
        return Config::get('nvd_mode') === 'incremental' ? $this->runIncremental($budget) : $this->runReferenced($budget);
    }

    private function headers(): array
    {
        $h = ['Accept' => 'application/json'];
        if (Config::get('nvd_api_key') !== '') {
            $h['apiKey'] = Config::get('nvd_api_key');
        }
        return $h;
    }

    private function runReferenced(int $budget): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $limit = min($budget, max(1, Config::getInt('nvd_batch_size')));
        // Rafraîchir aussi les CVE en erreur ou anciennes (> 7 jours), par lots
        $rows = $DB->request([
            'SELECT' => ['id', 'cve_id'],
            'FROM'   => Cve::TABLE,
            'WHERE'  => ['OR' => [
                ['nvd_status' => 'pending'],
                ['nvd_status' => 'error', 'nvd_fetched_at' => ['<', date('Y-m-d H:i:s', time() - 3600)]],
                ['nvd_status' => 'ok', 'nvd_fetched_at' => ['<', date('Y-m-d H:i:s', time() - 7 * 86400)]],
                // CVE citée avant sa publication NVD : on réessaie chaque jour
                ['nvd_status' => 'not_found', 'nvd_fetched_at' => ['<', date('Y-m-d H:i:s', time() - 86400)]],
            ]],
            'ORDER'  => ['nvd_status DESC', 'nvd_fetched_at ASC'],
            'LIMIT'  => $limit,
        ]);
        $done = $errors = 0;
        $client = $this->client ?? new SafeHttpClient();
        $delay = Config::get('nvd_api_key') !== '' ? 700000 : 6200000; // limites publiques NVD
        $first = true;
        foreach ($rows as $row) {
            if (!$first && !defined('VULNWATCH_TESTING')) {
                usleep($delay);
            }
            $first = false;
            try {
                $resp = $client->get(self::apiUrl() . '?cveId=' . rawurlencode($row['cve_id']), $this->headers());
                if ($resp['status'] !== 200) {
                    throw new \RuntimeException('HTTP ' . $resp['status']);
                }
                $data = json_decode($resp['body'], true, 64, JSON_THROW_ON_ERROR);
                if (empty($data['vulnerabilities'])) {
                    $this->markStatus((int) $row['id'], 'not_found', 'CVE absente de la NVD (réservée, rejetée ou pas encore publiée)');
                } else {
                    self::importVulnerability($data['vulnerabilities'][0]['cve'], 'nvd');
                }
                $done++;
            } catch (\Throwable $e) {
                $errors++;
                $this->markStatus((int) $row['id'], 'error', mb_substr($e->getMessage(), 0, 500));
                Logger::log('NVD ' . $row['cve_id'] . ' : ' . $e->getMessage());
            }
        }
        return ['ok' => $errors === 0, 'done' => $done, 'errors' => $errors, 'message' => "$done CVE enrichies, $errors erreurs"];
    }

    private function runIncremental(int $budget): array
    {
        $client = $this->client ?? new SafeHttpClient();
        $last = Config::get('nvd_last_sync');
        $start = $last !== '' ? strtotime($last) : time() - 7 * 86400;
        // Reprise d'une fenêtre interrompue (budget atteint) : même fenêtre, page suivante
        $cursorEnd = Config::get('nvd_incr_window_end');
        $end = $cursorEnd !== '' ? (int) $cursorEnd : min(time(), $start + 119 * 86400); // fenêtre max NVD : 120 jours
        $index = $cursorEnd !== '' ? (int) Config::get('nvd_incr_index') : 0;
        $fmt = static fn(int $t) => gmdate('Y-m-d\TH:i:s.000', $t);
        $done = 0;
        $pages = 0;
        $total = 0;
        try {
            do {
                $url = self::apiUrl() . '?' . http_build_query([
                    'lastModStartDate' => $fmt($start), 'lastModEndDate' => $fmt($end),
                    'startIndex' => $index, 'resultsPerPage' => 2000,
                ]);
                $resp = $client->get($url, $this->headers());
                if ($resp['status'] !== 200) {
                    throw new \RuntimeException('HTTP ' . $resp['status']);
                }
                $data = json_decode($resp['body'], true, 64, JSON_THROW_ON_ERROR);
                foreach ($data['vulnerabilities'] ?? [] as $v) {
                    self::importVulnerability($v['cve'], 'nvd_sync');
                    $done++;
                }
                $pages++;
                $index += (int) ($data['resultsPerPage'] ?? 0);
                $total = (int) ($data['totalResults'] ?? 0);
                if ((int) ($data['resultsPerPage'] ?? 0) === 0) {
                    break; // page vide : fin de fenêtre
                }
                if ($index < $total && $pages < $budget && !defined('VULNWATCH_TESTING')) {
                    usleep(6200000);
                }
            } while ($index < $total && $pages < $budget);

            if ($index < $total) {
                // Budget atteint : on mémorise la fenêtre et la page, la date de reprise n'avance pas
                Config::set(['nvd_incr_window_end' => (string) $end, 'nvd_incr_index' => (string) $index]);
                return ['ok' => true, 'done' => $done, 'errors' => 0, 'message' => sprintf('%d CVE synchronisées, reprise à %d/%d', $done, $index, $total)];
            }
            Config::set(['nvd_last_sync' => date('Y-m-d H:i:s', $end), 'nvd_incr_window_end' => '', 'nvd_incr_index' => '0']);
            return ['ok' => true, 'done' => $done, 'errors' => 0, 'message' => "$done CVE synchronisées"];
        } catch (\Throwable $e) {
            Logger::log('NVD incrémental : ' . $e->getMessage());
            // Ni la date ni la page de reprise n'avancent : la page en erreur sera rejouée
            if ($cursorEnd !== '' || $index > 0) {
                Config::set(['nvd_incr_window_end' => (string) $end, 'nvd_incr_index' => (string) $index]);
            }
            return ['ok' => false, 'done' => $done, 'errors' => 1, 'message' => $e->getMessage()];
        }
    }

    private function markStatus(int $id, string $status, string $error): void
    {
        /** @var \DBmysql $DB */
        global $DB;
        $DB->update(Cve::TABLE, ['nvd_status' => $status, 'nvd_error' => $error, 'nvd_fetched_at' => date('Y-m-d H:i:s')], ['id' => $id]);
    }

    /**
     * Importe un objet « cve » au format NVD 2.0 (API ou fichier). Idempotent.
     * Les critères ne sont réécrits que si les données ont changé.
     */
    public static function importVulnerability(array $cve, string $origin): int
    {
        /** @var \DBmysql $DB */
        global $DB;
        $cveId = strtoupper((string) ($cve['id'] ?? ''));
        $pk = Cve::ensure($cveId, $origin);
        $hash = hash('sha256', json_encode([$cve['lastModified'] ?? '', $cve['configurations'] ?? [], $cve['metrics'] ?? []]));

        $desc = '';
        foreach ($cve['descriptions'] ?? [] as $d) {
            if (($d['lang'] ?? '') === 'en' || $desc === '') {
                $desc = (string) $d['value'];
            }
        }
        [$score, $version, $vector, $severity] = self::pickCvss($cve['metrics'] ?? []);
        $fields = [
            'description'     => mb_substr($desc, 0, 8000),
            'cvss_score'      => $score,
            'cvss_version'    => $version,
            'cvss_vector'     => $vector,
            'severity'        => $severity,
            'vuln_status'     => $cve['vulnStatus'] ?? null,
            'date_published'  => isset($cve['published']) ? date('Y-m-d H:i:s', strtotime($cve['published'])) : null,
            'date_source_mod' => isset($cve['lastModified']) ? date('Y-m-d H:i:s', strtotime($cve['lastModified'])) : null,
            'nvd_status'      => 'ok',
            'nvd_error'       => null,
            'nvd_fetched_at'  => date('Y-m-d H:i:s'),
            'date_mod'        => date('Y-m-d H:i:s'),
        ];
        $current = Cve::getById($pk);
        if (($current['data_hash'] ?? '') !== $hash) {
            $DB->delete('glpi_plugin_vulnwatch_criteria', ['plugin_vulnwatch_cves_id' => $pk, 'source' => 'nvd']);
            foreach (self::extractCriteria($cve['configurations'] ?? []) as $c) {
                $DB->insert('glpi_plugin_vulnwatch_criteria', ['plugin_vulnwatch_cves_id' => $pk, 'source' => 'nvd'] + $c);
            }
            $fields['data_hash'] = $hash;
        }
        $DB->update(Cve::TABLE, $fields, ['id' => $pk]);
        return $pk;
    }

    /** @return array{0:?float,1:?string,2:?string,3:?string} */
    public static function pickCvss(array $metrics): array
    {
        foreach (['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2'] as $key) {
            $list = $metrics[$key] ?? [];
            usort($list, static fn($a, $b) => (($a['type'] ?? '') === 'Primary' ? 0 : 1) <=> (($b['type'] ?? '') === 'Primary' ? 0 : 1));
            foreach ($list as $m) {
                $d = $m['cvssData'] ?? [];
                if (isset($d['baseScore'])) {
                    $sev = $d['baseSeverity'] ?? $m['baseSeverity'] ?? null;
                    return [(float) $d['baseScore'], (string) ($d['version'] ?? ''), (string) ($d['vectorString'] ?? ''), $sev ? strtoupper($sev) : null];
                }
            }
        }
        return [null, null, null, null];
    }

    /**
     * Aplatit les configurations NVD. Un critère vulnérable d'une configuration AND
     * (ex. « application X sur système Y ») reçoit la liste des autres nœuds en conditions :
     * elles ne sont pas vérifiables à coup sûr depuis l'inventaire, le résultat restera « À vérifier ».
     * @return list<array<string,mixed>>
     */
    public static function extractCriteria(array $configurations): array
    {
        $out = [];
        foreach ($configurations as $ci => $config) {
            $nodes = $config['nodes'] ?? [];
            $configAnd = strtoupper($config['operator'] ?? 'OR') === 'AND' && count($nodes) > 1;
            foreach ($nodes as $ni => $node) {
                $nodeAnd = strtoupper($node['operator'] ?? 'OR') === 'AND' && count($node['cpeMatch'] ?? []) > 1;
                foreach ($node['cpeMatch'] ?? [] as $mi => $m) {
                    if (empty($m['vulnerable'])) {
                        continue;
                    }
                    $conds = [];
                    if (!empty($node['negate']) || !empty($config['negate'])) {
                        $conds[] = 'Règle avec négation (non évaluable automatiquement)';
                    }
                    if ($configAnd) {
                        foreach ($nodes as $nj => $other) {
                            if ($nj === $ni) {
                                continue;
                            }
                            $list = array_map(static fn($x) => self::describeCpeMatch($x), $other['cpeMatch'] ?? []);
                            $conds[] = (!empty($other['negate']) ? 'ne pas être : ' : 'avec l\'un de : ') . implode(' | ', array_slice($list, 0, 10)) . (count($list) > 10 ? ' …' : '');
                        }
                    }
                    if ($nodeAnd) {
                        foreach ($node['cpeMatch'] as $mj => $other) {
                            if ($mj !== $mi) {
                                $conds[] = 'avec : ' . self::describeCpeMatch($other);
                            }
                        }
                    }
                    $cpe = Cpe::parse((string) $m['criteria']);
                    if ($cpe === null) {
                        continue;
                    }
                    $out[] = [
                        'config_index'            => (int) $ci,
                        'node_index'              => (int) $ni,
                        'criteria'                => mb_substr((string) $m['criteria'], 0, 512),
                        'part'                    => $cpe['part'],
                        'vendor'                  => $cpe['vendor'],
                        'product'                 => $cpe['product'],
                        'cpe_version'             => $cpe['version'],
                        'cpe_update'              => $cpe['update'],
                        'target_sw'               => $cpe['target_sw'],
                        'target_hw'               => $cpe['target_hw'],
                        'version_start_including' => $m['versionStartIncluding'] ?? null,
                        'version_start_excluding' => $m['versionStartExcluding'] ?? null,
                        'version_end_including'   => $m['versionEndIncluding'] ?? null,
                        'version_end_excluding'   => $m['versionEndExcluding'] ?? null,
                        'is_vulnerable'           => 1,
                        'conditions'              => $conds === [] ? null : implode("\n", $conds),
                    ];
                }
            }
        }
        return $out;
    }

    private static function describeCpeMatch(array $m): string
    {
        $c = Cpe::parse((string) ($m['criteria'] ?? ''));
        if ($c === null) {
            return (string) ($m['criteria'] ?? '?');
        }
        $s = $c['vendor'] . ':' . $c['product'];
        if ($c['version'] !== '*' && $c['version'] !== '-') {
            $s .= ' ' . $c['version'];
        }
        foreach (['versionStartIncluding' => '≥', 'versionStartExcluding' => '>', 'versionEndIncluding' => '≤', 'versionEndExcluding' => '<'] as $k => $op) {
            if (!empty($m[$k])) {
                $s .= ' ' . $op . ' ' . $m[$k];
            }
        }
        return $s;
    }
}
