<?php

namespace GlpiPlugin\Vulnwatch\Source;

use GlpiPlugin\Vulnwatch\Config;
use GlpiPlugin\Vulnwatch\Cve;
use GlpiPlugin\Vulnwatch\Http\SafeHttpClient;
use GlpiPlugin\Vulnwatch\Logger;

/**
 * CISA Known Exploited Vulnerabilities : signale les CVE dont l'exploitation est connue.
 * Le catalogue complet est téléchargé ; rien n'est transmis.
 */
final class KevConnector implements SourceConnectorInterface
{
    public function __construct(private ?SafeHttpClient $client = null)
    {
    }

    public function getKey(): string
    {
        return 'kev';
    }

    public function getLabel(): string
    {
        return 'CISA KEV – vulnérabilités exploitées';
    }

    public function isEnabled(): bool
    {
        return Config::getBool('kev_enabled');
    }

    public function describeOutboundData(): string
    {
        return 'GET ' . Config::get('kev_url') . ' (téléchargement du catalogue complet, aucun paramètre).';
    }

    public function run(int $budget): array
    {
        if (!$this->isEnabled()) {
            return ['ok' => true, 'done' => 0, 'errors' => 0, 'message' => 'désactivé'];
        }
        $last = Config::get('kev_last_sync');
        if ($last !== '' && time() - strtotime($last) < 12 * 3600 && !defined('VULNWATCH_TESTING')) {
            return ['ok' => true, 'done' => 0, 'errors' => 0, 'message' => 'à jour'];
        }
        try {
            $resp = ($this->client ?? new SafeHttpClient())->get(Config::get('kev_url'), ['Accept' => 'application/json']);
            if ($resp['status'] !== 200) {
                throw new \RuntimeException('HTTP ' . $resp['status']);
            }
            $n = self::import(json_decode($resp['body'], true, 32, JSON_THROW_ON_ERROR));
            Config::set(['kev_last_sync' => date('Y-m-d H:i:s'), 'kev_last_error' => '']);
            return ['ok' => true, 'done' => $n, 'errors' => 0, 'message' => "$n entrées KEV"];
        } catch (\Throwable $e) {
            Config::set(['kev_last_error' => date('Y-m-d H:i') . ' ' . mb_substr($e->getMessage(), 0, 300)]);
            Logger::log('KEV : ' . $e->getMessage());
            // En cas d'échec, les marquages KEV existants sont conservés tels quels
            return ['ok' => false, 'done' => 0, 'errors' => 1, 'message' => $e->getMessage()];
        }
    }

    public static function import(array $catalog): int
    {
        /** @var \DBmysql $DB */
        global $DB;
        $trackAll = Config::getBool('kev_track_all');
        $n = 0;
        foreach ($catalog['vulnerabilities'] ?? [] as $v) {
            $id = strtoupper((string) ($v['cveID'] ?? ''));
            if (!Cve::isValidId($id)) {
                continue;
            }
            $row = Cve::getByCveId($id);
            if ($row === null) {
                if (!$trackAll) {
                    continue;
                }
                $pk = Cve::ensure($id, 'kev');
            } else {
                $pk = (int) $row['id'];
            }
            $DB->update(Cve::TABLE, [
                'is_kev'         => 1,
                'kev_date_added' => $v['dateAdded'] ?? null,
                'kev_due_date'   => $v['dueDate'] ?? null,
                'kev_ransomware' => isset($v['knownRansomwareCampaignUse']) ? mb_substr($v['knownRansomwareCampaignUse'], 0, 32) : null,
            ], ['id' => $pk]);
            $n++;
        }
        return $n;
    }
}
