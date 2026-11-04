<?php

namespace GlpiPlugin\Vulnwatch;

/**
 * Accès à la base locale de CVE (données publiques, globales).
 */
final class Cve
{
    public const TABLE = 'glpi_plugin_vulnwatch_cves';

    public static function isValidId(string $id): bool
    {
        return (bool) preg_match('/^CVE-\d{4}-\d{4,7}$/', $id);
    }

    /** Crée la CVE si absente (statut NVD « pending ») et retourne sa clé. */
    public static function ensure(string $cveId, string $origin): int
    {
        /** @var \DBmysql $DB */
        global $DB;
        $cveId = strtoupper(trim($cveId));
        if (!self::isValidId($cveId)) {
            throw new \InvalidArgumentException('Identifiant CVE invalide : ' . $cveId);
        }
        $row = $DB->request(['SELECT' => ['id'], 'FROM' => self::TABLE, 'WHERE' => ['cve_id' => $cveId]])->current();
        if ($row) {
            return (int) $row['id'];
        }
        $now = $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s');
        $DB->insert(self::TABLE, ['cve_id' => $cveId, 'origin' => $origin, 'nvd_status' => 'pending', 'date_creation' => $now, 'date_mod' => $now]);
        return (int) $DB->insertId();
    }

    public static function getByCveId(string $cveId): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $row = $DB->request(['FROM' => self::TABLE, 'WHERE' => ['cve_id' => strtoupper($cveId)]])->current();
        return $row ?: null;
    }

    public static function getById(int $id): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $row = $DB->request(['FROM' => self::TABLE, 'WHERE' => ['id' => $id]])->current();
        return $row ?: null;
    }

    public static function severityLabel(?string $sev): string
    {
        return match (strtoupper((string) $sev)) {
            'CRITICAL' => __('Critique', 'vulnwatch'),
            'HIGH'     => __('Haute', 'vulnwatch'),
            'MEDIUM'   => __('Moyenne', 'vulnwatch'),
            'LOW'      => __('Faible', 'vulnwatch'),
            'NONE'     => __('Aucune', 'vulnwatch'),
            default    => __('Inconnue', 'vulnwatch'),
        };
    }
}
