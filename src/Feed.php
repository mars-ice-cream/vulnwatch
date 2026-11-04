<?php

namespace GlpiPlugin\Vulnwatch;

use CommonDBTM;
use GlpiPlugin\Vulnwatch\Http\SafeHttpClient;
use GlpiPlugin\Vulnwatch\Source\FeedParser;

/**
 * Flux RSS/Atom configuré par un administrateur.
 * Cloisonnement : entités destinataires = entities_id + is_recursive (mécanisme natif).
 */
final class Feed extends Compat\ConfigRightDbtm
{

    public static function getTypeName($nb = 0)
    {
        return _n('Flux de veille', 'Flux de veille', $nb, 'vulnwatch');
    }

    public static function getTable($classname = null)
    {
        return 'glpi_plugin_vulnwatch_feeds';
    }

    public static function getIcon()
    {
        return 'ti ti-rss';
    }

    // Droit « configuration » : UPDATE suffit pour créer, modifier ou supprimer
    public static function canCreate(): bool
    {
        return \Session::haveRight(static::$rightname, UPDATE);
    }

    public static function canPurge(): bool
    {
        return \Session::haveRight(static::$rightname, UPDATE);
    }

    public static function canDelete(): bool
    {
        return \Session::haveRight(static::$rightname, UPDATE);
    }

    public function maybeRecursive()
    {
        return true;
    }

    public function isEntityAssign()
    {
        return true;
    }

    public function prepareInputForAdd($input)
    {
        return $this->checkInput($input, true);
    }

    public function prepareInputForUpdate($input)
    {
        return $this->checkInput($input, false);
    }

    /** @return array<string,mixed>|false */
    private function checkInput(array $input, bool $isNew)
    {
        if ($isNew || isset($input['name'])) {
            $input['name'] = trim((string) ($input['name'] ?? ''));
            if ($input['name'] === '') {
                \Session::addMessageAfterRedirect(__('Le nom du flux est obligatoire.', 'vulnwatch'), false, ERROR);
                return false;
            }
        }
        if ($isNew || isset($input['url'])) {
            $input['url'] = trim((string) ($input['url'] ?? ''));
            try {
                // Validation syntaxique + schéma + port. La résolution est refaite à chaque récupération.
                $parts = parse_url($input['url']);
                if (!$parts || !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true) || empty($parts['host'])) {
                    throw new \InvalidArgumentException(__('URL invalide : seuls http et https sont acceptés.', 'vulnwatch'));
                }
                if (isset($parts['user']) || isset($parts['pass'])) {
                    throw new \InvalidArgumentException(__('Les identifiants dans l\'URL ne sont pas acceptés.', 'vulnwatch'));
                }
            } catch (\Throwable $e) {
                \Session::addMessageAfterRedirect(htmlescape($e->getMessage()), false, ERROR);
                return false;
            }
        }
        if (isset($input['frequency'])) {
            $input['frequency'] = max(15, min(10080, (int) $input['frequency']));
        }
        if ($isNew) {
            $input['last_status'] = 'never';
        }
        return $input;
    }

    /**
     * Flux officiels proposés d'office (entité racine, récursifs, actifs).
     * Ajoutés à la première installation, et à la demande depuis la liste des flux s'ils ont été supprimés.
     */
    public const OFFICIAL_FEEDS = [
        ['CERT-FR – Avis de sécurité', 'https://www.cert.ssi.gouv.fr/avis/feed/', 'Avis de sécurité du CERT-FR (ANSSI) : vulnérabilités et correctifs, avec leurs identifiants CVE.'],
        ['CERT-FR – Alertes de sécurité', 'https://www.cert.ssi.gouv.fr/alerte/feed/', 'Alertes du CERT-FR (ANSSI) : vulnérabilités critiques exploitées ou menaces imminentes.'],
    ];

    /** Ajoute les flux officiels absents (comparaison sur l'URL). @return int nombre de flux ajoutés */
    public static function installOfficialFeeds(): int
    {
        /** @var \DBmysql $DB */
        global $DB;
        $existing = array_map(static fn($r) => rtrim(strtolower((string) $r['url']), '/'), iterator_to_array($DB->request(['SELECT' => ['url'], 'FROM' => self::getTable()]), false));
        $now = date('Y-m-d H:i:s');
        $added = 0;
        foreach (self::OFFICIAL_FEEDS as [$name, $url, $comment]) {
            if (in_array(rtrim(strtolower($url), '/'), $existing, true)) {
                continue;
            }
            $DB->insert(self::getTable(), [
                'entities_id' => 0, 'is_recursive' => 1, 'name' => $name, 'url' => $url, 'is_active' => 1, 'frequency' => 60,
                'last_status' => 'never', 'comment' => $comment . ' Flux officiel ajouté automatiquement par VulnWatch.',
                'date_creation' => $now, 'date_mod' => $now,
            ]);
            $added++;
        }
        return $added;
    }

    /** Flux dus pour une récupération. */
    public static function getDueFeeds(int $limit = 20): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $out = [];
        $now = time();
        foreach ($DB->request(['FROM' => self::getTable(), 'WHERE' => ['is_active' => 1], 'ORDER' => 'last_attempt ASC']) as $row) {
            $last = $row['last_attempt'] ? strtotime($row['last_attempt']) : 0;
            if ($now - $last >= ((int) $row['frequency']) * 60 - 30) {
                $out[] = $row;
            }
            if (count($out) >= $limit) {
                break;
            }
        }
        return $out;
    }

    /**
     * Récupère et enregistre un flux. Ne lève pas d'exception : l'état est conservé sur le flux.
     * @return array{ok:bool, items:int, new:int, error:string}
     */
    public static function sync(array $feed, ?SafeHttpClient $client = null): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $client ??= new SafeHttpClient();
        $now = $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s');
        $result = ['ok' => false, 'items' => 0, 'new' => 0, 'error' => ''];
        $update = ['last_attempt' => $now];
        try {
            $headers = ['Accept' => 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8'];
            if (!empty($feed['http_etag'])) {
                $headers['If-None-Match'] = $feed['http_etag'];
            }
            if (!empty($feed['http_last_modified'])) {
                $headers['If-Modified-Since'] = $feed['http_last_modified'];
            }
            $resp = $client->get($feed['url'], $headers);
            if ($resp['status'] === 304) {
                $result['ok'] = true;
                $update += ['last_success' => $now, 'last_status' => 'ok', 'last_new_count' => 0];
            } elseif ($resp['status'] < 200 || $resp['status'] >= 300) {
                throw new \RuntimeException('HTTP ' . $resp['status']);
            } else {
                $parsed = FeedParser::parse($resp['body']);
                $stats = self::storeItems((int) $feed['id'], $parsed['items'], $feed);
                $result = ['ok' => true, 'items' => $stats['items'], 'new' => $stats['new'], 'error' => ''];
                $update += [
                    'last_success'       => $now,
                    'last_status'        => 'ok',
                    'last_items_count'   => $stats['items'],
                    'last_new_count'     => $stats['new'],
                    'http_etag'          => $resp['headers']['etag'] ?? null,
                    'http_last_modified' => $resp['headers']['last-modified'] ?? null,
                ];
            }
        } catch (\Throwable $e) {
            $result['error'] = mb_substr($e->getMessage(), 0, 1000);
            $update += ['last_status' => 'error', 'last_error' => $result['error'], 'last_error_date' => $now];
            Logger::log(sprintf('Flux #%d "%s" en erreur : %s', $feed['id'], $feed['name'], $result['error']));
        }
        $DB->update(self::getTable(), $update, ['id' => $feed['id']]);
        return $result;
    }

    /** Teste la récupération sans rien enregistrer. */
    public static function test(string $url, ?SafeHttpClient $client = null): array
    {
        $client ??= new SafeHttpClient();
        try {
            $resp = $client->get($url);
            if ($resp['status'] < 200 || $resp['status'] >= 300) {
                return ['ok' => false, 'error' => 'HTTP ' . $resp['status']];
            }
            $parsed = FeedParser::parse($resp['body']);
            $cves = 0;
            foreach ($parsed['items'] as $it) {
                $cves += count($it['cves']);
            }
            return ['ok' => true, 'format' => $parsed['format'], 'title' => $parsed['title'], 'count' => count($parsed['items']),
                'cves' => $cves, 'sample' => array_slice(array_column($parsed['items'], 'title'), 0, 5), 'final_url' => $resp['url']];
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * @param list<array{guid:string,title:string,link:string,summary:string,published:?string,cves:list<string>}> $items
     * @return array{items:int,new:int}
     */
    public static function storeItems(int $feedId, array $items, array $feed = []): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $include = self::keywords($feed['filter_include'] ?? '');
        $exclude = self::keywords($feed['filter_exclude'] ?? '');
        $new = 0;
        $seen = [];
        $now = $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s');
        foreach ($items as $it) {
            $hay = mb_strtolower($it['title'] . ' ' . $it['summary']);
            if ($include !== [] && !self::containsAny($hay, $include)) {
                continue;
            }
            if ($exclude !== [] && self::containsAny($hay, $exclude)) {
                continue;
            }
            $guidHash = hash('sha256', $it['guid']);
            if (isset($seen[$guidHash])) {
                continue; // doublon dans la même réponse
            }
            $seen[$guidHash] = true;
            $existing = $DB->request(['SELECT' => ['id'], 'FROM' => 'glpi_plugin_vulnwatch_bulletins',
                'WHERE' => ['plugin_vulnwatch_feeds_id' => $feedId, 'guid_hash' => $guidHash]])->current();
            if ($existing) {
                $bulletinId = (int) $existing['id'];
            } else {
                $DB->insert('glpi_plugin_vulnwatch_bulletins', [
                    'plugin_vulnwatch_feeds_id' => $feedId,
                    'guid_hash'      => $guidHash,
                    'link_hash'      => $it['link'] !== '' ? hash('sha256', self::normalizeLink($it['link'])) : '',
                    'title'          => mb_substr($it['title'], 0, 1000),
                    'link'           => mb_substr($it['link'], 0, 2048),
                    'summary'        => $it['summary'],
                    'date_published' => $it['published'],
                    'cve_count'      => count($it['cves']),
                    'review_status'  => $it['cves'] === [] ? 'to_review' : 'linked',
                    'review_reason'  => $it['cves'] === [] ? 'Aucun identifiant CVE dans l\'article' : '',
                    'date_creation'  => $now,
                ]);
                $bulletinId = (int) $DB->insertId();
                $new++;
            }
            foreach ($it['cves'] as $cveId) {
                $cvePk = Cve::ensure($cveId, 'feed');
                $DB->updateOrInsert('glpi_plugin_vulnwatch_cves_bulletins',
                    ['plugin_vulnwatch_cves_id' => $cvePk, 'plugin_vulnwatch_bulletins_id' => $bulletinId],
                    ['plugin_vulnwatch_cves_id' => $cvePk, 'plugin_vulnwatch_bulletins_id' => $bulletinId]);
            }
        }
        return ['items' => count($seen), 'new' => $new];
    }

    public function rawSearchOptions()
    {
        $tab = parent::rawSearchOptions();
        $t = self::getTable();
        $tab[] = ['id' => 2, 'table' => $t, 'field' => 'url', 'name' => __('URL'), 'datatype' => 'string'];
        $tab[] = ['id' => 3, 'table' => $t, 'field' => 'is_active', 'name' => __('Active'), 'datatype' => 'bool'];
        $tab[] = ['id' => 4, 'table' => $t, 'field' => 'frequency', 'name' => __('Fréquence (minutes)', 'vulnwatch'), 'datatype' => 'integer'];
        $tab[] = ['id' => 5, 'table' => $t, 'field' => 'last_status', 'name' => __('État de synchronisation', 'vulnwatch'), 'datatype' => 'specific', 'searchtype' => ['equals', 'notequals']];
        $tab[] = ['id' => 6, 'table' => $t, 'field' => 'last_success', 'name' => __('Dernière réussite', 'vulnwatch'), 'datatype' => 'datetime'];
        $tab[] = ['id' => 7, 'table' => $t, 'field' => 'last_error', 'name' => __('Dernière erreur', 'vulnwatch'), 'datatype' => 'text'];
        $tab[] = ['id' => 8, 'table' => $t, 'field' => 'last_items_count', 'name' => __('Articles (dernière récupération)', 'vulnwatch'), 'datatype' => 'integer'];
        $tab[] = ['id' => 80, 'table' => 'glpi_entities', 'field' => 'completename', 'name' => \Entity::getTypeName(1), 'datatype' => 'dropdown'];
        return $tab;
    }

    public function defineTabs($options = [])
    {
        $ong = [];
        $this->addDefaultFormTab($ong);
        $this->addStandardTab(\Log::class, $ong, $options);
        return $ong;
    }

    public static function getSpecificValueToDisplay($field, $values, array $options = [])
    {
        if (!is_array($values)) {
            $values = [$field => $values];
        }
        if ($field === 'last_status') {
            return Ui::syncBadge((string) $values[$field]);
        }
        return parent::getSpecificValueToDisplay($field, $values, $options);
    }

    public static function getSpecificValueToSelect($field, $name = '', $values = '', array $options = [])
    {
        if (!is_array($values)) {
            $values = [$field => $values];
        }
        if ($field === 'last_status') {
            return \Dropdown::showFromArray($name, ['ok' => 'OK', 'error' => 'Erreur', 'never' => 'Jamais synchronisé'], ['value' => $values[$field], 'display' => false]);
        }
        return parent::getSpecificValueToSelect($field, $name, $values, $options);
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        $this->showFormHeader($options);
        $f = $this->fields;
        $h = static fn($v) => htmlescape((string) ($v ?? ''));
        echo "<tr class='tab_bg_1'><td>" . __('Name') . " *</td><td><input class='form-control' name='name' required value='{$h($f['name'] ?? '')}'></td>";
        echo '<td>' . __('URL du flux RSS/Atom', 'vulnwatch') . " *</td><td><input class='form-control' type='url' name='url' required value='{$h($f['url'] ?? '')}'></td></tr>";
        echo "<tr class='tab_bg_1'><td>" . __('Active') . '</td><td>';
        \Dropdown::showYesNo('is_active', $f['is_active'] ?? 1);
        echo '</td><td>' . __('Fréquence (minutes, 15 à 10080)', 'vulnwatch') . "</td><td><input class='form-control' type='number' min='15' max='10080' name='frequency' value='{$h($f['frequency'] ?? 60)}'></td></tr>";
        echo "<tr class='tab_bg_1'><td>" . __('Filtre : garder les articles contenant (mots séparés par virgule)', 'vulnwatch') . "</td><td><textarea class='form-control' name='filter_include'>{$h($f['filter_include'] ?? '')}</textarea></td>";
        echo '<td>' . __('Filtre : exclure les articles contenant', 'vulnwatch') . "</td><td><textarea class='form-control' name='filter_exclude'>{$h($f['filter_exclude'] ?? '')}</textarea></td></tr>";
        echo "<tr class='tab_bg_1'><td>" . __('Commentaire') . "</td><td colspan='3'><textarea class='form-control' name='comment'>{$h($f['comment'] ?? '')}</textarea></td></tr>";
        if (!$this->isNewID($ID)) {
            echo "<tr class='tab_bg_2'><td>" . __('État de synchronisation', 'vulnwatch') . '</td><td>' . Ui::syncBadge((string) $f['last_status'])
                . ' ' . $h($f['last_attempt']) . '</td><td>' . __('Dernière réussite', 'vulnwatch') . '</td><td>' . $h($f['last_success'] ?: '—')
                . ' (' . (int) $f['last_items_count'] . ' articles, ' . (int) $f['last_new_count'] . ' nouveaux)</td></tr>';
            echo "<tr class='tab_bg_2'><td>" . __('Dernière erreur', 'vulnwatch') . "</td><td colspan='3'>" . ($f['last_error'] ? $h($f['last_error_date'] . ' — ' . $f['last_error']) : '—') . '</td></tr>';
        }
        $this->showFormButtons($options);
        return true;
    }

    public static function normalizeLink(string $link): string
    {
        $p = parse_url($link);
        if (!$p || empty($p['host'])) {
            return $link;
        }
        $query = '';
        if (!empty($p['query'])) {
            parse_str($p['query'], $q);
            $q = array_filter($q, static fn($k) => !str_starts_with((string) $k, 'utm_'), ARRAY_FILTER_USE_KEY);
            ksort($q);
            $query = $q ? '?' . http_build_query($q) : '';
        }
        return strtolower($p['host']) . rtrim($p['path'] ?? '/', '/') . $query;
    }

    /** @return list<string> */
    private static function keywords(?string $s): array
    {
        $parts = preg_split('/[,\n]+/', mb_strtolower((string) $s)) ?: [];
        return array_values(array_filter(array_map('trim', $parts)));
    }

    /** @param list<string> $words */
    private static function containsAny(string $hay, array $words): bool
    {
        foreach ($words as $w) {
            if ($w !== '' && str_contains($hay, $w)) {
                return true;
            }
        }
        return false;
    }
}
