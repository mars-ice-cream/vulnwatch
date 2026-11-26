<?php

namespace GlpiPlugin\Vulnwatch\Http;

use GlpiPlugin\Vulnwatch\Config;

/**
 * Client HTTP durci pour toutes les récupérations du plugin.
 *
 * - schémas http/https uniquement, ports autorisés configurables (80,443 par défaut) ;
 * - résolution DNS faite par le plugin, puis connexion épinglée sur l'IP validée
 *   (CURLOPT_RESOLVE) : pas de contournement par DNS rebinding ;
 * - adresses privées, loopback, link-local, CGNAT, multicast, réservées et
 *   métadonnées cloud refusées, sauf hôte/CIDR explicitement autorisé ;
 * - redirections suivies manuellement (max 3), chaque saut est revalidé ;
 * - taille maximale et délai maximal ; pas d'identifiants ni cookies transmis.
 */
final class SafeHttpClient
{
    private const MAX_REDIRECTS = 3;
    private const USER_AGENT = 'GLPI-VulnWatch/1.0 (+https://glpi-project.org)';

    /** @var callable|null résolveur injectable (tests) : fn(string $host): string[] */
    private $resolver;

    public function __construct(?callable $resolver = null)
    {
        $this->resolver = $resolver;
    }

    /**
     * @param array<string,string> $headers
     * @return array{status:int, body:string, headers:array<string,string>, url:string}
     * @throws HttpException
     */
    public function get(string $url, array $headers = []): array
    {
        $current = $url;
        for ($hop = 0; $hop <= self::MAX_REDIRECTS; $hop++) {
            [$parts, $ip] = $this->validateUrl($current);
            $response = $this->doRequest($current, $parts, $ip, $headers);
            if (in_array($response['status'], [301, 302, 303, 307, 308], true)) {
                $location = $response['headers']['location'] ?? '';
                if ($location === '') {
                    throw new HttpException('Redirection sans en-tête Location');
                }
                $current = self::resolveRelative($current, $location);
                continue;
            }
            $response['url'] = $current;
            return $response;
        }
        throw new HttpException('Trop de redirections');
    }

    /**
     * @return array{0:array<string,mixed>,1:string}
     * @throws HttpException
     */
    public function validateUrl(string $url): array
    {
        if (strlen($url) > 2048) {
            throw new HttpException('URL trop longue');
        }
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new HttpException('URL invalide');
        }
        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new HttpException('Schéma non autorisé : ' . $scheme);
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new HttpException('Identifiants dans l\'URL refusés');
        }
        $port = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
        $allowedPorts = array_filter(array_map('intval', explode(',', Config::get('http_allowed_ports'))));
        if (!in_array($port, $allowedPorts, true)) {
            throw new HttpException('Port non autorisé : ' . $port);
        }
        $host = strtolower(trim($parts['host'], '[]'));
        $ips = $this->resolve($host);
        if ($ips === []) {
            throw new HttpException('Résolution DNS impossible pour ' . $host);
        }
        $allowlisted = $this->isHostAllowlisted($host);
        foreach ($ips as $ip) {
            // Toutes les adresses doivent être acceptables (évite un mélange public/privé)
            if (!self::isPublicIp($ip) && !$allowlisted && !$this->isIpAllowlisted($ip)) {
                throw new HttpException(sprintf('Adresse interne refusée (%s → %s). Ajoutez l\'hôte à la liste des sources internes autorisées si c\'est voulu.', $host, $ip));
            }
        }
        $parts['port'] = $port;
        $parts['host'] = $host;
        return [$parts, $ips[0]];
    }

    /** @return string[] */
    private function resolve(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [$host];
        }
        if ($this->resolver !== null) {
            return ($this->resolver)($host);
        }
        $ips = [];
        $records = @dns_get_record($host, DNS_A | DNS_AAAA) ?: [];
        foreach ($records as $r) {
            if (isset($r['ip'])) {
                $ips[] = $r['ip'];
            } elseif (isset($r['ipv6'])) {
                $ips[] = $r['ipv6'];
            }
        }
        if ($ips === []) {
            $v4 = @gethostbynamel($host) ?: [];
            $ips = $v4;
        }
        return array_values(array_unique($ips));
    }

    public static function isPublicIp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        // IPv4 mappée en IPv6 (::ffff:10.0.0.1)
        if (preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i', $ip, $m)) {
            $ip = $m[1];
        }
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
        $blocked = [
            '0.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '192.0.0.0/24',
            '192.0.2.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
            '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8', '64:ff9b::/96', '2001:db8::/32',
        ];
        foreach ($blocked as $cidr) {
            if (self::ipInCidr($ip, $cidr)) {
                return false;
            }
        }
        return true;
    }

    public static function ipInCidr(string $ip, string $cidr): bool
    {
        [$net, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
        $ipBin = @inet_pton($ip);
        $netBin = @inet_pton((string) $net);
        if ($ipBin === false || $netBin === false || strlen($ipBin) !== strlen($netBin)) {
            return false;
        }
        $bits = $bits === null ? strlen($ipBin) * 8 : (int) $bits;
        $bytes = intdiv($bits, 8);
        if (substr($ipBin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
            return false;
        }
        $rem = $bits % 8;
        if ($rem === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rem)) & 0xFF;
        return (ord($ipBin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
    }

    /** @return string[] */
    private function allowlist(): array
    {
        $lines = preg_split('/[\r\n,]+/', Config::get('http_internal_allowlist')) ?: [];
        return array_values(array_filter(array_map(static fn($l) => strtolower(trim($l)), $lines)));
    }

    private function isHostAllowlisted(string $host): bool
    {
        foreach ($this->allowlist() as $entry) {
            if (!str_contains($entry, '/') && !filter_var($entry, FILTER_VALIDATE_IP) && $entry === $host) {
                return true;
            }
        }
        return false;
    }

    private function isIpAllowlisted(string $ip): bool
    {
        foreach ($this->allowlist() as $entry) {
            if (filter_var($entry, FILTER_VALIDATE_IP) && inet_pton($entry) === inet_pton($ip)) {
                return true;
            }
            if (str_contains($entry, '/') && self::ipInCidr($ip, $entry)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array<string,mixed> $parts
     * @param array<string,string> $headers
     * @return array{status:int, body:string, headers:array<string,string>}
     */
    private function doRequest(string $url, array $parts, string $ip, array $headers): array
    {
        $maxBytes = max(65536, Config::getInt('http_max_bytes'));
        $timeout = max(3, Config::getInt('http_timeout'));
        $body = '';
        $respHeaders = [];
        $tooBig = false;

        $ch = curl_init();
        $resolveIp = str_contains($ip, ':') ? '[' . $ip . ']' : $ip;
        $opts = [
            CURLOPT_URL            => $url,
            CURLOPT_RESOLVE        => [$parts['host'] . ':' . $parts['port'] . ':' . $resolveIp],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => min(10, $timeout),
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_USERAGENT      => self::USER_AGENT,
            CURLOPT_ENCODING       => '',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => array_map(static fn($k, $v) => $k . ': ' . $v, array_keys($headers), $headers),
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$respHeaders): int {
                if (str_contains($line, ':')) {
                    [$k, $v] = explode(':', $line, 2);
                    $respHeaders[strtolower(trim($k))] = trim($v);
                } elseif (preg_match('#^HTTP/#', $line)) {
                    $respHeaders = [];
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION  => static function ($ch, string $chunk) use (&$body, &$tooBig, $maxBytes): int {
                if (strlen($body) + strlen($chunk) > $maxBytes) {
                    $tooBig = true;
                    return 0; // interrompt le transfert
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ];
        $proxy = Config::get('http_proxy');
        if ($proxy !== '') {
            // Avec un proxy sortant, la résolution est faite par le proxy : l'épinglage
            // d'IP ne s'applique plus, mais la validation de l'URL reste effective.
            $opts[CURLOPT_PROXY] = $proxy;
        } else {
            // Ignore les variables d'environnement http(s)_proxy : l'épinglage d'IP doit s'appliquer
            $opts[CURLOPT_PROXY] = '';
        }
        curl_setopt_array($ch, $opts);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if ($tooBig) {
            throw new HttpException(sprintf('Réponse trop volumineuse (> %d octets)', $maxBytes));
        }
        if ($ok === false) {
            throw new HttpException('Échec de la requête : ' . $err);
        }
        return ['status' => $status, 'body' => $body, 'headers' => $respHeaders];
    }

    public static function resolveRelative(string $base, string $location): string
    {
        if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $location)) {
            return $location;
        }
        $b = parse_url($base);
        $origin = $b['scheme'] . '://' . $b['host'] . (isset($b['port']) ? ':' . $b['port'] : '');
        if (str_starts_with($location, '//')) {
            return $b['scheme'] . ':' . $location;
        }
        if (str_starts_with($location, '/')) {
            return $origin . $location;
        }
        $path = $b['path'] ?? '/';
        $dir = substr($path, 0, (int) strrpos($path, '/') + 1);
        return $origin . $dir . $location;
    }
}
