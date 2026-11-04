<?php

namespace GlpiPlugin\Vulnwatch\Source;

/**
 * Analyse RSS 2.0, RSS 1.0 (RDF) et Atom.
 *
 * Sécurité XML : tout DOCTYPE est refusé (entités externes, XXE, « billion laughs »),
 * LIBXML_NONET interdit tout accès réseau, aucune substitution d'entité (pas de LIBXML_NOENT).
 */
final class FeedParser
{
    public const CVE_REGEX = '/\bCVE-(\d{4})-(\d{4,7})\b/i';

    /**
     * @return array{format:string, title:string, items:list<array{guid:string,title:string,link:string,summary:string,published:?string,cves:list<string>}>}
     */
    public static function parse(string $xml): array
    {
        $xml = ltrim($xml, "\xEF\xBB\xBF \t\r\n");
        if ($xml === '') {
            throw new \InvalidArgumentException('Contenu vide');
        }
        if (preg_match('/<!DOCTYPE|<!ENTITY/i', substr($xml, 0, 4096)) || stripos($xml, '<!ENTITY') !== false) {
            throw new \InvalidArgumentException('DOCTYPE/ENTITY refusé dans le flux (protection XXE)');
        }
        $prev = libxml_use_internal_errors(true);
        $doc = new \DOMDocument();
        $ok = $doc->loadXML($xml, LIBXML_NONET | LIBXML_NOCDATA | LIBXML_COMPACT);
        $errors = libxml_get_errors();
        libxml_clear_errors();
        libxml_use_internal_errors($prev);
        if (!$ok || $doc->documentElement === null) {
            $msg = $errors[0]->message ?? 'XML invalide';
            throw new \InvalidArgumentException('XML invalide : ' . trim($msg));
        }
        $root = $doc->documentElement;
        $rootName = strtolower($root->localName);

        $items = [];
        $format = 'unknown';
        $title = '';
        if ($rootName === 'feed') {
            $format = 'atom';
            $title = self::childText($root, 'title');
            foreach (self::children($root, 'entry') as $entry) {
                $link = '';
                foreach (self::children($entry, 'link') as $l) {
                    $rel = $l->getAttribute('rel') ?: 'alternate';
                    if ($rel === 'alternate' || $link === '') {
                        $link = $l->getAttribute('href');
                    }
                }
                $summary = self::childText($entry, 'summary') ?: self::childText($entry, 'content');
                $items[] = self::item(
                    self::childText($entry, 'id'),
                    self::childText($entry, 'title'),
                    $link,
                    $summary,
                    self::childText($entry, 'updated') ?: self::childText($entry, 'published'),
                );
            }
        } elseif ($rootName === 'rss' || $rootName === 'rdf') {
            $format = $rootName === 'rss' ? 'rss2' : 'rss1';
            $channel = self::children($root, 'channel')[0] ?? $root;
            $title = self::childText($channel, 'title');
            $entries = self::children($channel, 'item');
            if ($entries === []) {
                $entries = self::children($root, 'item'); // RSS 1.0 : items au niveau racine
            }
            foreach ($entries as $entry) {
                $summary = self::childText($entry, 'encoded') ?: self::childText($entry, 'description');
                $items[] = self::item(
                    self::childText($entry, 'guid') ?: $entry->getAttribute('rdf:about'),
                    self::childText($entry, 'title'),
                    self::childText($entry, 'link'),
                    $summary,
                    self::childText($entry, 'pubDate') ?: self::childText($entry, 'date'),
                );
            }
        } else {
            throw new \InvalidArgumentException('Format non reconnu (ni RSS ni Atom) : <' . $rootName . '>');
        }
        return ['format' => $format, 'title' => $title, 'items' => $items];
    }

    /** @return array{guid:string,title:string,link:string,summary:string,published:?string,cves:list<string>} */
    private static function item(string $guid, string $title, string $link, string $html, string $date): array
    {
        $title = self::cleanText($title, 1000);
        $summary = self::cleanText($html, 4000);
        $link = trim($link);
        if (!preg_match('#^https?://#i', $link)) {
            $link = ''; // pas de javascript:, data:, etc.
        }
        if ($guid === '') {
            $guid = $link !== '' ? $link : sha1($title . '|' . $summary);
        }
        $ts = $date !== '' ? strtotime($date) : false;
        return [
            'guid'      => trim($guid),
            'title'     => $title,
            'link'      => $link,
            'summary'   => $summary,
            'published' => $ts ? gmdate('Y-m-d H:i:s', $ts) : null,
            'cves'      => self::extractCves($title . ' ' . $summary . ' ' . $html . ' ' . $link),
        ];
    }

    /** @return list<string> */
    public static function extractCves(string $text): array
    {
        preg_match_all(self::CVE_REGEX, $text, $m, PREG_SET_ORDER);
        $out = [];
        foreach ($m as $match) {
            $out['CVE-' . $match[1] . '-' . $match[2]] = true;
        }
        return array_keys($out);
    }

    /** Texte brut : balises supprimées, entités décodées, espaces compactés. Affiché ensuite échappé. */
    public static function cleanText(string $html, int $max): string
    {
        $text = preg_replace('#<(script|style)\b[^>]*>.*?</\1>#is', ' ', $html) ?? '';
        $text = preg_replace('#<br\s*/?>|</p>|</li>#i', "\n", $text) ?? '';
        $text = html_entity_decode(strip_tags($text), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $text = preg_replace('/[ \t\x{00A0}]+/u', ' ', $text) ?? '';
        $text = trim(preg_replace("/\n\s*\n+/", "\n", $text) ?? '');
        return mb_substr($text, 0, $max);
    }

    /** @return list<\DOMElement> */
    private static function children(\DOMElement $el, string $localName): array
    {
        $out = [];
        foreach ($el->childNodes as $child) {
            if ($child instanceof \DOMElement && strcasecmp($child->localName, $localName) === 0) {
                $out[] = $child;
            }
        }
        return $out;
    }

    private static function childText(\DOMElement $el, string $localName): string
    {
        $c = self::children($el, $localName)[0] ?? null;
        return $c ? trim($c->textContent) : '';
    }
}
