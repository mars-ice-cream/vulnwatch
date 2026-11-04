<?php

namespace GlpiPlugin\Vulnwatch\Source;

use GlpiPlugin\Vulnwatch\Feed;
use GlpiPlugin\Vulnwatch\Http\SafeHttpClient;

/** Connecteur des flux RSS/Atom personnalisés. */
final class FeedConnector implements SourceConnectorInterface
{
    public function __construct(private ?SafeHttpClient $client = null)
    {
    }

    public function getKey(): string
    {
        return 'feeds';
    }

    public function getLabel(): string
    {
        return 'Flux RSS / Atom personnalisés';
    }

    public function isEnabled(): bool
    {
        return true;
    }

    public function describeOutboundData(): string
    {
        return 'GET sur l\'URL de chaque flux actif (en-têtes If-None-Match / If-Modified-Since). Aucune donnée d\'inventaire.';
    }

    public function run(int $budget): array
    {
        $done = $errors = 0;
        $msgs = [];
        foreach (Feed::getDueFeeds($budget) as $feed) {
            $r = Feed::sync($feed, $this->client);
            $r['ok'] ? $done++ : $errors++;
            if (!$r['ok']) {
                $msgs[] = $feed['name'] . ' : ' . $r['error'];
            }
        }
        return ['ok' => $errors === 0, 'done' => $done, 'errors' => $errors, 'message' => implode(' ; ', $msgs)];
    }
}
