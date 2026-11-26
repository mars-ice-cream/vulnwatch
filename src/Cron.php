<?php

namespace GlpiPlugin\Vulnwatch;

use CronTask;
use GlpiPlugin\Vulnwatch\Matching\Analyzer;
use GlpiPlugin\Vulnwatch\Source\FeedConnector;
use GlpiPlugin\Vulnwatch\Source\KevConnector;
use GlpiPlugin\Vulnwatch\Source\NvdConnector;
use GlpiPlugin\Vulnwatch\Source\SourceConnectorInterface;

/**
 * Actions automatiques natives GLPI, séparées par étape :
 *  - vulnwatchCollect : flux, NVD, KEV (chaque connecteur isolé : l'échec de l'un n'arrête pas les autres) ;
 *  - vulnwatchAnalyze : rapprochement local et suivi des corrections.
 * Les tickets ne sont jamais créés automatiquement : uniquement à la demande, depuis une alerte.
 */
final class Cron extends \CommonGLPI
{
    public static function registerTasks(): void
    {
        CronTask::register(self::class, 'vulnwatchCollect', HOUR_TIMESTAMP, ['param' => 20, 'state' => CronTask::STATE_WAITING, 'mode' => CronTask::MODE_EXTERNAL,
            'comment' => 'VulnWatch : collecte des sources (flux, NVD, KEV)']);
        CronTask::register(self::class, 'vulnwatchAnalyze', HOUR_TIMESTAMP, ['state' => CronTask::STATE_WAITING, 'mode' => CronTask::MODE_EXTERNAL,
            'comment' => 'VulnWatch : rapprochement inventaire et suivi des corrections']);
    }

    public static function cronInfo(string $name): array
    {
        return match ($name) {
            'vulnwatchCollect' => ['description' => __('Collecte des sources de vulnérabilités', 'vulnwatch'), 'parameter' => __('Budget par connecteur', 'vulnwatch')],
            'vulnwatchAnalyze' => ['description' => __('Rapprochement inventaire / vulnérabilités', 'vulnwatch')],
            default => [],
        };
    }

    /** @return list<SourceConnectorInterface> */
    public static function connectors(): array
    {
        return [new FeedConnector(), new NvdConnector(), new KevConnector()];
    }

    public static function cronVulnwatchCollect(?CronTask $task = null): int
    {
        $budget = $task ? max(1, (int) $task->fields['param']) : 20;
        $any = false;
        foreach (self::connectors() as $c) {
            try {
                $r = $c->run($budget);
            } catch (\Throwable $e) {
                $r = ['ok' => false, 'done' => 0, 'errors' => 1, 'message' => $e->getMessage()];
            }
            $msg = sprintf('%s : %s', $c->getLabel(), $r['message']);
            Logger::log($msg);
            $task?->log($msg);
            $task?->addVolume($r['done']);
            $any = $any || $r['done'] > 0;
        }
        return $any ? 1 : 0;
    }

    public static function cronVulnwatchAnalyze(?CronTask $task = null): int
    {
        $stats = (new Analyzer())->run();
        $task?->log(json_encode($stats));
        $task?->addVolume($stats['evaluations']);
        return 1;
    }
}
