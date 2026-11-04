<?php

namespace GlpiPlugin\Vulnwatch;

/** Journal technique : files/_log/vulnwatch.log */
final class Logger
{
    public static function log(string $message): void
    {
        \Toolbox::logInFile('vulnwatch', $message . "\n", true, false);
    }

    /** Trace d'une décision manuelle (association, veille, ticket, exception). */
    public static function decision(string $action, string $objectType, int $objectId, array $details = [], int $entitiesId = 0): void
    {
        /** @var \DBmysql $DB */
        global $DB;
        $DB->insert('glpi_plugin_vulnwatch_decisionlogs', [
            'users_id'      => (int) \Session::getLoginUserID(),
            'entities_id'   => $entitiesId,
            'action'        => $action,
            'object_type'   => $objectType,
            'object_id'     => $objectId,
            'details'       => json_encode($details, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            'date_creation' => $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s'),
        ]);
    }
}
