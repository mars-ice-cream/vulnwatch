<?php

use GlpiPlugin\Vulnwatch\Config;
use GlpiPlugin\Vulnwatch\Cron;
use GlpiPlugin\Vulnwatch\Profile as VulnwatchProfile;

function plugin_vulnwatch_install(): bool
{
    /** @var DBmysql $DB */
    global $DB;

    $migration = new Migration(PLUGIN_VULNWATCH_VERSION);
    $schema = require __DIR__ . '/install/schema.php';
    foreach ($schema as $table => $sql) {
        if (!$DB->tableExists($table)) {
            $DB->doQuery($sql);
        }
    }

    // Les futures montées de version ajouteront ici leurs $migration->addField(...)
    $migration->executeMigration();

    Config::installDefaults();
    // Colonnes affichées par défaut dans les listes (préférences globales, modifiables par chacun)
    $defaults = [
        \GlpiPlugin\Vulnwatch\Feed::class   => [2, 3, 5, 6, 7, 80],
        \GlpiPlugin\Vulnwatch\Target::class => [3, 4, 5, 6, 80],
    ];
    foreach ($defaults as $itemtype => $nums) {
        foreach ($nums as $rank => $num) {
            $DB->updateOrInsert('glpi_displaypreferences', ['rank' => $rank + 1],
                ['itemtype' => $itemtype, 'num' => $num, 'users_id' => 0, 'interface' => 'central']);
        }
    }
    if (Config::get('official_feeds_seeded') !== '1') {
        \GlpiPlugin\Vulnwatch\Feed::installOfficialFeeds();
        Config::set(['official_feeds_seeded' => '1']);
    }
    VulnwatchProfile::installRights();
    Cron::registerTasks();

    return true;
}

function plugin_vulnwatch_uninstall(): bool
{
    /** @var DBmysql $DB */
    global $DB;

    $schema = require __DIR__ . '/install/schema.php';
    foreach (array_keys($schema) as $table) {
        $DB->doQuery('DROP TABLE IF EXISTS ' . $DB->quoteName($table));
    }
    Config::uninstall();
    VulnwatchProfile::uninstallRights();
    CronTask::unregister('vulnwatch');
    $DB->delete('glpi_displaypreferences', ['itemtype' => [\GlpiPlugin\Vulnwatch\Feed::class, \GlpiPlugin\Vulnwatch\Target::class]]);

    return true;
}

/**
 * Nettoyage quand un actif est purgé dans GLPI.
 */
function plugin_vulnwatch_item_purge(CommonDBTM $item): void
{
    /** @var DBmysql $DB */
    global $DB;
    foreach (['glpi_plugin_vulnwatch_findings_items', 'glpi_plugin_vulnwatch_assetcontexts'] as $table) {
        $DB->delete($table, ['itemtype' => $item->getType(), 'items_id' => $item->getID()]);
    }
}
