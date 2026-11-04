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
