<?php

/**
 * Schéma SQL du plugin. Chaque entrée = CREATE TABLE idempotent.
 * Conventions GLPI 11 : InnoDB, utf8mb4_unicode_ci, ROW_FORMAT=DYNAMIC,
 * clés "int unsigned", dates en "timestamp NULL".
 */

$opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC';

return [
    // Flux RSS / Atom configurables depuis l'interface
    'glpi_plugin_vulnwatch_feeds' => "CREATE TABLE IF NOT EXISTS `glpi_plugin_vulnwatch_feeds` (
        `id` int unsigned NOT NULL AUTO_INCREMENT,
        `entities_id` int unsigned NOT NULL DEFAULT '0',
        `is_recursive` tinyint NOT NULL DEFAULT '1',
        `name` varchar(255) NOT NULL DEFAULT '',
        `url` varchar(2048) NOT NULL DEFAULT '',
        `is_active` tinyint NOT NULL DEFAULT '1',
        `frequency` int unsigned NOT NULL DEFAULT '60' COMMENT 'minutes',
        `filter_include` text,
        `filter_exclude` text,
        `last_attempt` timestamp NULL DEFAULT NULL,
        `last_success` timestamp NULL DEFAULT NULL,
        `last_error` text,
        `last_error_date` timestamp NULL DEFAULT NULL,
        `last_status` varchar(20) NOT NULL DEFAULT 'never',
        `last_items_count` int unsigned NOT NULL DEFAULT '0',
        `last_new_count` int unsigned NOT NULL DEFAULT '0',
        `http_etag` varchar(255) DEFAULT NULL,
        `http_last_modified` varchar(255) DEFAULT NULL,
        `comment` text,
        `date_creation` timestamp NULL DEFAULT NULL,
        `date_mod` timestamp NULL DEFAULT NULL,
        PRIMARY KEY (`id`),
        KEY `entities_id` (`entities_id`),
        KEY `is_active` (`is_active`)
    ) $opts",

    // Articles de flux (dédupliqués par flux + identifiant d'article)
    'glpi_plugin_vulnwatch_bulletins' => "CREATE TABLE IF NOT EXISTS `glpi_plugin_vulnwatch_bulletins` (
        `id` int unsigned NOT NULL AUTO_INCREMENT,
        `plugin_vulnwatch_feeds_id` int unsigned NOT NULL DEFAULT '0',
        `guid_hash` char(64) NOT NULL,
        `link_hash` char(64) NOT NULL DEFAULT '',
        `title` varchar(1024) NOT NULL DEFAULT '',
        `link` varchar(2048) NOT NULL DEFAULT '',
        `summary` text,
        `date_published` timestamp NULL DEFAULT NULL,
        `cve_count` int unsigned NOT NULL DEFAULT '0',
        `review_status` varchar(20) NOT NULL DEFAULT 'linked' COMMENT 'linked|to_review|processed|dismissed',
        `review_reason` varchar(255) NOT NULL DEFAULT '',
        `users_id_review` int unsigned NOT NULL DEFAULT '0',
        `date_review` timestamp NULL DEFAULT NULL,
        `date_creation` timestamp NULL DEFAULT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `feed_guid` (`plugin_vulnwatch_feeds_id`, `guid_hash`),
        KEY `link_hash` (`link_hash`),
        KEY `review_status` (`review_status`)
    ) $opts",

    // Base locale de CVE (données publiques, non cloisonnées par entité)
    'glpi_plugin_vulnwatch_cves' => "CREATE TABLE IF NOT EXISTS `glpi_plugin_vulnwatch_cves` (
        `id` int unsigned NOT NULL AUTO_INCREMENT,
        `cve_id` varchar(32) NOT NULL,
        `description` text,
        `cvss_score` decimal(3,1) DEFAULT NULL,
        `cvss_version` varchar(8) DEFAULT NULL,
        `cvss_vector` varchar(255) DEFAULT NULL,
        `severity` varchar(16) DEFAULT NULL,
        `vuln_status` varchar(64) DEFAULT NULL,
        `date_published` timestamp NULL DEFAULT NULL,
        `date_source_mod` timestamp NULL DEFAULT NULL,
        `is_kev` tinyint NOT NULL DEFAULT '0',
        `kev_date_added` date DEFAULT NULL,
        `kev_due_date` date DEFAULT NULL,
        `kev_ransomware` varchar(32) DEFAULT NULL,
        `epss_score` decimal(6,5) DEFAULT NULL,
        `nvd_status` varchar(16) NOT NULL DEFAULT 'pending' COMMENT 'pending|ok|not_found|error',
        `nvd_error` text,
        `nvd_fetched_at` timestamp NULL DEFAULT NULL,
        `origin` varchar(32) NOT NULL DEFAULT 'feed' COMMENT 'feed|manual|nvd_sync|kev|import',
        `data_hash` char(64) NOT NULL DEFAULT '',
        `date_creation` timestamp NULL DEFAULT NULL,
        `date_mod` timestamp NULL DEFAULT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `cve_id` (`cve_id`),
        KEY `nvd_status` (`nvd_status`),
        KEY `is_kev` (`is_kev`)
    ) $opts",

    'glpi_plugin_vulnwatch_cves_bulletins' => "CREATE TABLE IF NOT EXISTS `glpi_plugin_vulnwatch_cves_bulletins` (
        `id` int unsigned NOT NULL AUTO_INCREMENT,
        `plugin_vulnwatch_cves_id` int unsigned NOT NULL,
        `plugin_vulnwatch_bulletins_id` int unsigned NOT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `unicity` (`plugin_vulnwatch_cves_id`, `plugin_vulnwatch_bulletins_id`),
        KEY `plugin_vulnwatch_bulletins_id` (`plugin_vulnwatch_bulletins_id`)
    ) $opts",

    // Critères d'applicabilité (cpeMatch NVD), un enregistrement par critère
    'glpi_plugin_vulnwatch_criteria' => "CREATE TABLE IF NOT EXISTS `glpi_plugin_vulnwatch_criteria` (
        `id` int unsigned NOT NULL AUTO_INCREMENT,
        `plugin_vulnwatch_cves_id` int unsigned NOT NULL,
        `source` varchar(32) NOT NULL DEFAULT 'nvd',
        `config_index` int unsigned NOT NULL DEFAULT '0',
        `node_index` int unsigned NOT NULL DEFAULT '0',
        `criteria` varchar(512) NOT NULL DEFAULT '',
        `part` char(1) NOT NULL DEFAULT 'a',
        `vendor` varchar(255) NOT NULL DEFAULT '',
        `product` varchar(255) NOT NULL DEFAULT '',
        `cpe_version` varchar(128) NOT NULL DEFAULT '*',
        `cpe_update` varchar(128) NOT NULL DEFAULT '*',
        `target_sw` varchar(128) NOT NULL DEFAULT '*',
        `target_hw` varchar(128) NOT NULL DEFAULT '*',
        `version_start_including` varchar(128) DEFAULT NULL,
        `version_start_excluding` varchar(128) DEFAULT NULL,
        `version_end_including` varchar(128) DEFAULT NULL,
        `version_end_excluding` varchar(128) DEFAULT NULL,
        `is_vulnerable` tinyint NOT NULL DEFAULT '1',
        `conditions` text COMMENT 'conditions de configuration (AND) non vérifiables',
        PRIMARY KEY (`id`),
        KEY `plugin_vulnwatch_cves_id` (`plugin_vulnwatch_cves_id`),
        KEY `vendor_product` (`vendor`(100), `product`(100))
    ) $opts",

    // Associations logiciel GLPI <-> produit CPE, réutilisables
    'glpi_plugin_vulnwatch_mappings' => "CREATE TABLE IF NOT EXISTS `glpi_plugin_vulnwatch_mappings` (
        `id` int unsigned NOT NULL AUTO_INCREMENT,
        `name_norm` varchar(255) NOT NULL,
        `manufacturer_norm` varchar(255) NOT NULL DEFAULT '',
        `sample_name` varchar(255) NOT NULL DEFAULT '',
        `sample_manufacturer` varchar(255) NOT NULL DEFAULT '',
        `vendor` varchar(255) NOT NULL,
        `product` varchar(255) NOT NULL,
        `status` varchar(16) NOT NULL DEFAULT 'proposed' COMMENT 'auto|proposed|validated|rejected',
        `confidence` tinyint unsigned NOT NULL DEFAULT '0',
        `reason` varchar(512) NOT NULL DEFAULT '',
        `users_id` int unsigned NOT NULL DEFAULT '0',
        `date_decision` timestamp NULL DEFAULT NULL,
        `comment` text,
        `date_creation` timestamp NULL DEFAULT NULL,
        `date_mod` timestamp NULL DEFAULT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `unicity` (`name_norm`(150), `manufacturer_norm`(100), `vendor`(100), `product`(100)),
        KEY `status` (`status`)
    ) $opts",

    // Résultat d'évaluation : 1 ligne par (CVE, version logicielle GLPI)
    'glpi_plugin_vulnwatch_findings' => "CREATE TABLE IF NOT EXISTS `glpi_plugin_vulnwatch_findings` (
        `id` int unsigned NOT NULL AUTO_INCREMENT,
        `plugin_vulnwatch_cves_id` int unsigned NOT NULL,
        `softwareversions_id` int unsigned NOT NULL,
        `softwares_id` int unsigned NOT NULL DEFAULT '0',
        `plugin_vulnwatch_mappings_id` int unsigned NOT NULL DEFAULT '0',
        `plugin_vulnwatch_criteria_id` int unsigned NOT NULL DEFAULT '0',
        `status` varchar(16) NOT NULL COMMENT 'established|to_check|not_evaluated|not_affected|rejected',
        `confidence` tinyint unsigned NOT NULL DEFAULT '0',
        `version_found` varchar(255) NOT NULL DEFAULT '',
        `fixed_version` varchar(128) DEFAULT NULL,
        `rule_text` text,
        `reasons` text,
        `eval_hash` char(64) NOT NULL DEFAULT '',
        `date_first_seen` timestamp NULL DEFAULT NULL,
        `date_eval` timestamp NULL DEFAULT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `unicity` (`plugin_vulnwatch_cves_id`, `softwareversions_id`),
        KEY `softwareversions_id` (`softwareversions_id`),
        KEY `softwares_id` (`softwares_id`),
        KEY `status` (`status`)
    ) $opts",

    // Rattachement d'un résultat aux actifs + suivi de correction
    'glpi_plugin_vulnwatch_findings_items' => "CREATE TABLE IF NOT EXISTS `glpi_plugin_vulnwatch_findings_items` (
        `id` int unsigned NOT NULL AUTO_INCREMENT,
        `plugin_vulnwatch_findings_id` int unsigned NOT NULL,
        `plugin_vulnwatch_cves_id` int unsigned NOT NULL,
        `itemtype` varchar(100) NOT NULL,
        `items_id` int unsigned NOT NULL,
        `entities_id` int unsigned NOT NULL DEFAULT '0',
        `state` varchar(16) NOT NULL DEFAULT 'active' COMMENT 'active|fixed|unverified|out_of_scope|closed',
        `fix_kind` varchar(16) DEFAULT NULL COMMENT 'updated|removed|source_update|mapping_rejected',
        `fix_detail` varchar(255) DEFAULT NULL,
        `is_regression` tinyint NOT NULL DEFAULT '0',
        `inventory_date` timestamp NULL DEFAULT NULL COMMENT 'date du dernier inventaire au moment du constat',
        `date_first_seen` timestamp NULL DEFAULT NULL,
        `date_last_seen` timestamp NULL DEFAULT NULL,
        `date_fixed` timestamp NULL DEFAULT NULL,
        `plugin_vulnwatch_campaigns_id` int unsigned NOT NULL DEFAULT '0',
        PRIMARY KEY (`id`),
        UNIQUE KEY `unicity` (`plugin_vulnwatch_findings_id`, `itemtype`, `items_id`),
        KEY `item` (`itemtype`, `items_id`),
        KEY `entities_id` (`entities_id`),
        KEY `state` (`state`),
        KEY `plugin_vulnwatch_cves_id` (`plugin_vulnwatch_cves_id`),
        KEY `plugin_vulnwatch_campaigns_id` (`plugin_vulnwatch_campaigns_id`)
    ) $opts",

    // Contexte d'actif non natif : criticité et exposition réseau
    'glpi_plugin_vulnwatch_assetcontexts' => "CREATE TABLE IF NOT EXISTS `glpi_plugin_vulnwatch_assetcontexts` (
        `id` int unsigned NOT NULL AUTO_INCREMENT,
        `itemtype` varchar(100) NOT NULL,
        `items_id` int unsigned NOT NULL,
        `criticality` tinyint unsigned NOT NULL DEFAULT '0' COMMENT '0 non renseignée,1 faible,2 moyenne,3 haute',
        `exposure` tinyint unsigned NOT NULL DEFAULT '0' COMMENT '0 inconnue,1 interne,2 exposée Internet',
        `users_id` int unsigned NOT NULL DEFAULT '0',
        `date_mod` timestamp NULL DEFAULT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `item` (`itemtype`, `items_id`)
    ) $opts",

    // Versions cibles approuvées et fin de support
    'glpi_plugin_vulnwatch_targets' => "CREATE TABLE IF NOT EXISTS `glpi_plugin_vulnwatch_targets` (
        `id` int unsigned NOT NULL AUTO_INCREMENT,
        `entities_id` int unsigned NOT NULL DEFAULT '0',
        `is_recursive` tinyint NOT NULL DEFAULT '1',
        `software_name` varchar(255) NOT NULL,
        `name_norm` varchar(255) NOT NULL DEFAULT '',
        `target_version` varchar(128) DEFAULT NULL,
        `eol_date` date DEFAULT NULL,
        `eol_branch` varchar(128) DEFAULT NULL COMMENT 'versions < à cette branche = fin de support',
        `source` varchar(1024) NOT NULL DEFAULT '',
        `comment` text,
        `users_id` int unsigned NOT NULL DEFAULT '0',
        `date_creation` timestamp NULL DEFAULT NULL,
        `date_mod` timestamp NULL DEFAULT NULL,
        PRIMARY KEY (`id`),
        KEY `entities_id` (`entities_id`),
        KEY `name_norm` (`name_norm`)
    ) $opts",

    // Campagnes de correction = 1 ticket par (entité, produit, version cible)
    'glpi_plugin_vulnwatch_campaigns' => "CREATE TABLE IF NOT EXISTS `glpi_plugin_vulnwatch_campaigns` (
        `id` int unsigned NOT NULL AUTO_INCREMENT,
        `entities_id` int unsigned NOT NULL DEFAULT '0',
        `name` varchar(255) NOT NULL DEFAULT '',
        `product_key` varchar(255) NOT NULL,
        `target_version` varchar(128) NOT NULL DEFAULT '',
        `tickets_id` int unsigned NOT NULL DEFAULT '0',
        `is_open` tinyint NOT NULL DEFAULT '1',
        `users_id` int unsigned NOT NULL DEFAULT '0',
        `date_creation` timestamp NULL DEFAULT NULL,
        `date_mod` timestamp NULL DEFAULT NULL,
        PRIMARY KEY (`id`),
        KEY `lookup` (`entities_id`, `product_key`(150), `target_version`(50), `is_open`),
        KEY `tickets_id` (`tickets_id`)
    ) $opts",

    // Journal des décisions manuelles et exceptions
    'glpi_plugin_vulnwatch_decisionlogs' => "CREATE TABLE IF NOT EXISTS `glpi_plugin_vulnwatch_decisionlogs` (
        `id` int unsigned NOT NULL AUTO_INCREMENT,
        `users_id` int unsigned NOT NULL DEFAULT '0',
        `entities_id` int unsigned NOT NULL DEFAULT '0',
        `action` varchar(64) NOT NULL,
        `object_type` varchar(64) NOT NULL,
        `object_id` int unsigned NOT NULL DEFAULT '0',
        `details` text,
        `date_creation` timestamp NULL DEFAULT NULL,
        PRIMARY KEY (`id`),
        KEY `object` (`object_type`, `object_id`),
        KEY `date_creation` (`date_creation`)
    ) $opts",
];
