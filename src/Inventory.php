<?php

namespace GlpiPlugin\Vulnwatch;

/**
 * Lecture de l'inventaire GLPI 11 (tables natives, lecture seule).
 *
 * Champs vérifiés sur GLPI 11.0.9 :
 *  - glpi_softwares (name, manufacturers_id, entities_id, is_deleted, is_template)
 *  - glpi_softwareversions (name = version, arch, operatingsystems_id)
 *  - glpi_items_softwareversions (itemtype, items_id, entities_id, is_deleted, is_deleted_item,
 *    is_template_item, is_dynamic, date_install) — lien supprimé par l'inventaire quand le logiciel
 *    disparaît ou change de version
 *  - glpi_items_operatingsystems (+ versions, éditions, architectures, service packs, kernelversions) —
 *    aucun champ « niveau de correctif » : le build Windows n'apparaît que via kernelversion/version
 *  - glpi_items_devicefirmwares / glpi_devicefirmwares (version, manufacturers_id) — selon l'agent/SNMP
 *  - last_inventory_update sur glpi_computers, glpi_networkequipments, glpi_phones, glpi_printers
 *  Aucune « criticité » native : le plugin la stocke dans glpi_plugin_vulnwatch_assetcontexts.
 */
final class Inventory
{
    /** Types d'actifs dont les logiciels sont évalués en V1 (CFG software_types ∩ inventaire agent). */
    public const SOFTWARE_ITEMTYPES = ['Computer', 'Phone'];

    /** Types affichant l'onglet (OS / firmware modélisés, couverture affichée comme « non évaluée »). */
    public const TAB_ITEMTYPES = ['Computer', 'Phone', 'NetworkEquipment', 'Printer'];

    /**
     * Logiciels installés (au moins un lien actif vers un actif pris en charge).
     * @return list<array{softwares_id:int,name:string,manufacturer:string,softwareversions_id:int,version:string,arch:string,installs:int}>
     */
    public static function installedSoftwareVersions(): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $rows = $DB->request([
            'SELECT' => [
                'glpi_softwares.id AS softwares_id', 'glpi_softwares.name AS name', 'glpi_manufacturers.name AS manufacturer',
                'glpi_softwareversions.id AS softwareversions_id', 'glpi_softwareversions.name AS version', 'glpi_softwareversions.arch AS arch',
                'COUNT' => 'glpi_items_softwareversions.id AS installs',
            ],
            'FROM' => 'glpi_items_softwareversions',
            'INNER JOIN' => [
                'glpi_softwareversions' => ['ON' => ['glpi_items_softwareversions' => 'softwareversions_id', 'glpi_softwareversions' => 'id']],
                'glpi_softwares' => ['ON' => ['glpi_softwareversions' => 'softwares_id', 'glpi_softwares' => 'id']],
            ],
            'LEFT JOIN' => [
                'glpi_manufacturers' => ['ON' => ['glpi_softwares' => 'manufacturers_id', 'glpi_manufacturers' => 'id']],
            ],
            'WHERE' => self::activeLinkCriteria() + ['glpi_softwares.is_deleted' => 0, 'glpi_softwares.is_template' => 0],
            'GROUPBY' => ['glpi_softwareversions.id'],
        ]);
        $out = [];
        foreach ($rows as $r) {
            $out[] = [
                'softwares_id' => (int) $r['softwares_id'], 'name' => (string) $r['name'], 'manufacturer' => (string) ($r['manufacturer'] ?? ''),
                'softwareversions_id' => (int) $r['softwareversions_id'], 'version' => (string) $r['version'], 'arch' => (string) ($r['arch'] ?? ''),
                'installs' => (int) $r['installs'],
            ];
        }
        return $out;
    }

    public static function activeLinkCriteria(): array
    {
        return [
            'glpi_items_softwareversions.is_deleted'       => 0,
            'glpi_items_softwareversions.is_deleted_item'  => 0,
            'glpi_items_softwareversions.is_template_item' => 0,
            'glpi_items_softwareversions.itemtype'         => self::SOFTWARE_ITEMTYPES,
        ];
    }

    /**
     * Liens actifs actif ↔ version pour un ensemble de versions, avec date d'inventaire et OS.
     * @param list<int> $versionIds
     * @return list<array{softwareversions_id:int,itemtype:string,items_id:int,entities_id:int,last_inventory_update:?string,os:string}>
     */
    public static function linksForVersions(array $versionIds): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        if ($versionIds === []) {
            return [];
        }
        $out = [];
        foreach (array_chunk($versionIds, 500) as $chunk) {
            foreach (self::SOFTWARE_ITEMTYPES as $itemtype) {
                $table = getTableForItemType($itemtype);
                $rows = $DB->request([
                    'SELECT' => [
                        'glpi_items_softwareversions.softwareversions_id', 'glpi_items_softwareversions.items_id',
                        'glpi_items_softwareversions.entities_id', "$table.last_inventory_update", 'glpi_operatingsystems.name AS os',
                    ],
                    'FROM' => 'glpi_items_softwareversions',
                    'INNER JOIN' => [$table => ['ON' => ['glpi_items_softwareversions' => 'items_id', $table => 'id']]],
                    'LEFT JOIN' => [
                        'glpi_items_operatingsystems' => ['ON' => ['glpi_items_operatingsystems' => 'items_id', $table => 'id',
                            ['AND' => ['glpi_items_operatingsystems.itemtype' => $itemtype, 'glpi_items_operatingsystems.is_deleted' => 0]]]],
                        'glpi_operatingsystems' => ['ON' => ['glpi_items_operatingsystems' => 'operatingsystems_id', 'glpi_operatingsystems' => 'id']],
                    ],
                    'WHERE' => [
                        'glpi_items_softwareversions.itemtype' => $itemtype,
                        'glpi_items_softwareversions.softwareversions_id' => $chunk,
                        'glpi_items_softwareversions.is_deleted' => 0,
                        'glpi_items_softwareversions.is_deleted_item' => 0,
                        'glpi_items_softwareversions.is_template_item' => 0,
                        "$table.is_deleted" => 0,
                        "$table.is_template" => 0,
                    ],
                ]);
                foreach ($rows as $r) {
                    $out[] = [
                        'softwareversions_id' => (int) $r['softwareversions_id'], 'itemtype' => $itemtype, 'items_id' => (int) $r['items_id'],
                        'entities_id' => (int) $r['entities_id'], 'last_inventory_update' => $r['last_inventory_update'], 'os' => (string) ($r['os'] ?? ''),
                    ];
                }
            }
        }
        return $out;
    }

    /** @return array{exists:bool, deleted:bool, last_inventory_update:?string, entities_id:int, name:string} */
    public static function assetState(string $itemtype, int $id): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        if (!in_array($itemtype, self::TAB_ITEMTYPES, true)) {
            return ['exists' => false, 'deleted' => false, 'last_inventory_update' => null, 'entities_id' => 0, 'name' => ''];
        }
        $row = $DB->request(['SELECT' => ['is_deleted', 'last_inventory_update', 'entities_id', 'name'], 'FROM' => getTableForItemType($itemtype), 'WHERE' => ['id' => $id]])->current();
        if (!$row) {
            return ['exists' => false, 'deleted' => false, 'last_inventory_update' => null, 'entities_id' => 0, 'name' => ''];
        }
        return ['exists' => true, 'deleted' => (bool) $row['is_deleted'], 'last_inventory_update' => $row['last_inventory_update'],
            'entities_id' => (int) $row['entities_id'], 'name' => (string) $row['name']];
    }

    /**
     * Versions actuellement installées d'un logiciel sur un actif : même softwares_id, ou même
     * nom/éditeur normalisés quand ils sont fournis. @return list<array{id:int,name:string}>
     */
    public static function versionsOfSoftwareOnItem(int $softwaresId, string $itemtype, int $itemsId, ?string $nameNorm = null, ?string $manufNorm = null): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $rows = $DB->request([
            'SELECT' => ['glpi_softwareversions.id', 'glpi_softwareversions.name', 'glpi_softwares.id AS sid', 'glpi_softwares.name AS sname', 'glpi_manufacturers.name AS manufacturer'],
            'FROM' => 'glpi_items_softwareversions',
            'INNER JOIN' => [
                'glpi_softwareversions' => ['ON' => ['glpi_items_softwareversions' => 'softwareversions_id', 'glpi_softwareversions' => 'id']],
                'glpi_softwares' => ['ON' => ['glpi_softwareversions' => 'softwares_id', 'glpi_softwares' => 'id']],
            ],
            'LEFT JOIN' => ['glpi_manufacturers' => ['ON' => ['glpi_softwares' => 'manufacturers_id', 'glpi_manufacturers' => 'id']]],
            'WHERE' => ['glpi_items_softwareversions.itemtype' => $itemtype, 'glpi_items_softwareversions.items_id' => $itemsId, 'glpi_items_softwareversions.is_deleted' => 0],
        ]);
        $out = [];
        foreach ($rows as $r) {
            $same = (int) $r['sid'] === $softwaresId
                || ($nameNorm !== null && Matching\Normalizer::softwareName((string) $r['sname']) === $nameNorm
                    && Matching\Normalizer::manufacturer((string) ($r['manufacturer'] ?? '')) === (string) $manufNorm);
            if ($same) {
                $out[] = ['id' => (int) $r['id'], 'name' => (string) $r['name']];
            }
        }
        return $out;
    }

    public static function isStale(?string $lastInventory): bool
    {
        if ($lastInventory === null || $lastInventory === '') {
            return true;
        }
        return (time() - strtotime($lastInventory)) > Config::getInt('stale_days') * 86400;
    }

    /**
     * Contexte OS / firmware d'un actif, pour l'onglet (modèle prêt pour la phase 2).
     * @return array{os:list<array<string,string>>, firmwares:list<array<string,string>>}
     */
    public static function platformContext(string $itemtype, int $id): array
    {
        /** @var \DBmysql $DB */
        global $DB;
        $os = [];
        foreach ($DB->request([
            'SELECT' => ['glpi_operatingsystems.name AS os', 'glpi_operatingsystemversions.name AS version', 'glpi_operatingsystemeditions.name AS edition',
                'glpi_operatingsystemarchitectures.name AS arch', 'glpi_operatingsystemservicepacks.name AS servicepack', 'glpi_operatingsystemkernelversions.name AS kernel'],
            'FROM' => 'glpi_items_operatingsystems',
            'LEFT JOIN' => [
                'glpi_operatingsystems' => ['ON' => ['glpi_items_operatingsystems' => 'operatingsystems_id', 'glpi_operatingsystems' => 'id']],
                'glpi_operatingsystemversions' => ['ON' => ['glpi_items_operatingsystems' => 'operatingsystemversions_id', 'glpi_operatingsystemversions' => 'id']],
                'glpi_operatingsystemeditions' => ['ON' => ['glpi_items_operatingsystems' => 'operatingsystemeditions_id', 'glpi_operatingsystemeditions' => 'id']],
                'glpi_operatingsystemarchitectures' => ['ON' => ['glpi_items_operatingsystems' => 'operatingsystemarchitectures_id', 'glpi_operatingsystemarchitectures' => 'id']],
                'glpi_operatingsystemservicepacks' => ['ON' => ['glpi_items_operatingsystems' => 'operatingsystemservicepacks_id', 'glpi_operatingsystemservicepacks' => 'id']],
                'glpi_operatingsystemkernelversions' => ['ON' => ['glpi_items_operatingsystems' => 'operatingsystemkernelversions_id', 'glpi_operatingsystemkernelversions' => 'id']],
            ],
            'WHERE' => ['glpi_items_operatingsystems.itemtype' => $itemtype, 'glpi_items_operatingsystems.items_id' => $id, 'glpi_items_operatingsystems.is_deleted' => 0],
        ]) as $r) {
            $os[] = array_map(static fn($v) => (string) ($v ?? ''), $r);
        }
        $fw = [];
        foreach ($DB->request([
            'SELECT' => ['glpi_devicefirmwares.designation', 'glpi_devicefirmwares.version', 'glpi_manufacturers.name AS manufacturer'],
            'FROM' => 'glpi_items_devicefirmwares',
            'INNER JOIN' => ['glpi_devicefirmwares' => ['ON' => ['glpi_items_devicefirmwares' => 'devicefirmwares_id', 'glpi_devicefirmwares' => 'id']]],
            'LEFT JOIN' => ['glpi_manufacturers' => ['ON' => ['glpi_devicefirmwares' => 'manufacturers_id', 'glpi_manufacturers' => 'id']]],
            'WHERE' => ['glpi_items_devicefirmwares.itemtype' => $itemtype, 'glpi_items_devicefirmwares.items_id' => $id, 'glpi_items_devicefirmwares.is_deleted' => 0],
        ]) as $r) {
            $fw[] = array_map(static fn($v) => (string) ($v ?? ''), $r);
        }
        return ['os' => $os, 'firmwares' => $fw];
    }
}
