<?php

use GlpiPlugin\Vulnwatch\Inventory;
use GlpiPlugin\Vulnwatch\Logger;
use GlpiPlugin\Vulnwatch\Menu;

Session::checkRight(Menu::$rightname, UPDATE);

$itemtype = (string) ($_POST['itemtype'] ?? '');
$id = (int) ($_POST['items_id'] ?? 0);
if (!in_array($itemtype, Inventory::TAB_ITEMTYPES, true) || !($item = getItemForItemtype($itemtype)) || !$item->can($id, UPDATE)) {
    Html::displayRightError();
}
if (isset($_POST['save_context'])) {
    /** @var DBmysql $DB */
    global $DB;
    $data = [
        'criticality' => max(0, min(3, (int) ($_POST['criticality'] ?? 0))),
        'exposure'    => max(0, min(2, (int) ($_POST['exposure'] ?? 0))),
        'users_id'    => Session::getLoginUserID(),
        'date_mod'    => $_SESSION['glpi_currenttime'],
    ];
    $DB->updateOrInsert('glpi_plugin_vulnwatch_assetcontexts', $data, ['itemtype' => $itemtype, 'items_id' => $id]);
    Logger::decision('asset_context', $itemtype, $id, $data, (int) $item->fields['entities_id']);
    Session::addMessageAfterRedirect(__('Contexte enregistré.', 'vulnwatch'));
}
Html::back();
