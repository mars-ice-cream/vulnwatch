<?php

use GlpiPlugin\Vulnwatch\Logger;
use GlpiPlugin\Vulnwatch\Target;
use GlpiPlugin\Vulnwatch\Ui;

Session::checkRight(Target::$rightname, READ);
$target = new Target();
if (isset($_POST['add'])) {
    $target->check(-1, CREATE, $_POST);
    if ($id = $target->add($_POST)) {
        Logger::decision('target_add', 'target', $id, array_intersect_key($_POST, array_flip(['software_name', 'target_version', 'eol_branch', 'eol_date', 'source'])), (int) ($_POST['entities_id'] ?? 0));
        Html::redirect($target->getFormURLWithID($id));
    }
    Html::back();
} elseif (isset($_POST['update'])) {
    $target->check((int) $_POST['id'], UPDATE);
    $target->update($_POST);
    Logger::decision('target_update', 'target', (int) $_POST['id'], array_intersect_key($_POST, array_flip(['software_name', 'target_version', 'eol_branch', 'eol_date', 'source'])));
    Html::back();
} elseif (isset($_POST['purge'])) {
    $target->check((int) $_POST['id'], PURGE);
    $target->delete($_POST, true);
    Logger::decision('target_purge', 'target', (int) $_POST['id']);
    $target->redirectToList();
}
Ui::header(Target::getTypeName(1), 'target');
$target->display(['id' => (int) ($_GET['id'] ?? 0)]);
Html::footer();
