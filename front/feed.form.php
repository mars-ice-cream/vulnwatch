<?php

use GlpiPlugin\Vulnwatch\Feed;
use GlpiPlugin\Vulnwatch\Logger;
use GlpiPlugin\Vulnwatch\Ui;

Session::checkRight(Feed::$rightname, READ);
$feed = new Feed();

if (isset($_POST['add'])) {
    $feed->check(-1, CREATE, $_POST);
    if ($id = $feed->add($_POST)) {
        Logger::decision('feed_add', 'feed', $id, ['url' => $_POST['url'] ?? ''], (int) ($_POST['entities_id'] ?? 0));
        Html::redirect($feed->getFormURLWithID($id));
    }
    Html::back();
} elseif (isset($_POST['update'])) {
    $feed->check((int) $_POST['id'], UPDATE);
    $feed->update($_POST);
    Logger::decision('feed_update', 'feed', (int) $_POST['id'], array_intersect_key($_POST, array_flip(['url', 'is_active', 'frequency', 'filter_include', 'filter_exclude'])));
    Html::back();
} elseif (isset($_POST['purge'])) {
    $feed->check((int) $_POST['id'], PURGE);
    $feed->delete($_POST, true);
    Logger::decision('feed_purge', 'feed', (int) $_POST['id']);
    $feed->redirectToList();
} elseif (isset($_POST['test']) || isset($_POST['sync_now'])) {
    $feed->check((int) $_POST['id'], UPDATE);
    if (isset($_POST['test'])) {
        $r = Feed::test((string) $feed->fields['url']);
        if ($r['ok']) {
            Session::addMessageAfterRedirect(htmlescape(sprintf('Test réussi : format %s, « %s », %d article(s), %d mention(s) de CVE. Exemples : %s', $r['format'], $r['title'], $r['count'], $r['cves'], implode(' | ', $r['sample']))));
        } else {
            Session::addMessageAfterRedirect(htmlescape('Échec du test : ' . $r['error']), false, ERROR);
        }
    } else {
        $r = Feed::sync($feed->fields);
        Session::addMessageAfterRedirect(htmlescape($r['ok'] ? sprintf('Synchronisé : %d article(s), %d nouveau(x).', $r['items'], $r['new']) : 'Erreur : ' . $r['error']), false, $r['ok'] ? INFO : ERROR);
    }
    Html::back();
}

$id = (int) ($_GET['id'] ?? 0);
Ui::header(Feed::getTypeName(1), 'feed');
$feed->display(['id' => $id]);
if ($id > 0 && $feed->getFromDB($id) && $feed->can($id, UPDATE)) {
    echo "<form method='post' action='" . htmlescape(Feed::getFormURL()) . "' class='m-3'>";
    echo Html::hidden('id', ['value' => $id]);
    echo Html::submit(__('Tester la récupération', 'vulnwatch'), ['name' => 'test', 'class' => 'btn btn-outline-secondary me-2']);
    echo Html::submit(__('Synchroniser maintenant', 'vulnwatch'), ['name' => 'sync_now', 'class' => 'btn btn-outline-primary']);
    Html::closeForm();
}
Html::footer();
