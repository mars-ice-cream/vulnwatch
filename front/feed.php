<?php

use GlpiPlugin\Vulnwatch\Feed;
use GlpiPlugin\Vulnwatch\Ui;

Session::checkRight(Feed::$rightname, READ);
if (isset($_POST['add_official'])) {
    Session::checkRight(Feed::$rightname, UPDATE);
    $n = Feed::installOfficialFeeds();
    GlpiPlugin\Vulnwatch\Logger::decision('feed_official', 'feed', 0, ['added' => $n]);
    Session::addMessageAfterRedirect($n > 0 ? sprintf(__('%d flux officiel(s) ajouté(s).', 'vulnwatch'), $n) : __('Tous les flux officiels sont déjà présents.', 'vulnwatch'));
    Html::back();
}
Ui::header(Feed::getTypeName(2), 'feed');
if (Session::haveRight(Feed::$rightname, UPDATE)) {
    echo "<form method='post' action='" . Ui::e(GlpiPlugin\Vulnwatch\Menu::url('feed.php')) . "' class='d-flex gap-2 align-items-center mb-3'>"
        . "<a class='btn btn-primary' href='" . Ui::e(GlpiPlugin\Vulnwatch\Menu::url('feed.form.php')) . "'><i class='ti ti-plus me-1'></i>" . __('Ajouter un flux', 'vulnwatch') . '</a>'
        . Html::submit(__('Ajouter les flux officiels manquants (CERT-FR)', 'vulnwatch'), ['name' => 'add_official', 'class' => 'btn btn-outline-secondary']);
    Html::closeForm();
}
Search::show(Feed::class);
Html::footer();
