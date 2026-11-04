<?php

use GlpiPlugin\Vulnwatch\Feed;
use GlpiPlugin\Vulnwatch\Ui;

Session::checkRight(Feed::$rightname, READ);
Ui::header(Feed::getTypeName(2), 'feed');
Search::show(Feed::class);
Html::footer();
