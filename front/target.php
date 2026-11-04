<?php

use GlpiPlugin\Vulnwatch\Target;
use GlpiPlugin\Vulnwatch\Ui;

Session::checkRight(Target::$rightname, READ);
Ui::header(Target::getTypeName(2), 'target');
Search::show(Target::class);
Html::footer();
