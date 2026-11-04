<?php

namespace GlpiPlugin\Vulnwatch\Compat;

/**
 * Base des classes non persistées soumises au droit « plugin_vulnwatch ».
 * GLPI 11 : $rightname non typé, comme dans la classe mère.
 */
abstract class PluginRightItem extends \CommonGLPI
{
    public static $rightname = 'plugin_vulnwatch';
}
