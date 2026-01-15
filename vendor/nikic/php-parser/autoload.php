<?php
/**
 * Minimal autoloader for bundled nikic/php-parser (no Composer required).
 *
 * Loads classes in the PhpParser\ namespace from ./lib/PhpParser/
 */

if (!defined('PG_NIKIC_PARSER_LOADED')) {
    define('PG_NIKIC_PARSER_LOADED', true);
}

spl_autoload_register(function ($class) {
    $prefix = 'PhpParser\\';
    $prefixLen = strlen($prefix);

    if (strncmp($class, $prefix, $prefixLen) !== 0) {
        return;
    }

    $relative = substr($class, $prefixLen);
    $relativePath = str_replace('\\', '/', $relative) . '.php';
    $file = __DIR__ . '/lib/PhpParser/' . $relativePath;

    if (is_readable($file)) {
        require_once $file;
    }
});
