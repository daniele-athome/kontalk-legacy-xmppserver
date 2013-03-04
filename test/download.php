<?php
/**
 * TestKontalkBox download script.
 */

define('MESSAGE_STORAGE_PATH', '/tmp/kontalk');


function array_get($ar, $key, $def = false)
{
    return (isset($ar[$key])) ? $ar[$key] : $def;
}

function not_found($str = false)
{
    header('Status: 404 Not Found');
    header('Content-Type: text/plain');
    die($str ? $str : 'not found');
}



// --- BEGIN --- //


$filename = array_get($_GET, 'f');
if ($filename) {
    $fullpath = MESSAGE_STORAGE_PATH . DIRECTORY_SEPARATOR . $filename;
    die(file_get_contents($fullpath));
}

not_found();
