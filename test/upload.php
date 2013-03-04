<?php
/**
 * TestKontalkBox uploader script.
 */

define('URLFMT', 'http://10.0.2.2/kontalk/download.php?f=%s');
define('MESSAGE_STORAGE_PATH', '/tmp/kontalk');


define('CHARSBOX_AZN_CASEINS', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890');
define('CHARSBOX_AZN_LOWERCASE', 'abcdefghijklmnopqrstuvwxyz1234567890');
define('CHARSBOX_AZN_UPPERCASE', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');


function array_get($ar, $key, $def = false)
{
    return (isset($ar[$key])) ? $ar[$key] : $def;
}

function rand_str($length = 32, $chars = CHARSBOX_AZN_CASEINS)
{
    // Length of character list
    $chars_length = (strlen($chars) - 1);

    // Start our string
    $string = $chars{rand(0, $chars_length)};

    // Generate random string
    for ($i = 1; $i < $length; $i = strlen($string))
    {
        // Grab a random character from our list
        $r = $chars{rand(0, $chars_length)};

        // Make sure the same two characters don't appear next to each other
        if ($r != $string{$i - 1}) $string .=  $r;
    }

    // Return the string
    return $string;
}

function bad_request($str = false)
{
    header('Status: 400 Bad Request');
    header('Content-Type: text/plain');
    die($str ? $str : 'bad request');
}



// --- BEGIN --- //


$length = array_get($_SERVER, 'CONTENT_LENGTH');

// invalid or no size - protocol error
if ($length <= 0)
    bad_request('empty data or length not specified.');

// create directory tree
@mkdir(MESSAGE_STORAGE_PATH, 0770, true);
// create temporary file
$filename = rand_str(40);
$fullpath = MESSAGE_STORAGE_PATH . DIRECTORY_SEPARATOR . $filename;

// open input and output
$putdata = fopen('php://input', 'r');
$fp = fopen($fullpath, 'w');

// write down to temp file
while ($data = fread($putdata, 2048))
    fwrite($fp, $data);

fclose($fp);
fclose($putdata);

if (filesize($fullpath) != $length) {
    // remove file
    unlink($fullpath);

    bad_request('declared length not matching actual data length.');
}

printf(URLFMT, $filename);
