<?php

error_reporting(-1);
ini_set('display_errors', 'On');

require __DIR__.'/vendor/autoload.php';

use Symfony\Component\Console\Application;
use Symfony\Component\Console\Exception;

/** @var Application $app */
$app = require_once __DIR__.'/bootstrap/app.php';
try {
    $app->run();
} catch (Exception\RuntimeException $exception) {
    throw $exception;
}
