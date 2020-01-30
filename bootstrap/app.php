<?php

require_once __DIR__ .DIRECTORY_SEPARATOR .
    ".." . DIRECTORY_SEPARATOR .
    "app". DIRECTORY_SEPARATOR .
    "commands". DIRECTORY_SEPARATOR .
    "ScanRunCommand.php";

use Symfony\Component\Console\Application;

$application = new Application();
$application->add(new ScanRunCommand());
return $application;
