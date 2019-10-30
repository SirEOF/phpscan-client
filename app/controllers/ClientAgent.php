<?php

namespace App\Controllers;

use Alchemy\Zippy\Zippy as Zippy;
use Aws\S3\S3Client;
use Aws\Exception\AwsException;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use PhpParser\Node\Stmt\InlineHTML;
use GuzzleHttp\Client;

/**
 * Class RepositoryValidator
 */
class ClientAgent {

    public function test() {
        return 'ok';
    }

}