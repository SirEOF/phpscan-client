<?php

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Console\Formatter\OutputFormatterStyle;
use Symfony\Component\Finder\Finder;
use PhpParser\ParserFactory;
use PhpParser\Node\Stmt;

class ScanRunCommand extends Command
{

    protected static $defaultName = 'scan:run';

    /** @var \Symfony\Component\Console\Style\SymfonyStyle */
    private $io;

    public function __construct($name = null)
    {
        parent::__construct($name);
    }

    protected function configure()
    {
        $this
            ->setDescription('Scans PHP files for malwares in a given directory')
            ->addOption('apikey', 'k', InputOption::VALUE_REQUIRED, 'Purchased API key from phpscan.io')
            ->addOption('dir', 'd', InputOption::VALUE_REQUIRED, 'Absolute Base directory to scan PHP files inside it')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $io = new SymfonyStyle($input, $output);
        $this->io = new SymfonyStyle($input, $output);
        $outputStyle = new OutputFormatterStyle('blue', null);
        $output->getFormatter()->setStyle('help', $outputStyle);
        $io->writeln(['<help>For help, Pass --help to see options.</>', '']);

        $apiKey = $input->getOption('apikey');
        $baseDirectory = $input->getOption('dir');

        if (substr($baseDirectory, -1) !== '/') $baseDirectory .= '/';
        if (!ctype_alnum($apiKey)) {
            $io->error('apikey is wrong');
            die;
        }

        $phpFiles = $this->gatherPhpFiles($baseDirectory);
        $manifest = $this->hashes($phpFiles);
        $io->table(['hash', 'size'], $manifest);
//        foreach ($phpFiles as $file) {
//            $io->writeln($file);
//        }

    }

    /**
     * @param $baseDirectory string
     * @return array
     */
    private function gatherPhpFiles($baseDirectory) {

        $allFilesWithPhpExtension = $this->getAllFilesWithPhpExtension($baseDirectory);
        $allRealPhpFilesWithSize = $this->getApplicableFiles($allFilesWithPhpExtension);
        return $allRealPhpFilesWithSize;
    }

    private function getAllFilesWithPhpExtension($basePath) {
        $finder = new Finder();
        $results = [];
        $finder->files()->name('*.php')->in($basePath);
        foreach ($finder as $file) {
            $results[] = $file->getRealPath();
        }
        return $results;
    }

    private function getApplicableFiles($files) {

        $parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP5);
        $result = [];
        foreach ($files as $filePath) {
            $size = filesize($filePath);
            if($this->is_php($filePath, $parser)) {
                $result[] = [$filePath,  $size];
            }

        }
        return $result;

    }

    /**
     * @param $path
     * @param $parser \PhpParser\Parser
     * @return bool
     */
    private function is_php($path, $parser) {
        $content = file_get_contents($path);
        if (strpos($content, '<?')===false) {
            return false;
        }
        try {
            $ast = $parser->parse($content);
            $is_php=false;
            foreach ($ast as $node)
            {
                if (!$node instanceof Stmt\InlineHTML)
                {
                    $is_php=true;
                    break;
                }
            }
            if (!$is_php) {
//                if(self::DEBUG)  dump("after loop and is_php is false");
                return false;
            }
        }
        catch (\Exception $e) {
//            if(self::DEBUG)  dump("at exception so is false");
            return false;
        }
//        if(self::DEBUG)  dump("at the end so is php is true");
        return true;
    }

    private function hash($filePath) {
        $algorithms =  ["crc32", "md5", "sha1"];
        $hashes = [];
        foreach($algorithms as $algo) {
            $hashes[] = hash_file($algo, $filePath);
        }
        return implode("",$hashes);
    }

    private function hashes($files) {
        $result = [];
        $hashes = [];
        foreach($files as $key => $value) {
            if(is_array($value)) {
                $hash = $this->hash($value[0]);
                if(in_array($hash, $hashes))
                    continue;
                $hashes[] = $hash;
                $result[$value[0]][0] = $hash;
                $result[$value[0]][1] = $value[1];
            }
        }
        return $result;
    }

}