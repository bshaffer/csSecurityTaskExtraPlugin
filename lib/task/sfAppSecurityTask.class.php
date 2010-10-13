<?php

class sfAppSecurityTask extends sfBaseSecurityTaskExtraTask
{ 
  protected function configure()
  {
    $this->addArguments(array(
          new sfCommandArgument('application', sfCommandArgument::REQUIRED, 'The application'),
          new sfCommandArgument('module', sfCommandArgument::OPTIONAL, 'The module'),
        ));
        
    $this->addOptions(array(
      new sfCommandOption('env', null, sfCommandOption::PARAMETER_REQUIRED, 'The environment', 'prod'),
      ));

    $this->namespace        = 'app';
    $this->name             = 'security';
    $this->briefDescription = 'Assess security coverage in your application';
    $this->detailedDescription = <<<EOF
Assess security.yml in your application
EOF;
  }
  
  protected function execute($arguments = array(), $options = array())
  { 
    $maxModule = 6;
    $maxAction = 6;
    $maxIsSecure = 9;
    
    $this->initializeSecurityTaskExtra();
    
    $this->bootstrapSymfony($arguments['application'], $options['env'], true);
    $security = $this->getSecurityArray();
    
    foreach ($security as $item) 
    {
      if (!$arguments['module'] || $arguments['module'] == $item['module']) 
      {
        if (strlen($item['module']) > $maxModule)
        {
          $maxModule = strlen($item['module']);
        }

        if (strlen($item['action']) > $maxAction)
        {
          $maxAction = strlen($item['action']);
        }

        if (strlen($item['is_secure']) > $maxIsSecure)
        {
          $maxIsSecure = strlen($item['is_secure']);
        }
      }
    }
    
    $formatRow1  = '%-'.$maxModule.'s %-'.$maxAction.'s %-'.($maxIsSecure + 11).'s %s';    
    $formatRow2  = '%-'.$maxModule.'s %-'.$maxAction.'s %-'.($maxIsSecure + 9).'s %s';
    $formatHeader  = '%-'.($maxModule + 9).'s %-'.($maxAction + 9).'s %-'.($maxIsSecure + 9).'s %s';

    $this->log(sprintf($formatHeader, $this->formatter->format('Module', 'COMMENT'), $this->formatter->format('Action', 'COMMENT'), $this->formatter->format('Is Secure', 'COMMENT'), $this->formatter->format('Credentials', 'COMMENT')));
    foreach ($security as $item)
    {
      if (!$arguments['module'] || $arguments['module'] == $item['module']) 
      {
        $this->log(sprintf($item['is_secure'] ? $formatRow1:$formatRow2, 
                           $item['module'], $item['action'], 
                           $this->formats[$item['is_secure']?'yes':'no'], 
                           $this->formatMultilineCredentials($item['credential_string'], $this->maxCredentials, $maxModule+$maxAction+$maxIsSecure+3)));
      }
    }
  }
}