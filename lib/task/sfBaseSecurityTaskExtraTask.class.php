<?php

abstract class sfBaseSecurityTaskExtraTask extends sfBaseTask
{ 
  protected $labelFormat = array('fg' => 'white', 'bold' => true),
            $maxCredentials = 130;
  
  protected function initializeSecurityTaskExtra()
  {
    $this->formats = array(
      'left_parenthesis'  => $this->formatter->format("(", 'COMMENT'),
      'right_parenthesis' => $this->formatter->format(")", 'COMMENT'),
      'and'               => $this->formatter->format(' AND ', 'INFO'),
      'or'                => $this->formatter->format(' OR ', 'INFO'),
      'none'              => $this->formatter->format('none', 'COMMENT'),
      'yes'               => $this->formatter->format('yes', 'INFO'),
      'no'                => $this->formatter->format('no', 'COMMENT'),
    );
  }
  
  protected function bootstrapSymfony($app, $env, $debug = true)
  {
    $configuration = ProjectConfiguration::getApplicationConfiguration($app, $env, $debug);

    sfContext::createInstance($configuration);
  }
  
  protected function loadApplicationSecurity()
  {
    $path = sfConfig::get('sf_app_config_dir').'/security.yml';
    include(sfContext::getInstance()->getConfigCache()->checkConfig($path));
    return $this->security;
  }

  protected function loadModuleSecurity($module)
  {
    $path = sfConfig::get('sf_app_module_dir').'/'.$module.'/config/security.yml';
    include(sfContext::getInstance()->getConfigCache()->checkConfig($path));
    return $this->security;
  }
  
  public function getSecurityArray($options = array())
  {
    $appSecurity = $this->loadApplicationSecurity();

    $this->appSecurity = isset($appSecurity['all']) ? $appSecurity['all'] : array('all' => array('is_secure' => false));

    $this->appSecurity = array(
                            'module'            => 'global',
                            'action'            => 'all',
                            'is_secure'         => $this->appSecurity['is_secure'],
                            'credentials'       => isset($this->appSecurity['credentials']) ? $this->appSecurity['credentials'] : array(),
                            'credential_string' => isset($this->appSecurity['credentials']) ? $this->formatCredentials($this->appSecurity['credentials']) : $this->formats['none']);

    $this->appSecurity['is_secure_string'] = $this->appSecurity['is_secure'] ? $this->formats['yes'] : $this->formats['no'];

    $files = glob(sfConfig::get('sf_app_dir').'/modules/*/config/security.yml');
    $security = array('global-defaut' => $this->appSecurity);

    foreach ($files as $policy_file) {
      preg_match("#^".sfConfig::get('sf_app_dir')."/modules/([^/]+)/#", $policy_file, $matches);

      $policy = $this->loadModuleSecurity($matches[1]);
      
      foreach ($policy as $action => $actionOptions) 
      {
        $params = array('module'            => $matches[1], 
                        'action'            => $action, 
                        'is_secure'         => isset($actionOptions['is_secure']) ? $actionOptions['is_secure'] : null,
                        'credentials'       => isset($actionOptions['credentials']) ? $actionOptions['credentials'] : null);

        $security[$matches[1].'-'.$action] = $params;
      }
    }
    
    // Clean
    foreach ($security as $key => $policy) 
    {
      $allKey = $policy['module'].'-all';
      
      if ($policy['is_secure'] === null) 
      {
        $policy['is_secure'] = $key != $allKey && isset($security[$allKey]) && $security[$allKey]['is_secure'] !== null ? $security[$allKey]['is_secure'] : $this->appSecurity['is_secure'];
      }
      
      if($policy['credentials'] === null)
      {
        $policy['credentials'] = $key != $allKey && isset($security[$allKey]) && $security[$allKey]['credentials'] !== null ? $security[$allKey]['credentials'] : $this->appSecurity['credentials'];
      }
      
      if (!$policy['is_secure']) 
      {
         $policy['credentials'] = array();
      }

      $policy['is_secure_string'] = $policy['is_secure'] ? $this->formats['yes'] : $this->formats['no'];
      
      $policy['credential_string'] = $policy['credentials'] ? $this->formatCredentials($policy['credentials']) : $this->formats['none'];
      $security[$key] = $policy;
    }

    return $security;
  }

  protected function getSecurityByModuleAction()
  {
    $security = array();
    foreach ($this->getSecurityArray() as $policy) 
    {
      if(!isset($security[$policy['module']]))
      {
        $security[$policy['module']] = array();
      }
      $security[$policy['module']][$policy['action']] = $policy;
    }
    
    return $security;
  }
  
  protected function testCredentials($setCredentials, $checkCredentials)
  {
    $this->credentials = $setCredentials;
    return $this->hasCredential($checkCredentials);
  }

  protected function formatCredentials($credentials, $and = true)
  {
    $formattedCredentials = array();
    if (is_array($credentials)) 
    {
      foreach ($credentials as $credential) 
      {
        $formattedString = is_array($credential) ? $this->formatCredentials($credential, !$and) : $credential;
        if (is_array($credential) && count($credentials) > 1) 
        {
          $formattedString = $this->formats['left_parenthesis'].$formattedString.$this->formats['right_parenthesis'];
        }
        $formattedCredentials[] = $formattedString;
      }
      return implode($and ? $this->formats['and'] : $this->formats['or'], $formattedCredentials);
    }
    
    return $credentials;
  }
  
  public function formatMultilineCredentials($credentials, $maxCredentials, $numSpaces)
  {
    if (strlen($credentials) > $maxCredentials) 
    {
      $line = substr($credentials, 0, $maxCredentials);
      $split = max(strrpos($line, $this->formats['left_parenthesis']), 
                   (strrpos($line, $this->formats['right_parenthesis']) !== false) ? 
                        strrpos($line, $this->formats['right_parenthesis']) + strlen($this->formats['right_parenthesis']) : 0);

      if ($split == 0) 
      {
        $split = max(strrpos($line, $this->formats['and']) + strlen($this->formats['and']), 
                     strrpos($line, $this->formats['or']) + strlen($this->formats['or']),
                     strrpos($line, ' ') + 1);
        if ($split == 0) 
        {
          return trim($credentials);
        }
      }
      $append = $this->formatMultilineCredentials(substr($credentials, $split), $maxCredentials, $numSpaces);
      $credentials = substr($credentials, 0, $split)."\n".str_repeat(' ', $numSpaces). $append;
    }
    return trim($credentials);
  }
  
  protected function hasCredential($credentials, $useAnd = true)
  {
    if (!is_array($credentials))
    {
      return in_array($credentials, $this->credentials);
    }

    // now we assume that $credentials is an array
    $test = false;

    foreach ($credentials as $credential)
    {
      // recursively check the credential with a switched AND/OR mode
      $test = $this->hasCredential($credential, $useAnd ? false : true);

      if ($useAnd)
      {
        $test = $test ? false : true;
      }

      if ($test) // either passed one in OR mode or failed one in AND mode
      {
        break; // the matter is settled
      }
    }

    if ($useAnd) // in AND mode we succeed if $test is false
    {
      $test = $test ? false : true;
    }

    return $test;
  }
}