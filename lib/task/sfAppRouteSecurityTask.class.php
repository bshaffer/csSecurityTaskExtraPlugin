<?php

class sfAppRouteSecurityTask extends sfBaseSecurityTaskExtraTask
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

    $this->aliases          = array('route-security');
    $this->namespace        = 'app';
    $this->name             = 'route-security';
    $this->briefDescription = 'Assess security coverage of routes in your application';
    $this->detailedDescription = <<<EOF
The [app:route-security|INFO] displays the security coverage for a given application:

  [./symfony app:route-security frontend|INFO]
EOF;
  }
   /**
   * @see sfTask
   */
  protected function execute($arguments = array(), $options = array())
  {
    $maxName = 4;
    $maxIsSecure = 9;
    
    $this->initializeSecurityTaskExtra();
    
    $this->bootstrapSymfony($arguments['application'], $options['env'], true);
    
    $this->routes = $this->getRouting()->getRoutes();

    $this->security = $this->getSecurityByModuleAction();
    
    $this->logSection('app', sprintf('Current route security for application "%s"', $arguments['application']));

    $maxName = 4;
    $maxIsSecure = 9;
    
    $routeSecurity = array();

    foreach ($this->routes as $name => $route)
    {
      $defaults = $route->getDefaults();
      
      if (!isset($defaults['module']) || !isset($defaults['action'])) 
      {
        // Can't determine security
        continue;
      }
      
      $module = $defaults['module'];
      $action = $defaults['action'];
      
      if (isset($this->security[$module]) && (!$arguments['module'] || $arguments['module'] == $module)) 
      {
        if (isset($this->security[$module][$action])) 
        {
          $routeSecurity[$name] = $this->security[$module][$action];
        }
        elseif(isset($this->security[$module]['all']))
        {
          $routeSecurity[$name] = $this->security[$module]['all'];
        }
        else
        {
          $routeSecurity[$name] = $this->appSecurity;
        }
      }
      else
      {
        $routeSecurity[$name] = $this->appSecurity;
      }

      if (strlen($name) > $maxName)
      {
        $maxName = strlen($name);
      }
    }
    $formatRow1  = '%-'.$maxName.'s %-'.($maxIsSecure + 11).'s %s';
    $formatRow2  = '%-'.$maxName.'s %-'.($maxIsSecure + 9).'s %s';
    $formatHeader  = '%-'.($maxName + 9).'s %-'.($maxIsSecure + 9).'s %s';

    // displays the generated routes
    $this->log(sprintf($formatHeader, $this->formatter->format('Name', 'COMMENT'), $this->formatter->format('Is Secure', 'COMMENT'), $this->formatter->format('Credentials', 'COMMENT')));
    foreach ($routeSecurity as $name => $policy)
    {
      if (!$arguments['module'] || $arguments['module'] == $policy['module']) 
      {
        $this->log(sprintf($policy['is_secure'] ? $formatRow1 : $formatRow2, 
                           $name, $policy['is_secure_string'], 
                           $this->formatMultilineCredentials($policy['credential_string'], $this->maxCredentials, $maxName+$maxIsSecure+2)));
      }
    }
  }

}