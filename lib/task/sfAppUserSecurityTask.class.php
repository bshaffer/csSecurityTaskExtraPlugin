<?php

class sfAppUserSecurityTask extends sfBaseSecurityTaskExtraTask
{ 
  protected function configure()
  {
    $this->addArguments(array(
          new sfCommandArgument('application', sfCommandArgument::REQUIRED, 'The application'),
          new sfCommandArgument('user', sfCommandArgument::OPTIONAL, 'The id or username of a user to check'),
          new sfCommandArgument('module', sfCommandArgument::OPTIONAL, 'Display for a particular module'),
        ));
        
    $this->addOptions(array(
      new sfCommandOption('env', null, sfCommandOption::PARAMETER_REQUIRED, 'The environment', 'prod'),
      ));

    $this->aliases          = array('user-security');
    $this->namespace        = 'app';
    $this->name             = 'user-security';
    $this->briefDescription = 'Assess security coverage for users in your application';
    $this->detailedDescription = <<<EOF
The [app:user-security|INFO] displays the user security coverage for a given application:

  [./symfony app:user-security frontend|INFO]
  
Pass the id or username of an sfGuardUser object as the second argument to retrieve information about a specific user

  [./symfony app:user-security frontend johndoe|INFO]
EOF;
  }
  
  protected function execute($arguments = array(), $options = array())
  { 
    $maxUsername = 8;
    $maxModule = 6;
    $maxAction = 6;
    $maxHasAccess = 10;

    $this->initializeSecurityTaskExtra();
    
    $this->bootstrapSymfony($arguments['application'], $options['env'], true);
    
    $databaseManager = new sfDatabaseManager($this->configuration);
    $connection = $databaseManager->getDatabase('doctrine')->getConnection();
    
    
    if ($arguments['user']) 
    {
      $column = (int) $arguments['user'] ? 'id' : 'username';
      $users = Doctrine::getTable('sfGuardUser')->createQuery()->where($column.' = ?', $arguments['user'])->execute();
    }
    else
    {
      $users = Doctrine::getTable('sfGuardUser')->findAll();
    }
    
    if (!$users->count()) 
    {
      throw new InvalidArgumentException($arguments['users'] ? "User $arguments[user] not found":"No users found in database");
    }

    $this->logSection('app', sprintf('Current user security for application "%s"', $arguments['application']) . ($arguments['user'] ? sprintf(' and user "%s"', $arguments['user']) : ''));

    $security = $this->getSecurityArray();

    $userAccess = array();
    foreach ($users as $user) 
    {
      $name = $user['username'];
      if (strlen($name) > $maxUsername)
      {
        $maxUsername = strlen($name);
      }
      
      $permissions = $user->getAllPermissionNames();

      $userAccess[$name] = $security;
      foreach ($userAccess[$name] as $i => $item) 
      {
        if (!$item['is_secure']) 
        {
          unset($userAccess[$name][$i]);
          continue;
        }
        $hasAccess = $user['is_super_admin'] || $this->testCredentials($permissions, $item['credentials']);
        $userAccess[$name][$i]['has_access'] = $hasAccess;
        $userAccess[$name][$i]['has_access_string'] = $this->formats[$hasAccess?'yes':'no'];
                
        if (strlen($item['module']) > $maxModule)
        {
          $maxModule = strlen($item['module']);
        }

        if (strlen($item['action']) > $maxAction)
        {
          $maxAction = strlen($item['action']);
        }
      }
    }

    $formatRow1  = '%-'.($maxUsername + 11).'s %-'.$maxModule.'s %-'.($maxAction).'s %-'.($maxHasAccess + 11).'s %s'; 
    $formatRow2  = '%-'.($maxUsername + 11).'s %-'.$maxModule.'s %-'.($maxAction).'s %-'.($maxHasAccess + 9).'s %s';    
    $formatHeader  = '%-'.($maxUsername + 9).'s %-'.($maxModule + 9).'s %-'.($maxAction + 9).'s %-'.($maxHasAccess + 9).'s %s';

    $this->log(sprintf($formatHeader, $this->formatter->format('Username', 'COMMENT'), $this->formatter->format('Module', 'COMMENT'), $this->formatter->format('Action', 'COMMENT'), $this->formatter->format('Has Access', 'COMMENT'), $this->formatter->format('Credentials', 'COMMENT')));
    foreach ($userAccess as $name => $security)
    {
      $count = 0;
      foreach ($security as $i => $item) 
      {
        if (!$arguments['module'] || $arguments['module'] == $item['module']) 
        {
          $this->log(sprintf($item['has_access'] ? $formatRow1:$formatRow2,
                             $this->formatter->format($count == 0 ? $name:'', $this->labelFormat), 
                             $item['module'], $item['action'], $item['has_access_string'], 
                             $this->formatMultilineCredentials($item['credential_string'], $this->maxCredentials, $maxUsername+$maxModule+$maxAction+$maxHasAccess+4)
                  ));
          $count++;
        }
      }
    }
  }
}