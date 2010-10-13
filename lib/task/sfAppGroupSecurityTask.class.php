<?php

class sfAppGroupSecurityTask extends sfBaseSecurityTaskExtraTask
{ 
  protected function configure()
  {
    $this->addArguments(array(
          new sfCommandArgument('application', sfCommandArgument::REQUIRED, 'The application'),
          new sfCommandArgument('group', sfCommandArgument::OPTIONAL, 'The name of a group to check'),
          new sfCommandArgument('module', sfCommandArgument::OPTIONAL, 'Display for a particular module'),
        ));
        
    $this->addOptions(array(
      new sfCommandOption('env', null, sfCommandOption::PARAMETER_REQUIRED, 'The environment', 'prod'),
      ));

    $this->aliases          = array('group-security');
    $this->namespace        = 'app';
    $this->name             = 'group-security';
    $this->briefDescription = 'Assess security coverage for groups in your application';
    $this->detailedDescription = <<<EOF
The [app:group-security|INFO] displays the group security coverage for a given application:

  [./symfony app:group-security frontend|INFO]
  
Pass the name of an sfGuardGroup object as the second argument to retrieve information about a specific group

  [./symfony app:group-security frontend administrator|INFO]
EOF;
  }
  
  protected function execute($arguments = array(), $options = array())
  { 
    $maxGroup = 5;
    $maxModule = 6;
    $maxAction = 6;
    $maxHasAccess = 10;
    
    $this->initializeSecurityTaskExtra();
    $this->bootstrapSymfony($arguments['application'], $options['env'], true);
    
    $databaseManager = new sfDatabaseManager($this->configuration);
    $connection = $databaseManager->getDatabase('doctrine')->getConnection();
    
    if ($arguments['group']) 
    {
      $groups = Doctrine::getTable('sfGuardGroup')->createQuery()->where('name = ?', $arguments['group'])->execute();
    }
    else
    {
      $groups = Doctrine::getTable('sfGuardGroup')->findAll();
    }
    
    if (!$groups->count()) 
    {
      throw new InvalidArgumentException($arguments['group'] ? "Group $arguments[group] not found":"No groups found in database");
    }

    $this->logSection('app', sprintf('Current group security for application "%s"', $arguments['application']) . ($arguments['group'] ? sprintf(' and group "%s"', $arguments['group']) : ''));

    $security = $this->getSecurityArray();

    $groupAccess = array();
    foreach ($groups as $group) 
    {
      $name = $group['name'];
      if (strlen($name) > $maxGroup)
      {
        $maxGroup = strlen($name);
      }
      
      $permissions = $group->getPermissions()->toKeyValueArray('id', 'name');

      $groupAccess[$name] = $security;
      foreach ($groupAccess[$name] as $i => $item) 
      {
        if (!$item['is_secure']) 
        {
          unset($groupAccess[$name][$i]);
          continue;
        }
        $hasAccess = $this->testCredentials($permissions, $item['credentials']);
        $groupAccess[$name][$i]['has_access'] = $hasAccess;
        $groupAccess[$name][$i]['has_access_string'] = $this->formats[$hasAccess?'yes':'no'];
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

    $formatRow1  = '%-'.($maxGroup + 11).'s %-'.$maxModule.'s %-'.($maxAction).'s %-'.($maxHasAccess + 11).'s %s'; 
    $formatRow2  = '%-'.($maxGroup + 11).'s %-'.$maxModule.'s %-'.($maxAction).'s %-'.($maxHasAccess + 9).'s %s';    
    $formatHeader  = '%-'.($maxGroup + 9).'s %-'.($maxModule + 9).'s %-'.($maxAction + 9).'s %-'.($maxHasAccess + 9).'s %s';

    $this->log(sprintf($formatHeader, $this->formatter->format('Group', 'COMMENT'), $this->formatter->format('Module', 'COMMENT'), $this->formatter->format('Action', 'COMMENT'), $this->formatter->format('Has Access', 'COMMENT'), $this->formatter->format('Credentials', 'COMMENT')));

    foreach ($groupAccess as $group => $security)
    {
      $count = 0;  
      foreach ($security as $i => $item) 
      {
        if (!$arguments['module'] || $arguments['module'] == $item['module']) 
        {
          $this->log(sprintf($item['has_access'] ? $formatRow1:$formatRow2, 
                             $this->formatter->format($count == 0 ? $group : '',$this->labelFormat), 
                             $item['module'], $item['action'], $item['has_access_string'], 
                             $this->formatMultilineCredentials($item['credential_string'], $this->maxCredentials, $maxGroup+$maxModule+$maxAction+$maxHasAccess+4)));
          $count++;
        }
      }
    }
  }
}