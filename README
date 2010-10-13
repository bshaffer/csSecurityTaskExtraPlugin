csSecurityTaskExtraPlugin
=========================

The `csSecurityTaskExtraPlugin` provide some new tasks to the symfony command line tool

  * app:security application : Assess security coverage in your application
  * app:route-security application : Assess security coverage of routes in your application
  * app:group-security application [group] : Assess security coverage for groups in your application
  * app:user-security application [user] : Assess security coverage for users in your application
  
Examples
--------

The app:security task outputs a readable list of security.yml specifications in your application

    $ ./symfony app:security frontend

![App Security](http://trac.symfony-project.com/attachment/wiki/csSecurityTaskExtraPlugin/app-security.png?format=raw)

The app:route-security task compares your security.ymls to all the routes in your application

    $ ./symfony app:route-security frontend

![Route Security](http://trac.symfony-project.com/attachment/wiki/csSecurityTaskExtraPlugin/route-security.png?format=raw)

You can also list who has access to which actions specified in security.yml with the group-security task.

    $ ./symfony app:group-security frontend

![Group Security](http://trac.symfony-project.com/attachment/wiki/csSecurityTaskExtraPlugin/group-security-all.gif?format=raw)

Pass the name of an sfGuardGroup object as the second argument to narrow down your output

    $ ./symfony app:group-security frontend author

![Group Security](http://trac.symfony-project.com/attachment/wiki/csSecurityTaskExtraPlugin/group-security-author.png?format=raw)

List users who has access with the user-security task.

    $ ./symfony app:user-security frontend

![User Security](http://trac.symfony-project.com/attachment/wiki/csSecurityTaskExtraPlugin/user-security-all.gif?format=raw)

Pass the username or id of an sfGuardUser object as the second argument to narrow down your output

    $ ./symfony app:group-security frontend andyadministrator
    OR
    $ ./symfony app:group-security frontend 3

![User Security](http://trac.symfony-project.com/attachment/wiki/csSecurityTaskExtraPlugin/user-security-andyadmin.png?format=raw)

Please send all comments or questions to [Brent Shaffer](http://symplist.net/contact)