<?php

namespace Wontonee\Verifiedsms\Providers;

use Illuminate\Support\ServiceProvider;

class VerifiedsmsServiceProvider extends ServiceProvider
{

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        $this->loadRoutesFrom(__DIR__ . '/../Http/routes.php');

    }

    /* Register services.
    *
    * @return void
    */
   public function register()
   {
       $this->registerConfig();
   }

   /**
    * Register package config.
    *
    * @return void
    */
   protected function registerConfig()
   {


   }
}
