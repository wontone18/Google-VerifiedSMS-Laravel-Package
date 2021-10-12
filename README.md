# Google VerifiedSMS Laravel Package
 This is a laravel package developed for google business communication api and verified SMS API. Before we commence this installation package you must these things in your side :
 
 1. Your agent should be verified by google and you must have a partner account with google.
 2. Public/Private key or if you dont have public and private key then go through this <https://developers.google.com/business-communications/verified-sms/guides/build/keys>
 3. You must have a valid api service account or api for verifiedsms api and business communication api.
 
 ## Installation
 
1. Use command prompt to run this package `composer require wontonee/verifiedsms`
2. Its ready to use now in your project. Lets test this by using a Example : Create any controller `php artisan make:controller TestController`
3. Create a keys folder in your `http/controller/keys` (Put .pem and service account json file inside this folder).
4. Open your `TestController.php` and write this code
```sh
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Wontonee\Verifiedsms\Http\Controllers\VerifiedsmsController;

class TestController extends Controller
{
    /**
     * Testing Controller
     */

    public function testing()
    {
        $agentId = "VERIFIED_AGENT_ID";
        $privateKeyPath = __DIR__ . "/keys/private-key-P-384.PEM"; 
        $serviceAccountLocation = __DIR__ . "/keys/wontonee-493caec367b7.json"; //REPLACE WITH YOUR SERVICE ACCOUNT JSON
        $apiKey = ""; // REPLACE WITH API KEY IF SERVICE ACCOUNT NOT USING
        $sms = "This is my first message testing by Saju For wontonee.";
        $mobileno = "+919811381218"; // Mobile no should be with countrycode and mobile no
        
        $storehasing = new VerifiedsmsController($agentId, $privateKeyPath, $serviceAccountLocation, $apiKey, $sms,$mobileno);

        $storehasing->GoogleHashstore();

        // Response check if it having success 200 then send sms from your gateway

    }

}

```

For any help or customisation  <https://www.wontonee.com> or email us <hello@wontonee.com> 
