<?php

namespace App\Http\Controllers\Api;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\UserNotDefinedException;

class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    protected $ruleLogin = [
        "email" => "required|email",
        "password" => "required|regex:/^(?=.*[A-Z]{1,})(?=.*[!@#$&*_]{1,})(?=.*[0-9]{1,})(?=.*[a-z]{1,}).{8,100}$/"
    ];

    protected $ruleRegister = [
        "name" => "required|regex:/^[A-Za-z ]*$/",
        "email" => "required|email",
        "password" => "required|regex:/^(?=.*[A-Z]{1,})(?=.*[!@#$&*_]{1,})(?=.*[0-9]{1,})(?=.*[a-z]{1,}).{8,100}$/|confirmed",
        "password_confirmation" => "required|regex:/^(?=.*[A-Z]{1,})(?=.*[!@#$&*_]{1,})(?=.*[0-9]{1,})(?=.*[a-z]{1,}).{8,100}$/"
    ];

    public function __construct()
    {
        Auth::shouldUse("api");
    }
}
